//! Índice de paquetes de la GUI: la vista "como Wireshark" de cada
//! conversación, pero explicada.
//!
//! El pipeline de flujos resume los paquetes y los descarta; para bajar al
//! paquete se relee la captura y se guarda cada trama con el flujo al que
//! pertenece. Al pedir un paquete se vuelve a diseccionar (es barato) y se
//! cuenta capa a capa: cada campo con su valor y qué significa, y el rango
//! de bytes de cada capa para resaltarlo en el volcado hexadecimal.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use socshark_capture::{CaptureSource, PcapFileReader};
use socshark_core::{
    dns_rcode_str, dns_type_str, EnrichedFlow, L7Protocol, LinkType, RawPacket, Transport,
};
use socshark_dissectors::{DissectedPacket, DissectorPipeline};
use socshark_flow::FlowKey;
use socshark_soc::explain::{host_name, port_label};
use socshark_soc::hosts::HostBook;
use socshark_soc::summarize::fmt_bytes;

/// Cota de bytes de tramas que se guardan en memoria. En un archivo, por
/// encima se indexan las tramas sin contenido (la lista sigue, el detalle
/// no); en vivo se descartan las más antiguas.
const MAX_STORED_BYTES: usize = 256 * 1024 * 1024;
/// Cota de tramas en el búfer circular del modo en vivo.
const MAX_LIVE_PACKETS: usize = 500_000;

/// Paquetes que se devuelven como mucho en la lista de un flujo.
pub const MAX_LIST: usize = 5000;
/// Bytes como mucho en "seguir la conversación".
const MAX_STREAM: usize = 1024 * 1024;
/// Sin flujo (no IP): marca en `flow_of`.
const NO_FLOW: u32 = u32::MAX;

/// Tramas de una captura asociadas a su flujo.
///
/// Los paquetes se numeran desde 1 en orden de llegada, como en Wireshark.
/// En vivo funciona como búfer circular: `base` es el índice global del
/// primer paquete aún guardado.
pub struct PacketIndex {
    link: LinkType,
    packets: VecDeque<RawPacket>,
    /// Flujo de cada paquete guardado (índice en `flow_ids`).
    flow_of: VecDeque<u32>,
    base: usize,
    flow_ids: Vec<String>,
    flow_lookup: HashMap<String, u32>,
    /// Índices globales de los paquetes de cada flujo.
    by_flow: Vec<Vec<usize>>,
    stored_bytes: usize,
    ring: bool,
    evicted_since_prune: usize,
    dissectors: DissectorPipeline,
    /// Archivo: se alcanzó la cota y hay tramas sin contenido. En vivo: ya
    /// se descartaron paquetes antiguos.
    pub truncated: bool,
    /// Quién es quién, aprendido de cada trama al indexarla.
    pub hosts: HostBook,
}

impl PacketIndex {
    /// Índice vacío. `ring` = búfer circular (modo en vivo).
    pub fn new(link: LinkType, ring: bool) -> Self {
        Self {
            link,
            packets: VecDeque::new(),
            flow_of: VecDeque::new(),
            base: 0,
            flow_ids: Vec::new(),
            flow_lookup: HashMap::new(),
            by_flow: Vec::new(),
            stored_bytes: 0,
            ring,
            evicted_since_prune: 0,
            dissectors: DissectorPipeline::new(),
            truncated: false,
            hosts: HostBook::new(),
        }
    }

    /// Relee una captura de archivo y asocia cada trama a su flujo.
    pub fn build(path: &Path) -> Result<Self> {
        let mut reader = PcapFileReader::open(path)
            .with_context(|| format!("no se pudo abrir {}", path.display()))?;
        let mut index = Self::new(reader.link_type(), false);
        while let Some(pkt) = reader.next_packet().context("error leyendo paquetes")? {
            index.push(pkt);
        }
        Ok(index)
    }

    /// Añade una trama al final.
    pub fn push(&mut self, mut pkt: RawPacket) {
        let id = match self.dissectors.dissect(&pkt, self.link) {
            Some(dp) => {
                self.hosts.observe(&dp);
                flow_id(&dp)
            }
            None => None,
        };
        let fid = match id {
            Some(id) => self.intern(id),
            None => NO_FLOW,
        };
        let global = self.base + self.packets.len();
        if fid != NO_FLOW {
            self.by_flow[fid as usize].push(global);
        }
        if self.ring {
            while !self.packets.is_empty()
                && (self.stored_bytes + pkt.data.len() > MAX_STORED_BYTES
                    || self.packets.len() >= MAX_LIVE_PACKETS)
            {
                self.evict_oldest();
            }
        } else if self.stored_bytes + pkt.data.len() > MAX_STORED_BYTES {
            self.truncated = true;
            pkt.data = Vec::new();
        }
        self.stored_bytes += pkt.data.len();
        self.packets.push_back(pkt);
        self.flow_of.push_back(fid);
    }

    fn intern(&mut self, id: String) -> u32 {
        if let Some(&i) = self.flow_lookup.get(&id) {
            return i;
        }
        let i = self.flow_ids.len() as u32;
        self.flow_ids.push(id.clone());
        self.flow_lookup.insert(id, i);
        self.by_flow.push(Vec::new());
        i
    }

    fn evict_oldest(&mut self) {
        if let Some(old) = self.packets.pop_front() {
            self.stored_bytes -= old.data.len();
            self.flow_of.pop_front();
            self.base += 1;
            self.truncated = true;
            self.evicted_since_prune += 1;
        }
        // Las listas por flujo se podan de vez en cuando (no en cada paquete).
        if self.evicted_since_prune >= 10_000 {
            let base = self.base;
            for v in &mut self.by_flow {
                v.retain(|&g| g >= base);
            }
            self.evicted_since_prune = 0;
        }
    }

    /// Paquetes vistos desde el principio (guardados o no).
    pub fn total(&self) -> usize {
        self.base + self.packets.len()
    }

    pub fn link(&self) -> LinkType {
        self.link
    }

    fn get(&self, global: usize) -> Option<&RawPacket> {
        self.packets.get(global.checked_sub(self.base)?)
    }

    /// Índices globales aún guardados de un flujo.
    fn flow_packets(&self, flow_id: &str) -> &[usize] {
        let Some(&fid) = self.flow_lookup.get(flow_id) else {
            return &[];
        };
        let v = &self.by_flow[fid as usize];
        let first = v.partition_point(|&g| g < self.base);
        &v[first..]
    }

    /// Lista de paquetes de un flujo con una frase por paquete.
    pub fn list(&self, flow: &EnrichedFlow) -> (Vec<PacketRow>, bool) {
        let idx = self.flow_packets(&flow.flow_id.0);
        let t0 = idx
            .first()
            .and_then(|&g| self.get(g))
            .map(|p| p.ts_micros)
            .unwrap_or(0);
        let rows = idx
            .iter()
            .take(MAX_LIST)
            .filter_map(|&g| {
                let pkt = self.get(g)?;
                let dp = self.dissectors.dissect(pkt, self.link);
                Some(PacketRow {
                    n: g + 1,
                    ts_micros: pkt.ts_micros,
                    rel_micros: pkt.ts_micros.saturating_sub(t0),
                    len: pkt.orig_len as usize,
                    outbound: dp.as_ref().is_some_and(|d| is_outbound(d, flow)),
                    summary: summary_or_reason(dp.as_ref(), pkt),
                })
            })
            .collect();
        (rows, idx.len() > MAX_LIST)
    }

    /// Página de la lista global de paquetes (la vista principal de
    /// Wireshark). `keep` decide qué flujos se muestran (filtro DSL); los
    /// paquetes sin flujo solo aparecen sin filtro.
    pub fn page(
        &self,
        offset: usize,
        limit: usize,
        keep: Option<&dyn Fn(&str) -> bool>,
    ) -> (Vec<GlobalRow>, usize) {
        let t0 = self.packets.front().map(|p| p.ts_micros).unwrap_or(0);
        // El filtro se evalúa una vez por flujo, no por paquete.
        let allowed: Option<Vec<bool>> =
            keep.map(|k| self.flow_ids.iter().map(|id| k(id)).collect());
        let mut total = 0usize;
        let mut rows = Vec::new();
        for (i, (pkt, &fid)) in self.packets.iter().zip(&self.flow_of).enumerate() {
            let shown = match &allowed {
                None => true,
                Some(a) => fid != NO_FLOW && a[fid as usize],
            };
            if !shown {
                continue;
            }
            if total >= offset && rows.len() < limit {
                let dp = self.dissectors.dissect(pkt, self.link);
                let (src, dst) = dp.as_ref().map(endpoints).unwrap_or_default();
                rows.push(GlobalRow {
                    n: self.base + i + 1,
                    rel_micros: pkt.ts_micros.saturating_sub(t0),
                    ts_micros: pkt.ts_micros,
                    src,
                    dst,
                    protocol: dp.as_ref().map(protocol_name).unwrap_or_default(),
                    len: pkt.orig_len as usize,
                    summary: summary_or_reason(dp.as_ref(), pkt),
                    flow_id: (fid != NO_FLOW).then(|| self.flow_ids[fid as usize].clone()),
                });
            }
            total += 1;
        }
        (rows, total)
    }

    /// Detalle de un paquete (número 1-based, como en Wireshark).
    pub fn detail(&self, n: usize) -> Option<PacketDetail> {
        let pkt = self.get(n.checked_sub(1)?)?;
        let dp = self.dissectors.dissect(pkt, self.link);
        Some(PacketDetail {
            n,
            ts_micros: pkt.ts_micros,
            len: pkt.orig_len as usize,
            captured: pkt.data.len(),
            summary: dp.as_ref().map(summary).unwrap_or_default(),
            layers: dp
                .as_ref()
                .map(|d| layers(pkt, self.link, d))
                .unwrap_or_default(),
            hex: hex(&pkt.data),
        })
    }

    /// "Seguir la conversación": los datos de aplicación de ambos lados en
    /// orden, sin retransmisiones, agrupados en turnos.
    pub fn stream(&self, flow: &EnrichedFlow) -> StreamView {
        let mut view = StreamView::default();
        // Siguiente secuencia esperada por dirección (solo TCP).
        let mut next: [Option<u32>; 2] = [None, None];
        for &g in self.flow_packets(&flow.flow_id.0) {
            let Some(pkt) = self.get(g) else { continue };
            let Some(dp) = self.dissectors.dissect(pkt, self.link) else {
                continue;
            };
            let mut data: &[u8] = &dp.payload;
            if data.is_empty() {
                continue;
            }
            let outbound = is_outbound(&dp, flow);
            if let Some(t) = &dp.tcp {
                let slot = &mut next[usize::from(!outbound)];
                let len = data.len() as u32;
                if let Some(exp) = *slot {
                    let ahead = t.seq.wrapping_sub(exp) as i32;
                    if ahead < 0 {
                        // Retransmisión total o parcial: solo lo nuevo.
                        let dup = ahead.unsigned_abs();
                        if dup >= len {
                            continue;
                        }
                        data = &data[dup as usize..];
                    } else if ahead > 0 {
                        view.gaps = true;
                    }
                }
                // Fin del segmento (sin recortar): lo siguiente esperado.
                *slot = Some(t.seq.wrapping_add(len));
            }
            let room = MAX_STREAM.saturating_sub(view.client_bytes + view.server_bytes);
            if room == 0 {
                view.truncated = true;
                break;
            }
            let data = &data[..data.len().min(room)];
            if outbound {
                view.client_bytes += data.len();
            } else {
                view.server_bytes += data.len();
            }
            match view.chunks.last_mut() {
                Some(last) if last.outbound == outbound => last.hex.push_str(&hex(data)),
                _ => view.chunks.push(StreamChunk {
                    outbound,
                    n: g + 1,
                    hex: hex(data),
                }),
            }
        }
        view
    }

    /// Paquetes y bytes por intervalo de tiempo (la "gráfica de E/S"). Con
    /// `keep` solo cuentan las conversaciones que pasan el filtro; el eje de
    /// tiempo sigue siendo el de toda la captura, para poder comparar.
    pub fn timeline(&self, buckets: usize, keep: Option<&dyn Fn(&str) -> bool>) -> Timeline {
        let (Some(first), Some(last)) = (self.packets.front(), self.packets.back()) else {
            return Timeline::default();
        };
        let (t0, t1) = (first.ts_micros, last.ts_micros.max(first.ts_micros));
        let buckets = buckets.max(1);
        let span = (t1 - t0).max(1);
        let width = span.div_ceil(buckets as u64).max(1);
        let n = ((span / width) as usize + 1).min(buckets);
        let mut packets = vec![0u64; n];
        let mut bytes = vec![0u64; n];
        let allowed: Option<Vec<bool>> =
            keep.map(|k| self.flow_ids.iter().map(|id| k(id)).collect());
        for (p, &fid) in self.packets.iter().zip(&self.flow_of) {
            if let Some(a) = &allowed {
                if fid == NO_FLOW || !a[fid as usize] {
                    continue;
                }
            }
            let b = (((p.ts_micros.saturating_sub(t0)) / width) as usize).min(n - 1);
            packets[b] += 1;
            bytes[b] += u64::from(p.orig_len);
        }
        Timeline {
            start_micros: t0,
            bucket_micros: width,
            packets,
            bytes,
        }
    }

    /// Las tramas guardadas como pcap clásico (para "Guardar captura").
    pub fn to_pcap(&self) -> Vec<u8> {
        let link: u32 = match self.link {
            LinkType::Ethernet => 1,
            LinkType::RawIp => 101,
            LinkType::Unknown(code) => code,
        };
        let mut out = Vec::with_capacity(24 + self.stored_bytes + 16 * self.packets.len());
        out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65_535u32.to_le_bytes());
        out.extend_from_slice(&link.to_le_bytes());
        for p in self.packets.iter().filter(|p| !p.data.is_empty()) {
            out.extend_from_slice(&((p.ts_micros / 1_000_000) as u32).to_le_bytes());
            out.extend_from_slice(&((p.ts_micros % 1_000_000) as u32).to_le_bytes());
            out.extend_from_slice(&(p.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&p.orig_len.max(p.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&p.data);
        }
        out
    }
}

/// Frase del paquete o, si no se pudo diseccionar, el motivo.
fn summary_or_reason(dp: Option<&DissectedPacket>, pkt: &RawPacket) -> String {
    match dp {
        Some(d) => summary(d),
        None if pkt.data.is_empty() => "(contenido no guardado)".into(),
        None => "Paquete que no se pudo interpretar".into(),
    }
}

/// `origen:puerto` y `destino:puerto` de un paquete.
fn endpoints(dp: &DissectedPacket) -> (String, String) {
    let (sp, dpp) = ports(dp);
    let fmt = |ip: Option<IpAddr>, port: u16| match ip {
        Some(IpAddr::V6(v6)) if port != 0 => format!("[{v6}]:{port}"),
        Some(ip) if port != 0 => format!("{ip}:{port}"),
        Some(ip) => ip.to_string(),
        None => String::new(),
    };
    (fmt(dp.src_ip(), sp), fmt(dp.dst_ip(), dpp))
}

/// Protocolo más alto reconocido (columna "Protocolo" de Wireshark).
fn protocol_name(dp: &DissectedPacket) -> String {
    // Un TCP sin datos (SYN, ACK, FIN…) es TCP, aunque vaya al puerto 443:
    // así lo muestra también Wireshark.
    let control_only = dp.transport == Transport::Tcp && dp.payload.is_empty();
    if dp.l7 != L7Protocol::Unknown && !control_only {
        return dp.l7.as_str().to_string();
    }
    dp.transport.as_str().to_string()
}

/// Fila de la lista global de paquetes.
#[derive(Debug, Serialize)]
pub struct GlobalRow {
    pub n: usize,
    pub ts_micros: u64,
    /// Desde el primer paquete guardado.
    pub rel_micros: u64,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub len: usize,
    pub summary: String,
    pub flow_id: Option<String>,
}

/// Un turno de la conversación: datos seguidos de un mismo lado.
#[derive(Debug, Serialize)]
pub struct StreamChunk {
    /// Del iniciador (si no, del otro extremo).
    pub outbound: bool,
    /// Primer paquete del turno.
    pub n: usize,
    pub hex: String,
}

#[derive(Debug, Default, Serialize)]
pub struct StreamView {
    pub chunks: Vec<StreamChunk>,
    pub client_bytes: usize,
    pub server_bytes: usize,
    /// Faltan datos (paquetes no capturados).
    pub gaps: bool,
    /// Se cortó en [`MAX_STREAM`].
    pub truncated: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct Timeline {
    pub start_micros: u64,
    pub bucket_micros: u64,
    pub packets: Vec<u64>,
    pub bytes: Vec<u64>,
}

/// Identificador del flujo de un paquete, igual que lo calcula el agregador.
pub(crate) fn flow_id(dp: &DissectedPacket) -> Option<String> {
    let (src, dst) = (dp.src_ip()?, dp.dst_ip()?);
    let (sp, dpp) = ports(dp);
    Some(FlowKey::new(src, sp, dst, dpp, dp.transport).flow_id().0)
}

fn ports(dp: &DissectedPacket) -> (u16, u16) {
    match (dp.tcp.as_ref(), dp.udp.as_ref()) {
        (Some(t), _) => (t.src_port, t.dst_port),
        (_, Some(u)) => (u.src_port, u.dst_port),
        _ => (0, 0),
    }
}

/// ¿Va del iniciador del flujo hacia el otro extremo?
fn is_outbound(dp: &DissectedPacket, flow: &EnrichedFlow) -> bool {
    dp.src_ip() == Some(flow.src_ip) && ports(dp).0 == flow.src_port
}

#[derive(Debug, Serialize)]
pub struct PacketRow {
    pub n: usize,
    pub ts_micros: u64,
    pub rel_micros: u64,
    pub len: usize,
    /// Del iniciador hacia el destino (si no, es la respuesta).
    pub outbound: bool,
    pub summary: String,
}

#[derive(Debug, Serialize)]
pub struct PacketDetail {
    pub n: usize,
    pub ts_micros: u64,
    /// Tamaño en el cable.
    pub len: usize,
    /// Bytes capturados (puede ser menor si hubo recorte).
    pub captured: usize,
    pub summary: String,
    pub layers: Vec<Layer>,
    /// Bytes de la trama en hexadecimal (dos caracteres por byte).
    pub hex: String,
}

/// Una capa del paquete contada para personas.
#[derive(Debug, Serialize)]
pub struct Layer {
    pub name: String,
    /// Para qué sirve esta capa, en una frase.
    pub about: String,
    /// Rango `[inicio, fin)` de bytes de la capa dentro de la trama.
    pub range: Option<(usize, usize)>,
    pub fields: Vec<Field>,
}

#[derive(Debug, Serialize)]
pub struct Field {
    pub name: String,
    pub value: String,
    /// Qué significa el valor (vacío si es evidente).
    pub help: String,
}

fn field(name: &str, value: impl Into<String>, help: impl Into<String>) -> Field {
    Field {
        name: name.into(),
        value: value.into(),
        help: help.into(),
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn mac(m: &[u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

// ------------------------------------------------------------ frases

/// Primera línea de un texto HTTP si el payload la tiene.
fn http_line(payload: &[u8]) -> Option<String> {
    let starts = [
        &b"GET "[..],
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"HTTP/1.",
    ];
    if !starts.iter().any(|s| payload.starts_with(s)) {
        return None;
    }
    let end = payload
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(payload.len())
        .min(200);
    Some(String::from_utf8_lossy(&payload[..end]).into_owned())
}

/// Tipo de registro TLS (y de mensaje de handshake) del inicio del payload.
fn tls_kind(payload: &[u8]) -> Option<&'static str> {
    if payload.len() < 5 || payload[1] != 0x03 {
        return None;
    }
    Some(match payload[0] {
        20 => "Cambio a modo cifrado (TLS)",
        21 => "Aviso TLS (alerta del protocolo)",
        22 => match payload.get(5) {
            Some(1) => "Saludo TLS del cliente: pide una conexión segura",
            Some(2) => "Saludo TLS del servidor: acepta la conexión segura",
            Some(11) => "Certificado del servidor (TLS)",
            Some(16) => "Intercambio de claves (TLS)",
            _ => "Negociación TLS",
        },
        23 => "Datos cifrados (TLS)",
        _ => return None,
    })
}

/// Una frase por paquete: qué hace este paquete.
pub fn summary(dp: &DissectedPacket) -> String {
    if let Some(dns) = &dp.dns {
        let q = dns.queries.first();
        let qname = q.map(|q| q.name.as_str()).unwrap_or("?");
        if !dns.is_response {
            let qtype = q.map(|q| dns_type_str(q.qtype)).unwrap_or_default();
            return format!("Pregunta DNS: ¿dónde está «{qname}»? ({qtype})");
        }
        if dns.rcode == Some(3) {
            return format!("Respuesta DNS: «{qname}» no existe");
        }
        let addrs: Vec<String> = dns
            .answers
            .iter()
            .filter_map(|a| {
                a.address
                    .map(|ip| ip.to_string())
                    .or_else(|| a.target.clone())
            })
            .collect();
        return format!("Respuesta DNS: «{qname}» → {}", addrs.join(", "));
    }
    let payload = &dp.payload[..];
    if let Some(t) = &dp.tcp {
        let f = &t.flags;
        if f.rst {
            return "Corta la conexión de golpe (RST)".into();
        }
        if f.syn && f.ack {
            return "Acepta abrir la conexión (SYN-ACK)".into();
        }
        if f.syn {
            return "Pide abrir una conexión (SYN)".into();
        }
        if !payload.is_empty() {
            if let Some(line) = http_line(payload) {
                return if line.starts_with("HTTP/") {
                    format!("Respuesta web: {line}")
                } else {
                    format!("Petición web: {line}")
                };
            }
            if let Some(kind) = tls_kind(payload) {
                return format!("{kind} · {}", fmt_bytes(payload.len() as u64));
            }
            if payload.starts_with(b"SSH-") {
                return "Saludo SSH: presenta su versión".into();
            }
            return format!("Envía {} de datos", fmt_bytes(payload.len() as u64));
        }
        if f.fin {
            return "Cierra la conexión (FIN)".into();
        }
        return "Confirma lo recibido (ACK)".into();
    }
    if dp.udp.is_some() {
        return format!("Envía {} de datos (UDP)", fmt_bytes(payload.len() as u64));
    }
    format!("Paquete {}", dp.transport.as_str())
}

// ------------------------------------------------------------ capas

/// Longitud de la cabecera de enlace (Ethernet + etiquetas VLAN).
fn link_header_len(raw: &[u8], link: LinkType) -> usize {
    match link {
        LinkType::Ethernet => {
            let mut len = 14;
            while raw.len() >= len && matches!(&raw[len - 2..len], [0x81, 0x00] | [0x88, 0xa8]) {
                len += 4;
            }
            len
        }
        _ => 0,
    }
}

/// Posición del payload dentro de la trama (es un subslice de ella).
fn payload_offset(raw: &[u8], payload: &[u8]) -> Option<usize> {
    let start = raw.as_ptr() as usize;
    let p = payload.as_ptr() as usize;
    (p >= start && p + payload.len() <= start + raw.len()).then(|| p - start)
}

fn tcp_flags_text(f: &socshark_dissectors::TcpFlags) -> (String, String) {
    let mut names = Vec::new();
    let mut help = Vec::new();
    for (on, name, what) in [
        (f.syn, "SYN", "pide abrir conexión"),
        (f.ack, "ACK", "confirma lo recibido"),
        (f.psh, "PSH", "entrega datos ya"),
        (f.fin, "FIN", "termina de forma ordenada"),
        (f.rst, "RST", "corta de golpe"),
        (f.urg, "URG", "datos urgentes"),
        (f.ece, "ECE", "aviso de congestión"),
        (f.cwr, "CWR", "reduce la velocidad por congestión"),
    ] {
        if on {
            names.push(name);
            help.push(format!("{name}: {what}"));
        }
    }
    (names.join(", "), help.join(" · "))
}

fn layers(raw: &RawPacket, link: LinkType, dp: &DissectedPacket) -> Vec<Layer> {
    let data = &raw.data[..];
    let mut out = Vec::new();
    let l3 = link_header_len(data, link);

    if let Some(e) = &dp.eth {
        let ethertype = match e.ethertype {
            0x0800 => "IPv4",
            0x86dd => "IPv6",
            0x0806 => "ARP",
            _ => "otro",
        };
        let dst_help = if e.dst_mac == [0xff; 6] {
            "todos los equipos de la red (difusión)"
        } else {
            ""
        };
        out.push(Layer {
            name: "Ethernet".into(),
            about: "La dirección física de las tarjetas de red. Solo sirve dentro de la red local."
                .into(),
            range: (data.len() >= l3).then_some((0, l3)),
            fields: vec![
                field(
                    "Origen (MAC)",
                    mac(&e.src_mac),
                    "tarjeta de red que lo envía",
                ),
                field("Destino (MAC)", mac(&e.dst_mac), dst_help),
                field(
                    "Contenido",
                    format!("{ethertype} (0x{:04x})", e.ethertype),
                    "qué protocolo viaja dentro",
                ),
            ],
        });
    }

    // Comienzo de la cabecera de transporte: payload menos su cabecera.
    let payload_at = payload_offset(data, &dp.payload);
    let l4_len = match (&dp.tcp, &dp.udp) {
        (Some(t), _) => Some(20 + t.options_len),
        (_, Some(_)) => Some(8),
        _ => None,
    };
    let l4_at = payload_at.zip(l4_len).and_then(|(p, h)| p.checked_sub(h));
    let ip_range = l4_at.filter(|&s| s >= l3).map(|s| (l3, s));
    let ip_name = |ip: IpAddr| host_name(ip);

    if let Some(i) = &dp.ipv4 {
        let proto = match i.protocol {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            _ => "otro",
        };
        let mut frag = Vec::new();
        if i.dont_fragment {
            frag.push("no fragmentar".to_string());
        }
        if i.more_fragments || i.fragment_offset > 0 {
            frag.push(format!("fragmento (desplazamiento {})", i.fragment_offset));
        }
        out.push(Layer {
            name: "IPv4".into(),
            about: "La dirección de Internet: de qué equipo sale el paquete y a cuál va.".into(),
            range: ip_range,
            fields: vec![
                field("Origen", i.src.to_string(), ip_name(IpAddr::V4(i.src))),
                field("Destino", i.dst.to_string(), ip_name(IpAddr::V4(i.dst))),
                field(
                    "TTL",
                    i.ttl.to_string(),
                    "saltos entre routers que le quedan antes de descartarse",
                ),
                field(
                    "Protocolo",
                    format!("{proto} ({})", i.protocol),
                    "qué viaja dentro",
                ),
                field(
                    "Identificación",
                    format!("0x{:04x}", i.identification),
                    "número para recomponer fragmentos",
                ),
                field(
                    "Fragmentación",
                    if frag.is_empty() {
                        "ninguna".to_string()
                    } else {
                        frag.join(", ")
                    },
                    "",
                ),
                field(
                    "Suma de control",
                    if i.checksum_ok {
                        "correcta"
                    } else {
                        "INCORRECTA"
                    },
                    "comprueba que la cabecera no llegó dañada",
                ),
            ],
        });
    }
    if let Some(i) = &dp.ipv6 {
        out.push(Layer {
            name: "IPv6".into(),
            about: "La dirección de Internet (versión nueva): de qué equipo sale y a cuál va."
                .into(),
            range: ip_range,
            fields: vec![
                field("Origen", i.src.to_string(), ip_name(IpAddr::V6(i.src))),
                field("Destino", i.dst.to_string(), ip_name(IpAddr::V6(i.dst))),
                field(
                    "Límite de saltos",
                    i.hop_limit.to_string(),
                    "routers que puede atravesar antes de descartarse",
                ),
                field(
                    "Siguiente cabecera",
                    i.next_header.to_string(),
                    "qué viaja dentro",
                ),
                field(
                    "Extensiones",
                    if i.extensions.is_empty() {
                        "ninguna".to_string()
                    } else {
                        format!("{:?}", i.extensions)
                    },
                    "cabeceras opcionales encadenadas",
                ),
            ],
        });
    }

    let l4_range = l4_at.zip(payload_at);
    if let Some(t) = &dp.tcp {
        let (flags, flags_help) = tcp_flags_text(&t.flags);
        out.push(Layer {
            name: "TCP".into(),
            about: "Conexión fiable: numera los datos y confirma que llegan, en orden.".into(),
            range: l4_range,
            fields: vec![
                field(
                    "Puerto origen",
                    port_label(t.src_port, Transport::Tcp),
                    "programa que envía",
                ),
                field(
                    "Puerto destino",
                    port_label(t.dst_port, Transport::Tcp),
                    "servicio al que va",
                ),
                field("Flags", flags, flags_help),
                field(
                    "Secuencia",
                    t.seq.to_string(),
                    "posición de estos datos en la conversación",
                ),
                field(
                    "Confirmación",
                    t.ack_number.to_string(),
                    "hasta dónde ha recibido del otro lado",
                ),
                field(
                    "Ventana",
                    t.window.to_string(),
                    "cuántos bytes acepta recibir sin confirmar",
                ),
            ],
        });
    }
    if let Some(u) = &dp.udp {
        out.push(Layer {
            name: "UDP".into(),
            about: "Envío rápido sin conexión ni confirmación (si se pierde, no se reenvía)."
                .into(),
            range: l4_range,
            fields: vec![
                field(
                    "Puerto origen",
                    port_label(u.src_port, Transport::Udp),
                    "programa que envía",
                ),
                field(
                    "Puerto destino",
                    port_label(u.dst_port, Transport::Udp),
                    "servicio al que va",
                ),
                field(
                    "Longitud",
                    u.length.to_string(),
                    "bytes de cabecera más datos",
                ),
            ],
        });
    }

    let payload_range = payload_at.map(|p| (p, p + dp.payload.len()));
    if let Some(d) = &dp.dns {
        let mut fields = vec![
            field(
                "Tipo",
                if d.is_response {
                    "respuesta"
                } else {
                    "pregunta"
                },
                "",
            ),
            field(
                "Identificador",
                format!("0x{:04x}", d.id),
                "empareja la pregunta con su respuesta",
            ),
        ];
        if let Some(rc) = d.rcode.filter(|_| d.is_response) {
            let help = match rc {
                0 => "sin errores",
                3 => "el nombre no existe",
                2 => "el servidor falló",
                5 => "el servidor se negó a responder",
                _ => "",
            };
            fields.push(field("Resultado", dns_rcode_str(rc), help));
        }
        for q in &d.queries {
            fields.push(field(
                "Pregunta",
                format!("{} ({})", q.name, dns_type_str(q.qtype)),
                dns_type_help(q.qtype),
            ));
        }
        for a in &d.answers {
            let value = a
                .address
                .map(|ip| ip.to_string())
                .or_else(|| a.target.clone())
                .unwrap_or_default();
            fields.push(field(
                "Respuesta",
                format!("{} → {value}", a.name),
                format!("{} · válida {} s", dns_type_help(a.rtype), a.ttl),
            ));
        }
        out.push(Layer {
            name: "DNS".into(),
            about: "La guía telefónica de Internet: traduce nombres en direcciones.".into(),
            range: payload_range,
            fields,
        });
    } else if !dp.payload.is_empty() {
        let p = &dp.payload[..];
        let mut fields = vec![field(
            "Tamaño",
            fmt_bytes(p.len() as u64),
            "datos de la aplicación",
        )];
        let about = if let Some(kind) = tls_kind(p) {
            fields.push(field("Mensaje", kind, ""));
            "Datos de una conexión segura: el contenido va cifrado y no se puede leer."
        } else if let Some(line) = http_line(p) {
            fields.push(field("Primera línea", line, ""));
            "Texto de la web sin cifrar: se puede leer tal cual."
        } else {
            "Datos de la aplicación."
        };
        let text: String = p
            .iter()
            .take(160)
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '·'
                }
            })
            .collect();
        fields.push(field("Vista de texto", text, "bytes no imprimibles como ·"));
        out.push(Layer {
            name: "Datos".into(),
            about: about.into(),
            range: payload_range,
            fields,
        });
    }
    out
}

fn dns_type_help(t: u16) -> &'static str {
    match t {
        1 => "dirección IPv4",
        28 => "dirección IPv6",
        5 => "alias de otro nombre",
        15 => "servidor de correo",
        16 => "texto libre",
        12 => "nombre de una dirección",
        2 => "servidor DNS responsable",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_testgen::{flags, frame_tcp, sample_pcap_packets, write_pcap};

    #[test]
    fn frases_por_paquete_tcp() {
        let d = DissectorPipeline::new();
        let raw = |fl: u8, payload: &[u8]| RawPacket {
            ts_micros: 0,
            orig_len: 0,
            data: frame_tcp(
                socshark_testgen::MAC_HOST_A,
                socshark_testgen::MAC_ROUTER,
                socshark_testgen::HOST_A,
                socshark_testgen::GATEWAY,
                40000,
                80,
                1,
                0,
                fl,
                payload,
            ),
        };
        let s = |fl, p: &[u8]| summary(&d.dissect(&raw(fl, p), LinkType::Ethernet).unwrap());
        assert_eq!(s(flags::SYN, b""), "Pide abrir una conexión (SYN)");
        assert_eq!(s(flags::SYN_ACK, b""), "Acepta abrir la conexión (SYN-ACK)");
        assert_eq!(
            s(flags::RST | flags::ACK, b""),
            "Corta la conexión de golpe (RST)"
        );
        assert_eq!(s(flags::ACK, b""), "Confirma lo recibido (ACK)");
        assert_eq!(
            s(
                flags::PSH_ACK,
                b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n"
            ),
            "Petición web: GET /index.html HTTP/1.1"
        );
    }

    fn demo_index() -> PacketIndex {
        let mut idx = PacketIndex::new(LinkType::Ethernet, false);
        for (ts, data) in sample_pcap_packets() {
            idx.push(RawPacket {
                ts_micros: ts,
                orig_len: data.len() as u32,
                data,
            });
        }
        idx
    }

    fn flow_of(id_part: &str, idx: &PacketIndex) -> EnrichedFlow {
        // Flujo mínimo con el id y los extremos que usa el índice.
        let id = idx
            .flow_ids
            .iter()
            .find(|f| f.contains(id_part))
            .expect("flujo de la demo")
            .clone();
        let g = idx.flow_packets(&id)[0];
        let dp = idx
            .dissectors
            .dissect(idx.get(g).unwrap(), idx.link)
            .unwrap();
        let (sp, dpp) = ports(&dp);
        let mut f: EnrichedFlow = serde_json::from_value(serde_json::json!({
            "flow_id": id, "state": "Idle", "transport": "Tcp", "l7_protocol": "Unknown",
            "ip_version": 4, "src_ip": dp.src_ip().unwrap(), "src_port": sp,
            "dst_ip": dp.dst_ip().unwrap(), "dst_port": dpp,
            "first_seen_micros": 0, "last_seen_micros": 0, "duration_micros": 0,
            "packets": 0, "bytes": 0, "packets_rev": 0, "bytes_rev": 0,
            "tcp_flags": {"syn":0,"ack":0,"fin":0,"rst":0,"psh":0,"urg":0},
            "is_background_noise": false, "human_summary": "", "risk_score": 0
        }))
        .unwrap();
        f.flow_id.0 = id;
        f
    }

    #[test]
    fn indice_de_la_demo_capas_y_rangos_coherentes() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("socshark-gui-index-{}.pcap", std::process::id()));
        write_pcap(&path, 1, &sample_pcap_packets()).unwrap();
        let idx = PacketIndex::build(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(idx.total(), 45);
        assert!(!idx.truncated);

        // Cada trama de flujo cae en su flujo: el total coincide.
        let in_flows: usize = idx.by_flow.iter().map(Vec::len).sum();
        assert_eq!(in_flows, 45);

        // Paquete 1: pregunta DNS por example.com con Ethernet/IPv4/UDP/DNS.
        let p = idx.detail(1).unwrap();
        assert!(p
            .summary
            .starts_with("Pregunta DNS: ¿dónde está «example.com»?"));
        let names: Vec<&str> = p.layers.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["Ethernet", "IPv4", "UDP", "DNS"]);
        // Rangos contiguos que cubren la trama: 14 + 20 + 8 + payload.
        let r: Vec<(usize, usize)> = p.layers.iter().map(|l| l.range.unwrap()).collect();
        assert_eq!(r[0], (0, 14));
        assert_eq!(r[1], (14, 34));
        assert_eq!(r[2], (34, 42));
        assert_eq!(r[3].0, 42);
        assert_eq!(p.hex.len(), p.captured * 2);
        assert!(idx.detail(0).is_none() && idx.detail(46).is_none());
    }

    #[test]
    fn lista_global_paginada_y_filtrada_por_flujo() {
        let idx = demo_index();
        let (all, total) = idx.page(0, 10, None);
        assert_eq!(total, 45);
        assert_eq!(all.len(), 10);
        assert_eq!(all[0].n, 1);
        assert_eq!(all[0].protocol, "DNS");
        assert_eq!(all[0].src, "192.168.1.10:53001");
        let (tail, _) = idx.page(40, 10, None);
        assert_eq!(tail.len(), 5);
        assert_eq!(tail[4].n, 45);

        let only_443 = |id: &str| id.contains(":443-");
        let (rows, total) = idx.page(0, 100, Some(&only_443));
        assert_eq!(total, 7, "los 7 paquetes de la sesión TLS");
        assert!(rows
            .iter()
            .all(|r| r.protocol == "TLS" || r.protocol == "TCP"));
    }

    #[test]
    fn seguir_conversacion_http_y_linea_de_tiempo() {
        let idx = demo_index();
        let http = flow_of(":80-192.168.1.20:40112", &idx);
        let v = idx.stream(&http);
        assert!(v.chunks.len() >= 2, "petición y respuesta");
        assert!(v.chunks[0].outbound);
        let first = String::from_utf8(
            (0..v.chunks[0].hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&v.chunks[0].hex[i..i + 2], 16).unwrap())
                .collect(),
        )
        .unwrap();
        assert!(first.starts_with("GET /downloads/factura.jpg"), "{first}");
        assert!(!v.chunks[1].outbound);
        assert!(v.server_bytes > 0 && !v.truncated);

        let t = idx.timeline(50, None);
        assert_eq!(t.packets.iter().sum::<u64>(), 45);
        assert!(t.packets.len() <= 50);
        // Filtrada: mismo eje, menos paquetes.
        let solo_http = |id: &str| id == http.flow_id.0;
        let f = idx.timeline(50, Some(&solo_http));
        assert_eq!(
            (f.start_micros, f.bucket_micros),
            (t.start_micros, t.bucket_micros)
        );
        assert_eq!(
            f.packets.iter().sum::<u64>(),
            idx.flow_packets(&http.flow_id.0).len() as u64
        );
        assert!(f.packets.iter().sum::<u64>() < 45);
    }

    #[test]
    fn buffer_circular_en_vivo_descarta_lo_antiguo() {
        let mut idx = PacketIndex::new(LinkType::Ethernet, true);
        let frame = sample_pcap_packets()[0].1.clone();
        for i in 0..(MAX_LIVE_PACKETS + 10) {
            idx.push(RawPacket {
                ts_micros: i as u64,
                orig_len: frame.len() as u32,
                data: frame.clone(),
            });
        }
        assert_eq!(idx.total(), MAX_LIVE_PACKETS + 10);
        assert!(idx.truncated);
        assert!(idx.detail(1).is_none(), "el primero ya se descartó");
        assert!(idx.detail(MAX_LIVE_PACKETS + 10).is_some());
        let (rows, total) = idx.page(0, 1, None);
        assert_eq!(total, MAX_LIVE_PACKETS);
        assert_eq!(rows[0].n, 11);
    }

    #[test]
    fn guardar_como_pcap_se_relee_igual() {
        let idx = demo_index();
        let bytes = idx.to_pcap();
        let mut r = PcapFileReader::new(&bytes[..]).unwrap();
        let mut n = 0;
        let originals = sample_pcap_packets();
        while let Some(p) = r.next_packet().unwrap() {
            assert_eq!(p.data, originals[n].1);
            assert_eq!(p.ts_micros, originals[n].0);
            n += 1;
        }
        assert_eq!(n, 45);
    }
}
