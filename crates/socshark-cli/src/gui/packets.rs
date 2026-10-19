//! Índice de paquetes de la GUI: la vista "como Wireshark" de cada
//! conversación, pero explicada.
//!
//! El pipeline de flujos resume los paquetes y los descarta; para bajar al
//! paquete se relee la captura y se guarda cada trama con el flujo al que
//! pertenece. Al pedir un paquete se vuelve a diseccionar (es barato) y se
//! cuenta capa a capa: cada campo con su valor y qué significa, y el rango
//! de bytes de cada capa para resaltarlo en el volcado hexadecimal.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use socshark_capture::{CaptureSource, PcapFileReader};
use socshark_core::{dns_rcode_str, dns_type_str, EnrichedFlow, LinkType, RawPacket, Transport};
use socshark_dissectors::{DissectedPacket, DissectorPipeline};
use socshark_flow::FlowKey;
use socshark_soc::explain::{host_name, port_label};
use socshark_soc::summarize::fmt_bytes;

/// Cota de bytes de tramas que se guardan en memoria. Por encima, el resto
/// de paquetes se indexan sin contenido (la lista sigue, el detalle no).
const MAX_STORED_BYTES: usize = 256 * 1024 * 1024;

/// Paquetes que se devuelven como mucho en la lista de un flujo.
pub const MAX_LIST: usize = 5000;

/// Todas las tramas de la captura, agrupables por flujo.
pub struct PacketIndex {
    link: LinkType,
    packets: Vec<RawPacket>,
    by_flow: HashMap<String, Vec<usize>>,
    /// Se alcanzó [`MAX_STORED_BYTES`]: hay tramas sin contenido.
    pub truncated: bool,
}

impl PacketIndex {
    /// Relee la captura y asocia cada trama a su flujo.
    pub fn build(path: &Path) -> Result<Self> {
        let mut reader = PcapFileReader::open(path)
            .with_context(|| format!("no se pudo abrir {}", path.display()))?;
        let link = reader.link_type();
        let dissectors = DissectorPipeline::new();
        let mut packets = Vec::new();
        let mut by_flow: HashMap<String, Vec<usize>> = HashMap::new();
        let mut stored = 0usize;
        let mut truncated = false;
        while let Some(mut pkt) = reader.next_packet().context("error leyendo paquetes")? {
            let i = packets.len();
            if let Some(id) = dissectors.dissect(&pkt, link).as_ref().and_then(flow_id) {
                by_flow.entry(id).or_default().push(i);
            }
            if stored + pkt.data.len() > MAX_STORED_BYTES {
                truncated = true;
                pkt.data = Vec::new();
            }
            stored += pkt.data.len();
            packets.push(pkt);
        }
        Ok(Self {
            link,
            packets,
            by_flow,
            truncated,
        })
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Lista de paquetes de un flujo con una frase por paquete.
    pub fn list(&self, flow: &EnrichedFlow) -> (Vec<PacketRow>, bool) {
        let idx = self
            .by_flow
            .get(&flow.flow_id.0)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let t0 = idx.first().map(|&i| self.packets[i].ts_micros).unwrap_or(0);
        let dissectors = DissectorPipeline::new();
        let rows = idx
            .iter()
            .take(MAX_LIST)
            .map(|&i| {
                let pkt = &self.packets[i];
                let dp = dissectors.dissect(pkt, self.link);
                PacketRow {
                    n: i + 1,
                    ts_micros: pkt.ts_micros,
                    rel_micros: pkt.ts_micros.saturating_sub(t0),
                    len: pkt.orig_len as usize,
                    outbound: dp.as_ref().is_some_and(|d| is_outbound(d, flow)),
                    summary: match &dp {
                        Some(d) => summary(d),
                        None if pkt.data.is_empty() => "(contenido no guardado)".into(),
                        None => "Paquete que no se pudo interpretar".into(),
                    },
                }
            })
            .collect();
        (rows, idx.len() > MAX_LIST)
    }

    /// Detalle de un paquete (número 1-based, como en Wireshark).
    pub fn detail(&self, n: usize) -> Option<PacketDetail> {
        let pkt = self.packets.get(n.checked_sub(1)?)?;
        let dp = DissectorPipeline::new().dissect(pkt, self.link);
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
}

/// Identificador del flujo de un paquete, igual que lo calcula el agregador.
fn flow_id(dp: &DissectedPacket) -> Option<String> {
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

    #[test]
    fn indice_de_la_demo_capas_y_rangos_coherentes() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("socshark-gui-index-{}.pcap", std::process::id()));
        write_pcap(&path, 1, &sample_pcap_packets()).unwrap();
        let idx = PacketIndex::build(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(idx.len(), 45);
        assert!(!idx.truncated);

        // Cada trama de flujo cae en su flujo: el total coincide.
        let in_flows: usize = idx.by_flow.values().map(Vec::len).sum();
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
}
