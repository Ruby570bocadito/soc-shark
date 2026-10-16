//! socshark-flow: agregación de paquetes en flujos bidireccionales.
//!
//! Es la etapa 3/4 del pipeline (etapa "Dissector Pool" + germen del
//! "Stream Reassembler"): consume [`socshark_dissectors::DissectedPacket`]
//! y produce [`socshark_core::EnrichedFlow`] listos para la capa SOC.
//!
//! Claves de diseño:
//! - **Bidireccionalidad canónica**: A→B y B→A comparten clave; los contadores
//!   se separan en dirección `fwd` (primer paquete observado) y `rev`.
//! - **IPv4 e IPv6 iguales ante la clave**: la clave canónica opera sobre
//!   `IpAddr`, así que la agregación v6 es exactamente la v4 (Fase 2).
//! - **Sin reordenar**: los timestamps fuera de orden solo empujan
//!   `first_seen` hacia atrás; nada se pierde.
//! - **Presión de memoria acotada**: `max_flows` con expulsión de los flujos
//!   más antiguos, y reensamblado TCP opcional con tope de 1 MiB por
//!   dirección ([`ReassembledStream`]).

use std::collections::HashMap;
use std::net::IpAddr;

use socshark_core::{
    DnsAnswerSummary, DnsQuerySummary, DnsSummary, EnrichedFlow, FlowId, FlowState, IntervalStats,
    L7Protocol, TcpFlagCounts, Transport,
};
use socshark_dissectors::{ClientHelloCapture, DissectedPacket, DnsInfo};

/// Tope de bytes recolectados por dirección y flujo para el reensamblado.
/// Lo que exceda el tope se descarta y se marca el stream como `lossy`.
pub const MAX_STREAM_BYTES: u64 = 1024 * 1024;

/// Timestamps en dirección iniciador que se retienen por flujo para las
/// estadísticas de intervalos (33 muestras = 32 intervalos; a un beacon de
/// 30 s cubre ~16 minutos, más que suficiente para estimar el periodo).
const MAX_TIMES_FWD: usize = 33;

/// Clave canónica de flujo bidireccional: los extremos se ordenan para que
/// A→B y B→A compartan clave.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub low: IpAddr,
    pub low_port: u16,
    pub high: IpAddr,
    pub high_port: u16,
    pub transport: Transport,
}

impl FlowKey {
    /// Normaliza un par de extremos (IP, puerto) en una clave canónica.
    pub fn new(a: IpAddr, a_port: u16, b: IpAddr, b_port: u16, transport: Transport) -> Self {
        let (low, low_port, high, high_port) = if (a, a_port) <= (b, b_port) {
            (a, a_port, b, b_port)
        } else {
            (b, b_port, a, a_port)
        };
        Self {
            low,
            low_port,
            high,
            high_port,
            transport,
        }
    }

    /// Identificador legible y estable del flujo.
    pub fn flow_id(&self) -> FlowId {
        FlowId(format!(
            "{}/{}:{}-{}:{}",
            self.transport.as_str().to_ascii_lowercase(),
            self.low,
            self.low_port,
            self.high,
            self.high_port
        ))
    }
}

/// Estadísticas globales del pipeline.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineStats {
    pub total_packets: u64,
    pub parsed_packets: u64,
    pub skipped_packets: u64,
    pub flows_created: u64,
}

impl PipelineStats {
    /// Resumen en una línea para la barra de progreso de la CLI.
    pub fn summary(&self) -> String {
        format!(
            "{} paquetes leídos · {} diseccionados · {} descartados · {} flujos",
            self.total_packets, self.parsed_packets, self.skipped_packets, self.flows_created
        )
    }
}

// --------------------------------------------------- reensamblado TCP (Fase 2)

/// Buffer de una dirección: segmentos `(seq, datos)` con su ISN observado.
#[derive(Debug, Default, Clone)]
struct StreamBuf {
    /// Número de secuencia del primer segmento observado en la dirección.
    base: Option<u32>,
    segs: Vec<(u32, Vec<u8>)>,
    collected: u64,
    truncated: bool,
}

impl StreamBuf {
    fn push(&mut self, seq: u32, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        match self.base {
            None => self.base = Some(seq),
            Some(b) => {
                // Si el segmento es ANTERIOR a la base (comparación serial con
                // signo, RFC 9293 §3.3), la captura empezó a mitad de dirección:
                // se retrocede la base para que todos los offsets queden
                // ordenables hacia adelante.
                if (seq.wrapping_sub(b) as i32) < 0 {
                    self.base = Some(seq);
                }
            }
        }
        if self.collected + data.len() as u64 > MAX_STREAM_BYTES {
            self.truncated = true;
            return;
        }
        self.collected += data.len() as u64;
        self.segs.push((seq, data.to_vec()));
    }

    /// Reensambla en orden de secuencia relativo al primer ISN observado:
    /// elimina retransmisiones solapadas y marca los huecos con un
    /// separador legible. Devuelve `(bytes, hay_pérdida)`.
    fn reassemble(&self) -> (Vec<u8>, bool) {
        let Some(base) = self.base else {
            return (Vec::new(), false);
        };
        let mut segs = self.segs.clone();
        segs.sort_by_key(|(seq, _)| seq.wrapping_sub(base));

        let mut out = Vec::with_capacity(self.collected as usize);
        let mut cursor: u64 = 0; // offset relativo ya cubierto
        let mut lossy = self.truncated;
        for (seq, data) in segs {
            let off = seq.wrapping_sub(base) as u64;
            let end = off + data.len() as u64;
            if end <= cursor {
                continue; // retransmisión íntegra ya vista
            }
            if off > cursor {
                let gap = off - cursor;
                out.extend_from_slice(format!("\n[{gap} bytes perdidos]\n").as_bytes());
                lossy = true;
                out.extend_from_slice(&data);
            } else {
                let skip = (cursor - off) as usize;
                out.extend_from_slice(&data[skip..]);
            }
            cursor = end;
        }
        (out, lossy)
    }
}

/// Par de streams de un flujo TCP (cliente = origen del primer paquete).
#[derive(Debug, Clone)]
struct StreamPair {
    fwd: StreamBuf,
    rev: StreamBuf,
}

/// Stream TCP reensamblado, listo para `socshark follow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledStream {
    /// Bytes del iniciador de la conexión (src del primer paquete).
    pub client: Vec<u8>,
    /// Bytes del otro extremo.
    pub server: Vec<u8>,
    /// True si hubo huecos de secuencia, retransmisiones inconsistentes o
    /// descartes por el tope de memoria.
    pub client_lossy: bool,
    pub server_lossy: bool,
}

// ------------------------------------------------------------ acumuladores

/// Acumulador interno por flujo.
#[derive(Debug, Clone)]
struct FlowAccum {
    key: FlowKey,
    /// Extremos según el PRIMER paquete observado (dirección "fwd").
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
    src_mac: Option<String>,
    dst_mac: Option<String>,
    first_seen: u64,
    last_seen: u64,
    packets_fwd: u64,
    bytes_fwd: u64,
    packets_rev: u64,
    bytes_rev: u64,
    flags: TcpFlagCounts,
    l7: L7Protocol,
    dns: Option<DnsSummary>,
    streams: Option<StreamPair>,
    /// Captura acotada del ClientHello del iniciador (Fase 3, JA4).
    hello: ClientHelloCapture,
    /// Timestamps (µs) de los primeros paquetes en dirección iniciador
    /// (Fase 3, beaconing). No mantiene orden: se ordena al exportar.
    times_fwd: Vec<u64>,
}

impl FlowAccum {
    #[allow(clippy::too_many_arguments)]
    fn new(
        key: FlowKey,
        ts_micros: u64,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        dp: &DissectedPacket,
        collect_streams: bool,
    ) -> Self {
        let (src_mac, dst_mac) = dp
            .eth
            .as_ref()
            .map(|e| (Some(e.src_mac_str()), Some(e.dst_mac_str())))
            .unwrap_or((None, None));
        Self {
            key,
            src,
            src_port,
            dst,
            dst_port,
            src_mac,
            dst_mac,
            first_seen: ts_micros,
            last_seen: ts_micros,
            packets_fwd: 0,
            bytes_fwd: 0,
            packets_rev: 0,
            bytes_rev: 0,
            flags: TcpFlagCounts::default(),
            l7: dp.l7,
            dns: None,
            streams: if collect_streams && dp.transport == Transport::Tcp {
                Some(StreamPair {
                    fwd: StreamBuf::default(),
                    rev: StreamBuf::default(),
                })
            } else {
                None
            },
            hello: ClientHelloCapture::default(),
            times_fwd: Vec::new(),
        }
    }

    /// Fusiona un paquete DNS en el resumen del flujo: la consulta aporta
    /// `queries`, la respuesta aporta `rcode` + `answers` (y marca
    /// `is_response`). Así un flujo query+response queda completo.
    fn merge_dns(&mut self, d: &DnsInfo) {
        let to_query = |q: &socshark_dissectors::DnsQuestion| DnsQuerySummary {
            name: q.name.clone(),
            qtype: q.qtype,
        };
        let to_answer = |r: &socshark_dissectors::DnsRecord| DnsAnswerSummary {
            name: r.name.clone(),
            rtype: r.rtype,
            ttl: r.ttl,
            address: r.address,
            target: r.target.clone(),
        };

        match self.dns.as_mut() {
            None => {
                self.dns = Some(DnsSummary {
                    is_response: d.is_response,
                    rcode: d.rcode,
                    queries: d.queries.iter().map(to_query).collect(),
                    answers: d.answers.iter().map(to_answer).collect(),
                });
            }
            Some(s) => {
                if d.is_response {
                    s.is_response = true;
                    s.rcode = d.rcode;
                    s.answers = d.answers.iter().map(to_answer).collect();
                } else {
                    s.queries = d.queries.iter().map(to_query).collect();
                }
            }
        }
    }
}

/// Agregador de flujos: convierte paquetes diseccionados en
/// [`EnrichedFlow`] listos para el enriquecimiento SOC.
pub struct FlowAggregator {
    flows: HashMap<FlowKey, FlowAccum>,
    max_flows: usize,
    idle_timeout_micros: u64,
    collect_streams: bool,
    stats: PipelineStats,
}

impl FlowAggregator {
    /// Crea un agregador con límite de tabla, timeout de inactividad y la
    /// opción de recolectar segmentos TCP para reensamblar streams.
    pub fn new(max_flows: usize, idle_timeout_secs: u64, collect_streams: bool) -> Self {
        Self {
            flows: HashMap::new(),
            max_flows,
            idle_timeout_micros: idle_timeout_secs * 1_000_000,
            collect_streams,
            stats: PipelineStats::default(),
        }
    }

    /// Estadísticas acumuladas del pipeline.
    pub fn stats(&self) -> PipelineStats {
        self.stats
    }

    /// Registra un paquete ya diseccionado.
    ///
    /// `raw_len` es el tamaño capturado del paquete (cabeceras incluidas) y
    /// alimenta los contadores de bytes.
    pub fn on_packet(&mut self, ts_micros: u64, raw_len: usize, dp: &DissectedPacket) {
        self.stats.total_packets += 1;

        let (Some(src_ip), Some(dst_ip)) = (dp.src_ip(), dp.dst_ip()) else {
            self.stats.skipped_packets += 1;
            return;
        };
        let transport = dp.transport;
        let (sport, dport) = match (dp.tcp.as_ref(), dp.udp.as_ref()) {
            (Some(t), _) => (t.src_port, t.dst_port),
            (_, Some(u)) => (u.src_port, u.dst_port),
            _ => (0, 0),
        };
        self.stats.parsed_packets += 1;

        let key = FlowKey::new(src_ip, sport, dst_ip, dport, transport);
        if !self.flows.contains_key(&key) && self.flows.len() >= self.max_flows {
            self.force_expire();
        }

        let flows = &mut self.flows;
        let stats = &mut self.stats;
        let acc = flows.entry(key.clone()).or_insert_with(|| {
            stats.flows_created += 1;
            FlowAccum::new(
                key,
                ts_micros,
                src_ip,
                sport,
                dst_ip,
                dport,
                dp,
                self.collect_streams,
            )
        });

        // ¿El paquete va en la dirección del primer paquete (fwd) o en la opuesta?
        let forward = acc.src == src_ip && acc.src_port == sport;
        if forward {
            acc.packets_fwd += 1;
            acc.bytes_fwd += raw_len as u64;
        } else {
            acc.packets_rev += 1;
            acc.bytes_rev += raw_len as u64;
        }

        // Tolerancia a reordenamiento: first_seen solo retrocede.
        if ts_micros < acc.first_seen {
            acc.first_seen = ts_micros;
        }
        if ts_micros > acc.last_seen {
            acc.last_seen = ts_micros;
        }

        // Ventana acotada de timestamps del iniciador (Fase 3, beaconing).
        if forward && acc.times_fwd.len() < MAX_TIMES_FWD {
            acc.times_fwd.push(ts_micros);
        }

        if let Some(t) = dp.tcp.as_ref() {
            let f = t.flags;
            acc.flags.syn += f.syn as u32;
            acc.flags.ack += f.ack as u32;
            acc.flags.fin += f.fin as u32;
            acc.flags.rst += f.rst as u32;
            acc.flags.psh += f.psh as u32;
            acc.flags.urg += f.urg as u32;

            // Reensamblado (Fase 2): solo segmentos con payload.
            if let Some(sp) = acc.streams.as_mut() {
                if !dp.payload.is_empty() {
                    let dir = if forward { &mut sp.fwd } else { &mut sp.rev };
                    dir.push(t.seq, &dp.payload);
                }
            }

            // Captura del ClientHello (Fase 3, JA4): solo la dirección del
            // iniciador; la máquina de estados rechaza no-TLS por si sola.
            if forward && !dp.payload.is_empty() {
                acc.hello.feed(&dp.payload);
            }
        }

        if acc.l7 == L7Protocol::Unknown && dp.l7 != L7Protocol::Unknown {
            acc.l7 = dp.l7;
        }
        if let Some(d) = dp.dns.as_ref() {
            acc.merge_dns(d);
        }
    }

    /// Expulsa los flujos inactivos (last_seen + timeout < now) y los devuelve.
    pub fn drain_expired(&mut self, now_micros: u64) -> Vec<EnrichedFlow> {
        let timeout = self.idle_timeout_micros;
        let expired: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, a)| now_micros.saturating_sub(a.last_seen) > timeout)
            .map(|(k, _)| k.clone())
            .collect();
        expired
            .into_iter()
            .filter_map(|k| {
                self.flows
                    .remove(&k)
                    .map(|acc| Self::export_with_streams(acc).0)
            })
            .collect()
    }

    /// Finaliza la captura y exporta todos los flujos restantes, ordenados
    /// por primer avistamiento (el orden natural para el analista).
    pub fn finish(self) -> Vec<EnrichedFlow> {
        self.finish_with_streams().0
    }

    /// Como [`FlowAggregator::finish`], pero además devuelve los streams TCP
    /// reensamblados por flujo (solo si `collect_streams` estaba activo).
    /// La clave del mapa es el `flow_id` del flujo.
    pub fn finish_with_streams(self) -> (Vec<EnrichedFlow>, HashMap<String, ReassembledStream>) {
        let mut streams_out = HashMap::new();
        let mut out: Vec<EnrichedFlow> = self
            .flows
            .into_values()
            .map(|acc| {
                let (flow, streams) = Self::export_with_streams(acc);
                if let Some(s) = streams {
                    streams_out.insert(flow.flow_id.0.clone(), s);
                }
                flow
            })
            .collect();
        out.sort_by_key(|f| f.first_seen_micros);
        (out, streams_out)
    }

    /// Bajo presión de memoria: expulsa los `excess` flujos con `last_seen`
    /// más antiguo (independientemente de su timeout) hasta dejar la tabla
    /// al 90% de `max_flows`.
    fn force_expire(&mut self) {
        let target = self.max_flows * 9 / 10;
        if self.flows.len() <= target {
            return;
        }
        let mut by_age: Vec<(FlowKey, u64)> = self
            .flows
            .iter()
            .map(|(k, v)| (k.clone(), v.last_seen))
            .collect();
        by_age.sort_by_key(|(_, ls)| *ls);
        let excess = self.flows.len() - target;
        for (k, _) in by_age.into_iter().take(excess) {
            self.flows.remove(&k);
        }
    }

    /// Convierte un acumulador en el `EnrichedFlow` final y, si procede, su
    /// stream reensamblado. Los campos SOC (riesgo, alertas, resúmenes) los
    /// rellena después `socshark-soc`.
    fn export_with_streams(mut acc: FlowAccum) -> (EnrichedFlow, Option<ReassembledStream>) {
        let state = if acc.flags.fin > 0 || acc.flags.rst > 0 {
            FlowState::Closed
        } else {
            FlowState::Idle
        };
        let streams = acc.streams.take().map(|sp| {
            let (client, client_lossy) = sp.fwd.reassemble();
            let (server, server_lossy) = sp.rev.reassemble();
            ReassembledStream {
                client,
                server,
                client_lossy,
                server_lossy,
            }
        });
        let interval_stats = interval_stats_of(&acc.times_fwd);
        let (ja4_fingerprint, tls_sni) = match acc.hello.hello() {
            Some(ch) => (Some(ch.ja4()), ch.sni.clone()),
            None => (None, None),
        };
        let flow = EnrichedFlow {
            flow_id: acc.key.flow_id(),
            state,
            transport: acc.key.transport,
            l7_protocol: acc.l7,
            ip_version: match acc.src {
                IpAddr::V4(_) => 4,
                IpAddr::V6(_) => 6,
            },
            src_ip: acc.src,
            src_port: acc.src_port,
            dst_ip: acc.dst,
            dst_port: acc.dst_port,
            src_mac: acc.src_mac,
            dst_mac: acc.dst_mac,
            first_seen_micros: acc.first_seen,
            last_seen_micros: acc.last_seen,
            duration_micros: acc.last_seen.saturating_sub(acc.first_seen),
            packets: acc.packets_fwd,
            bytes: acc.bytes_fwd,
            packets_rev: acc.packets_rev,
            bytes_rev: acc.bytes_rev,
            tcp_flags: acc.flags,
            // eBPF (Fase 3) y threat intel (Fase 4): aún sin valor; el
            // enriquecimiento SOC rellena threat_intel si hay listas cargadas.
            process_name: None,
            pid: None,
            user: None,
            resolved_domain: None,
            dns: acc.dns,
            dst_geo_asn: None,
            ja4_fingerprint,
            tls_sni,
            interval_stats,
            threat_intel: Vec::new(),
            is_background_noise: false,
            human_summary: String::new(),
            risk_score: 0,
            alerts: Vec::new(),
            extracted_files: Vec::new(),
        };
        (flow, streams)
    }
}

/// Estadística de intervalos sobre los timestamps del iniciador.
///
/// Se ordena (tolerancia a reordenamiento de la captura) y se calculan los
/// deltas consecutivos; con menos de 3 paquetes (2 intervalos) no hay
/// estadística útil y se devuelve `None`.
fn interval_stats_of(times_fwd: &[u64]) -> Option<IntervalStats> {
    if times_fwd.len() < 3 {
        return None;
    }
    let mut ts = times_fwd.to_vec();
    ts.sort_unstable();
    let deltas: Vec<u64> = ts.windows(2).map(|w| w[1] - w[0]).collect();
    let n = deltas.len() as f64;
    let mean = deltas.iter().sum::<u64>() as f64 / n;
    let var = deltas
        .iter()
        .map(|&d| {
            let x = d as f64 - mean;
            x * x
        })
        .sum::<f64>()
        / n;
    Some(IntervalStats {
        intervals: deltas.len() as u32,
        mean_micros: mean.round() as u64,
        std_micros: var.sqrt().round() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_core::RawPacket;
    use socshark_dissectors::DissectorPipeline;
    use socshark_testgen as tg;

    /// Diseca una trama y devuelve (tamaño_capturado, paquete_diseccionado).
    /// La trama se traslada al heap con duración 'static para simplificar.
    fn dissected(pkt: Vec<u8>) -> (usize, DissectedPacket<'static>) {
        let len = pkt.len();
        let raw: &'static RawPacket = Box::leak(Box::new(RawPacket {
            ts_micros: 0,
            orig_len: len as u32,
            data: pkt,
        }));
        let dp = DissectorPipeline::new()
            .dissect(raw, socshark_core::LinkType::Ethernet)
            .expect("trama del testgen diseccionable");
        (len, dp)
    }

    #[test]
    fn bidireccional_comparte_flujo() {
        let mut agg = FlowAggregator::new(1000, 120, false);
        let (len1, dp1) = dissected(tg::frame_tcp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::WEB,
            52000,
            443,
            1,
            0,
            tg::flags::SYN,
            &[],
        ));
        let (len2, dp2) = dissected(tg::frame_tcp(
            tg::MAC_ROUTER,
            tg::MAC_HOST_A,
            tg::WEB,
            tg::HOST_A,
            443,
            52000,
            2,
            2,
            tg::flags::SYN_ACK,
            &[],
        ));
        agg.on_packet(1_000, len1, &dp1);
        agg.on_packet(2_000, len2, &dp2);

        let flows = agg.finish();
        assert_eq!(flows.len(), 1, "A→B y B→A deben ser el mismo flujo");
        let f = &flows[0];
        assert_eq!(f.packets, 1);
        assert_eq!(f.packets_rev, 1);
        assert_eq!(f.tcp_flags.syn, 2); // SYN + SYN-ACK
        assert_eq!(f.state, FlowState::Idle); // sin FIN/RST
    }

    // ---------------------------------------------- Fase 2: IPv6

    #[test]
    fn flujo_ipv6_se_agrega_como_ipv4() {
        let mut agg = FlowAggregator::new(1000, 120, false);
        let (len1, d1) = dissected(tg::frame_ipv6_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A6,
            tg::DNS6,
            53010,
            53,
            &tg::dns_query(0x0606, "v6.example.com", 28),
        ));
        let (len2, d2) = dissected(tg::frame_ipv6_udp(
            tg::MAC_ROUTER,
            tg::MAC_HOST_A,
            tg::DNS6,
            tg::HOST_A6,
            53,
            53010,
            &tg::dns_response_aaaa(0x0606, "v6.example.com", tg::WEB6),
        ));
        agg.on_packet(1_000, len1, &d1);
        agg.on_packet(2_000, len2, &d2);

        let flows = agg.finish();
        assert_eq!(flows.len(), 1);
        let f = &flows[0];
        assert_eq!(f.ip_version, 6);
        assert_eq!(f.src_ip, IpAddr::V6(tg::HOST_A6));
        assert_eq!(f.dst_ip, IpAddr::V6(tg::DNS6));
        assert_eq!(f.packets_rev, 1);
        let dns = f.dns.as_ref().expect("resumen DNS v6");
        assert_eq!(dns.answers[0].address, Some(IpAddr::V6(tg::WEB6)));
        // flow_id con literal IPv6 entre corchetes visualmente legible.
        assert!(f.flow_id.0.contains("fd00::10") || f.flow_id.0.contains("fd00:"));
    }

    // ---------------------------------------- Fase 2: reensamblado TCP

    /// Pcap sintético: cliente manda 2 segmentos y servidor responde con
    /// un segmento fuera de orden + retransmisión solapada.
    #[allow(clippy::vec_init_then_push)]
    fn pcap_streams() -> Vec<(u64, Vec<u8>)> {
        let (sp, s_seq, r_seq) = (50000u16, 1000u32, 5000u32);
        let mut pkts: Vec<(u64, Vec<u8>)> = Vec::new();
        // Cliente → servidor: "HOLA " (seq 1000) y "MUNDO" (seq 1005).
        pkts.push((
            1_000,
            tg::frame_tcp(
                tg::MAC_HOST_A,
                tg::MAC_ROUTER,
                tg::HOST_A,
                tg::WEB,
                sp,
                8080,
                s_seq,
                r_seq,
                tg::flags::PSH_ACK,
                b"HOLA ",
            ),
        ));
        pkts.push((
            2_000,
            tg::frame_tcp(
                tg::MAC_HOST_A,
                tg::MAC_ROUTER,
                tg::HOST_A,
                tg::WEB,
                sp,
                8080,
                s_seq + 5,
                r_seq,
                tg::flags::PSH_ACK,
                b"MUNDO",
            ),
        ));
        // Servidor → cliente: llega primero el segmento LECLeJO (seq 5005)
        // y después el inicial (seq 5000): fuera de orden en la captura.
        pkts.push((
            3_000,
            tg::frame_tcp(
                tg::MAC_ROUTER,
                tg::MAC_HOST_A,
                tg::WEB,
                tg::HOST_A,
                8080,
                sp,
                r_seq + 5,
                s_seq + 10,
                tg::flags::PSH_ACK,
                b"ECLEJO",
            ),
        ));
        // Retransmisión solapada de "ADIOS" + 2 bytes ya vistos.
        pkts.push((
            4_000,
            tg::frame_tcp(
                tg::MAC_ROUTER,
                tg::MAC_HOST_A,
                tg::WEB,
                tg::HOST_A,
                8080,
                sp,
                r_seq,
                s_seq + 10,
                tg::flags::PSH_ACK,
                b"ADIOSECLEJO",
            ),
        ));
        pkts
    }

    #[test]
    fn reensamblado_orden_retransmisiones_y_huecos() {
        let mut agg = FlowAggregator::new(1000, 120, true);
        let pipe = DissectorPipeline::new();
        for (ts, frame) in pcap_streams() {
            let len = frame.len();
            let raw = RawPacket {
                ts_micros: ts,
                orig_len: len as u32,
                data: frame,
            };
            if let Some(dp) = pipe.dissect(&raw, socshark_core::LinkType::Ethernet) {
                agg.on_packet(ts, len, &dp);
            }
        }
        let (flows, streams) = agg.finish_with_streams();
        assert_eq!(flows.len(), 1);
        let s = streams.get(&flows[0].flow_id.0).expect("stream presente");

        // Cliente: dos segmentos consecutivos → sin huecos.
        assert_eq!(s.client, b"HOLA MUNDO");
        assert!(!s.client_lossy);

        // Servidor: "ECLEJO" llegó antes (seq+5), "ADIOSECLEJO" retransmite
        // "ADIOS" + solapa 6 bytes; el reensamblado debe dar "ADIOS"+"ECLEJO".
        assert_eq!(s.server, b"ADIOSECLEJO");
        assert!(!s.server_lossy);
    }

    #[test]
    fn hueco_de_secuencia_se_marca() {
        let mut agg = FlowAggregator::new(1000, 120, true);
        // Solo dos segmentos con un hueco de 100 bytes entre ellos.
        let (len1, d1) = dissected(tg::frame_tcp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::WEB,
            50001,
            8080,
            1000,
            0,
            tg::flags::PSH_ACK,
            b"INICIO",
        ));
        agg.on_packet(1_000, len1, &d1);
        let (len2, d2) = dissected(tg::frame_tcp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::WEB,
            50001,
            8080,
            1106,
            0,
            tg::flags::PSH_ACK,
            b"FINAL",
        ));
        agg.on_packet(2_000, len2, &d2);

        let (_, streams) = agg.finish_with_streams();
        let s = streams.values().next().unwrap();
        assert_eq!(s.client, b"INICIO\n[100 bytes perdidos]\nFINAL");
        assert!(s.client_lossy);
    }

    #[test]
    fn tope_de_stream_marca_lossy() {
        // 20 segmentos de 60 KiB (el máximo realista de IPv4 son ~65 KiB por
        // datagrama): 1,2 MiB en total supera el tope de 1 MiB por dirección.
        let seg = vec![b'x'; 60_000];
        let mut agg = FlowAggregator::new(1000, 120, true);
        for i in 0..20u32 {
            let seq = 1000 + i * 60_000;
            let (len, d) = dissected(tg::frame_tcp(
                tg::MAC_HOST_A,
                tg::MAC_ROUTER,
                tg::HOST_A,
                tg::WEB,
                50002,
                8080,
                seq,
                0,
                tg::flags::PSH_ACK,
                &seg,
            ));
            agg.on_packet((i as u64 + 1) * 1_000, len, &d);
        }
        let (_, streams) = agg.finish_with_streams();
        let s = streams.values().next().unwrap();
        assert!(
            s.client_lossy,
            "los segmentos que exceden el tope se descartan"
        );
        // 17 × 60.000 = 1.020.000 bytes entran; el 18.º ya excede 1 MiB.
        assert_eq!(s.client.len(), 1_020_000);
    }

    #[test]
    fn sin_collect_streams_no_hay_mapa() {
        let mut agg = FlowAggregator::new(1000, 120, false);
        let (len, d) = dissected(tg::frame_tcp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::WEB,
            50003,
            8080,
            1,
            0,
            tg::flags::PSH_ACK,
            b"payload",
        ));
        agg.on_packet(1_000, len, &d);
        let (_, streams) = agg.finish_with_streams();
        assert!(streams.is_empty());
    }

    #[test]
    fn fin_marcado_como_cerrado() {
        let mut agg = FlowAggregator::new(1000, 120, false);
        let (len1, d1) = dissected(tg::frame_tcp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::WEB,
            52000,
            443,
            1,
            0,
            tg::flags::FIN,
            &[],
        ));
        agg.on_packet(1_000, len1, &d1);
        let f = agg.finish().remove(0);
        assert_eq!(f.state, FlowState::Closed);
    }

    #[test]
    fn dns_query_y_respuesta_se_fusionan() {
        let mut agg = FlowAggregator::new(1000, 120, false);
        let (len1, d1) = dissected(tg::frame_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::DNS_EXT,
            53001,
            53,
            &tg::dns_query(0x1234, "example.com", 1),
        ));
        let (len2, d2) = dissected(tg::frame_udp(
            tg::MAC_ROUTER,
            tg::MAC_HOST_A,
            tg::DNS_EXT,
            tg::HOST_A,
            53,
            53001,
            &tg::dns_response(0x1234, "example.com", 1, tg::WEB),
        ));
        agg.on_packet(1_000, len1, &d1);
        agg.on_packet(2_000, len2, &d2);

        let f = agg.finish().remove(0);
        let dns = f.dns.expect("resumen DNS presente");
        assert!(dns.is_response);
        assert_eq!(dns.queries[0].name, "example.com");
        assert_eq!(dns.answers[0].address, Some(std::net::IpAddr::V4(tg::WEB)));
    }

    #[test]
    fn drain_expired_expulsa_solo_inactivos() {
        let mut agg = FlowAggregator::new(1000, 120, false); // 120 s
        let (len1, d1) = dissected(tg::frame_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::DNS_EXT,
            53001,
            53,
            &tg::dns_query(1, "a.example", 1),
        ));
        agg.on_packet(1_000_000, len1, &d1); // t = 1 s

        assert!(agg.drain_expired(30_000_000).is_empty()); // t = 30 s: aún activo
        let expired = agg.drain_expired(200_000_000); // t = 200 s: expira
        assert_eq!(expired.len(), 1);
        assert!(agg.finish().is_empty());
    }

    #[test]
    fn max_flows_fuerza_expulsion_de_los_mas_antiguos() {
        let mut agg = FlowAggregator::new(4, 120, false);
        // 6 flujos distintos (puertos origen distintos), límite 4 → quedan ~3-4.
        for i in 0..6u16 {
            let (len, d) = dissected(tg::frame_udp(
                tg::MAC_HOST_A,
                tg::MAC_ROUTER,
                tg::HOST_A,
                tg::DNS_EXT,
                50000 + i,
                53,
                &tg::dns_query(i, &format!("f{i}.example"), 1),
            ));
            agg.on_packet((i as u64 + 1) * 1_000_000, len, &d);
        }
        let flows = agg.finish();
        assert!(
            flows.len() <= 4,
            "la tabla no debe superar max_flows tras la expulsión (obtenido {})",
            flows.len()
        );
    }
}
