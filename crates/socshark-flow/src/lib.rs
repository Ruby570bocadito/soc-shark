//! socshark-flow: agregación de paquetes en flujos bidireccionales.
//!
//! Es la etapa 3/4 del pipeline (etapa "Dissector Pool" + germen del
//! "Stream Reassembler"): consume [`socshark_dissectors::DissectedPacket`]
//! y produce [`socshark_core::EnrichedFlow`] listos para la capa SOC.
//!
//! Claves de diseño:
//! - **Bidireccionalidad canónica**: A→B y B→A comparten clave; los contadores
//!   se separan en dirección `fwd` (primer paquete observado) y `rev`.
//! - **Sin reordenar**: los timestamps fuera de orden solo empujan
//!   `first_seen` hacia atrás; nada se pierde.
//! - **Presión de memoria acotada**: `max_flows` con expulsión de los flujos
//!   más antiguos cuando se alcanza el límite (capturas largas o ataques de
//!   agotamiento de tabla).

use std::collections::HashMap;
use std::net::IpAddr;

use socshark_core::{
    DnsAnswerSummary, DnsQuerySummary, DnsSummary, EnrichedFlow, FlowId, FlowState, L7Protocol,
    TcpFlagCounts, Transport,
};
use socshark_dissectors::{DissectedPacket, DnsInfo};

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
}

impl FlowAccum {
    fn new(
        key: FlowKey,
        ts_micros: u64,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        dp: &DissectedPacket,
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
    stats: PipelineStats,
}

impl FlowAggregator {
    /// Crea un agregador con límite de tabla y timeout de inactividad.
    pub fn new(max_flows: usize, idle_timeout_secs: u64) -> Self {
        Self {
            flows: HashMap::new(),
            max_flows,
            idle_timeout_micros: idle_timeout_secs * 1_000_000,
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

        let Some(ip) = dp.ipv4.as_ref() else {
            self.stats.skipped_packets += 1;
            return;
        };
        let transport = Transport::from_ip_proto(ip.protocol);
        let (sport, dport) = match (dp.tcp.as_ref(), dp.udp.as_ref()) {
            (Some(t), _) => (t.src_port, t.dst_port),
            (_, Some(u)) => (u.src_port, u.dst_port),
            _ => (0, 0),
        };
        self.stats.parsed_packets += 1;

        let key = FlowKey::new(ip.src.into(), sport, ip.dst.into(), dport, transport);
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
                ip.src.into(),
                sport,
                ip.dst.into(),
                dport,
                dp,
            )
        });

        // ¿El paquete va en la dirección del primer paquete (fwd) o en la opuesta?
        let forward = acc.src == IpAddr::V4(ip.src) && acc.src_port == sport;
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

        if let Some(t) = dp.tcp.as_ref() {
            let f = t.flags;
            acc.flags.syn += f.syn as u32;
            acc.flags.ack += f.ack as u32;
            acc.flags.fin += f.fin as u32;
            acc.flags.rst += f.rst as u32;
            acc.flags.psh += f.psh as u32;
            acc.flags.urg += f.urg as u32;
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
            .filter_map(|k| self.flows.remove(&k).map(Self::export))
            .collect()
    }

    /// Finaliza la captura y exporta todos los flujos restantes, ordenados
    /// por primer avistamiento (el orden natural para el analista).
    pub fn finish(self) -> Vec<EnrichedFlow> {
        let mut out: Vec<EnrichedFlow> = self.flows.into_values().map(Self::export).collect();
        out.sort_by_key(|f| f.first_seen_micros);
        out
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

    /// Convierte un acumulador en el `EnrichedFlow` final. Los campos SOC
    /// (riesgo, alertas, resúmenes) los rellena después `socshark-soc`.
    fn export(acc: FlowAccum) -> EnrichedFlow {
        let state = if acc.flags.fin > 0 || acc.flags.rst > 0 {
            FlowState::Closed
        } else {
            FlowState::Idle
        };
        EnrichedFlow {
            flow_id: acc.key.flow_id(),
            state,
            transport: acc.key.transport,
            l7_protocol: acc.l7,
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
            // eBPF (Fase 3) y threat intel (Fase 4): aún sin valor.
            process_name: None,
            pid: None,
            user: None,
            resolved_domain: None,
            dns: acc.dns,
            dst_geo_asn: None,
            ja4_fingerprint: None,
            is_background_noise: false,
            human_summary: String::new(),
            risk_score: 0,
            alerts: Vec::new(),
            extracted_files: Vec::new(),
        }
    }
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
        let mut agg = FlowAggregator::new(1000, 120);
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

    #[test]
    fn fin_marcado_como_cerrado() {
        let mut agg = FlowAggregator::new(1000, 120);
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
        let mut agg = FlowAggregator::new(1000, 120);
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
        let mut agg = FlowAggregator::new(1000, 120); // 120 s
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
        let mut agg = FlowAggregator::new(4, 120);
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
