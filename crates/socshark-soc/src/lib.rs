//! socshark-soc: capa de análisis SOC ("soc-engine" del diseño original).
//!
//! Módulos independientes orquestados por [`enrich::enrich_all`]:
//! - [`noise`]: Smart Noise Dimming (clasificación de tráfico de fondo).
//! - [`passive_dns`]: caché dominio↔IP construida con las respuestas DNS.
//! - [`risk`]: mini-IDS heurístico + puntuación de riesgo (0-100).
//! - [`summarize`]: traducción semántica a lenguaje humano.
//!
//! Las fases posteriores añadirán aquí: detección de beaconing, file carving
//! con SHA-256, threat intel offline (GeoIP/ASN/Feodo/Tor) y export SIEM.
//! Ver `docs/soc-features.md` y `docs/soc-mitre-mapping.md`.

pub mod enrich;
pub mod noise;
pub mod passive_dns;
pub mod risk;
pub mod summarize;

use std::collections::HashMap;
use std::net::IpAddr;

use socshark_core::{EnrichedFlow, Transport};

pub use enrich::{enrich_all, SocContext};

/// (ip_origen, ip_destino, puerto_destino) objetivo de un posible escaneo.
pub type ScanKey = (IpAddr, IpAddr, u16);

/// Rastrea patrones de escaneo SYN a través de flujos.
///
/// ¿Por qué aquí y no en el agregador? Un escáner cambia de puerto origen en
/// cada conexión, así que produce *flujos distintos* de un solo SYN. El
/// patrón solo es visible con estado **entre flujos**, agrupado por
/// (origen, destino, puerto_destino): exactamente lo que hace este tracker.
#[derive(Default)]
pub struct ScanTracker {
    counts: HashMap<ScanKey, u32>,
}

impl ScanTracker {
    /// Observa un flujo exportado y acumula sus SYNs "en seco" (SYN sin ACK
    /// en el flujo completo). Un SYN+SYN-ACK legítimo nunca cuenta porque el
    /// flujo contiene ACKs.
    pub fn observe(&mut self, flow: &EnrichedFlow) {
        if flow.transport == Transport::Tcp
            && flow.tcp_flags.syn > 0
            && flow.tcp_flags.ack == 0
            && flow.tcp_flags.fin == 0
        {
            *self
                .counts
                .entry((flow.src_ip, flow.dst_ip, flow.dst_port))
                .or_default() += flow.tcp_flags.syn;
        }
    }

    /// Número de SYNs en seco observados hacia este destino desde esa origen.
    pub fn hits(&self, key: &ScanKey) -> u32 {
        self.counts.get(key).copied().unwrap_or(0)
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    use socshark_core::{EnrichedFlow, FlowId, FlowState, L7Protocol, TcpFlagCounts, Transport};
    use std::net::{IpAddr, Ipv4Addr};

    /// Flujo genérico para tests: extremos neutros y el protocolo indicado.
    /// `proto_num` es el número de protocolo IP (6=TCP, 17=UDP).
    pub(crate) fn flujo_basico(proto_num: u8, sport: u16, dport: u16) -> EnrichedFlow {
        let transport = Transport::from_ip_proto(proto_num);
        EnrichedFlow {
            flow_id: FlowId(format!("{transport:?}/10.0.0.5:{sport}-10.0.0.99:{dport}")),
            state: FlowState::Idle,
            transport,
            l7_protocol: L7Protocol::Unknown,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            src_port: sport,
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
            dst_port: dport,
            src_mac: None,
            dst_mac: None,
            first_seen_micros: 0,
            last_seen_micros: 1_000,
            duration_micros: 1_000,
            packets: 1,
            bytes: 100,
            packets_rev: 0,
            bytes_rev: 0,
            tcp_flags: TcpFlagCounts::default(),
            process_name: None,
            pid: None,
            user: None,
            resolved_domain: None,
            dns: None,
            dst_geo_asn: None,
            ja4_fingerprint: None,
            is_background_noise: false,
            human_summary: String::new(),
            risk_score: 0,
            alerts: vec![],
            extracted_files: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_core::{FlowId, FlowState, L7Protocol};

    fn flujo_syn_solo(sport: u16) -> EnrichedFlow {
        EnrichedFlow {
            flow_id: FlowId(format!("tcp/10.0.0.9:{sport}-10.0.0.1:22")),
            state: FlowState::Idle,
            transport: Transport::Tcp,
            l7_protocol: L7Protocol::Unknown,
            src_ip: "10.0.0.9".parse().unwrap(),
            src_port: sport,
            dst_ip: "10.0.0.1".parse().unwrap(),
            dst_port: 22,
            src_mac: None,
            dst_mac: None,
            first_seen_micros: 0,
            last_seen_micros: 1,
            duration_micros: 1,
            packets: 1,
            bytes: 60,
            packets_rev: 0,
            bytes_rev: 0,
            tcp_flags: socshark_core::TcpFlagCounts {
                syn: 1,
                ..Default::default()
            },
            process_name: None,
            pid: None,
            user: None,
            resolved_domain: None,
            dns: None,
            dst_geo_asn: None,
            ja4_fingerprint: None,
            is_background_noise: false,
            human_summary: String::new(),
            risk_score: 0,
            alerts: vec![],
            extracted_files: vec![],
        }
    }

    #[test]
    fn tracker_acumula_flujos_distintos_del_mismo_escaneo() {
        let mut t = ScanTracker::default();
        for i in 0..3u16 {
            t.observe(&flujo_syn_solo(40000 + i));
        }
        let key: ScanKey = ("10.0.0.9".parse().unwrap(), "10.0.0.1".parse().unwrap(), 22);
        assert_eq!(t.hits(&key), 3);
    }
}
