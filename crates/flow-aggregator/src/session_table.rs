//! Tabla de sesiones: agrupa paquetes sueltos en conversaciones (5-tupla).

use crate::model::{EnrichedFlow, FlowKey, FlowState, MAX_PACKET_PTRS};
use socshark_dissectors::layer7::dns::qtype_name;
use socshark_dissectors::view::{AppInfo, DissectedPacket};
use std::collections::HashMap;

/// Agregador de conversaciones.
///
/// `feed` se llama por cada paquete diseccionado; el estado interno es un
/// `HashMap<FlowKey, usize>` hacia un `Vec<EnrichedFlow>` (estable para que
/// `soc-engine` pueda enriquecer por índice después). Las búsquedas prueban
/// la tupla directa y la invertida: una conversación TCP bidireccional es
/// **una sola fila**, no dos.
#[derive(Default)]
pub struct SessionTable {
    flows: Vec<EnrichedFlow>,
    index: HashMap<FlowKey, usize>,
}

impl SessionTable {
    pub fn new() -> Self {
        SessionTable::default()
    }

    /// Número de conversaciones.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn flows(&self) -> &[EnrichedFlow] {
        &self.flows
    }

    pub fn flows_mut(&mut self) -> &mut [EnrichedFlow] {
        &mut self.flows
    }

    /// Incorpora un paquete a su conversación (creándola si no existe).
    ///
    /// `file_offset` = offset del paquete en el buffer de la captura, para el
    /// acordeón desplegable de la UI (lectura directa por mmap en fase 2).
    pub fn feed(&mut self, dp: &DissectedPacket, file_offset: u64) {
        let Some(tuple) = &dp.five_tuple else {
            return; // ARP/ICMP: sin 5-tupla completa, fuera del modelo Flow-First
        };
        let key = FlowKey {
            src: tuple.src,
            sport: tuple.src_port,
            dst: tuple.dst,
            dport: tuple.dst_port,
            proto: tuple.proto,
        };
        let idx = self.get_or_create(&key, dp.ts_us);
        let flow = &mut self.flows[idx];
        let is_c2s = flow.key == key;
        let has_data = dp.app_payload.map(|p| !p.is_empty()).unwrap_or(false);

        if is_c2s {
            flow.packets_c2s += 1;
            flow.bytes_c2s += dp.app_payload.map(|p| p.len()).unwrap_or(0) as u64;
        } else {
            flow.packets_s2c += 1;
            flow.bytes_s2c += dp.app_payload.map(|p| p.len()).unwrap_or(0) as u64;
        }
        flow.packet_count += 1;
        flow.last_seen_us = flow.last_seen_us.max(dp.ts_us);
        flow.duration_ms = flow.last_seen_us.saturating_sub(flow.first_seen_us) / 1000;
        if flow.packet_offsets.len() < MAX_PACKET_PTRS {
            flow.packet_offsets.push(file_offset);
            flow.packet_ts.push(dp.ts_us);
            flow.packet_data.push(match (has_data, is_c2s) {
                (true, true) => 1,  // datos cliente→servidor
                (true, false) => 2, // datos servidor→cliente
                (false, _) => 0,
            });
        }

        // Máquina de estados TCP ligera.
        if let Some(flags) = dp.tcp_flags() {
            if flags & 0x04 != 0 {
                flow.state = FlowState::Reset; // RST
            } else if flags & 0x01 != 0 && flow.state == FlowState::Active {
                flow.state = FlowState::Closed; // FIN
            }
        }

        // Digests L7 (flat) para resúmenes, DSL y enriquecimiento.
        if let Some(app) = &dp.app {
            match app {
                AppInfo::Dns(d) => {
                    flow.l7_protocol = "DNS";
                    if let Some(q) = d.qname() {
                        if flow.dns_queries.len() < 32 && !flow.dns_queries.iter().any(|x| x == q) {
                            flow.dns_queries.push(q.to_string());
                        }
                    }
                    if d.is_response {
                        for r in &d.answers {
                            let s = format!("{} {}", qtype_name(r.rtype), r.rdata.value_str());
                            if flow.dns_answers.len() < 16 && !flow.dns_answers.contains(&s) {
                                flow.dns_answers.push(s);
                            }
                        }
                    }
                }
                AppInfo::Http(h) => {
                    flow.l7_protocol = "HTTP";
                    match h {
                        socshark_dissectors::layer7::http::HttpMessage::Request(r) => {
                            flow.http_method = Some(r.method.clone());
                            flow.http_target = Some(r.target.clone());
                            flow.http_host = r.header("host").map(|s| s.to_string());
                        }
                        socshark_dissectors::layer7::http::HttpMessage::Response(r) => {
                            flow.http_status = Some(r.status);
                            flow.http_content_length = r.content_length();
                            flow.http_content_type =
                                r.header("content-type").map(|s| s.to_string());
                        }
                    }
                }
                AppInfo::Tls(t) => {
                    flow.l7_protocol = "TLS";
                    if let Some(ch) = &t.client_hello {
                        flow.tls_version =
                            Some(tls_version_str(ch.supported_version.unwrap_or(t.version)));
                        flow.tls_sni = ch.sni.clone();
                        flow.tls_alpn = ch.alpn.clone();
                        if flow.ja4_fingerprint.is_none() {
                            flow.ja4_fingerprint = Some(ch.ja4_like(t.version));
                        }
                    }
                }
            }
        }
    }

    /// Inserta un flujo pre-construido (para tests y futura importación de
    /// capturas parciales). No actualiza el índice de búsqueda inversa.
    pub fn insert_flow(&mut self, flow: EnrichedFlow) {
        self.flows.push(flow);
    }

    fn get_or_create(&mut self, key: &FlowKey, ts: u64) -> usize {
        if let Some(&i) = self.index.get(key) {
            return i;
        }
        let rev = key.reversed();
        if let Some(&i) = self.index.get(&rev) {
            return i;
        }
        let id = self.flows.len() as u64;
        self.flows.push(EnrichedFlow::new(id, key.clone(), ts));
        let i = self.flows.len() - 1;
        self.index.insert(key.clone(), i);
        // El reverso también apunta a la misma conversación (bidireccional).
        self.index.entry(rev).or_insert(i);
        i
    }
}

/// Convierte (3, minor) en etiqueta legible.
pub fn tls_version_str(v: (u8, u8)) -> String {
    match v {
        (3, 4) => "TLS 1.3".into(),
        (3, 3) => "TLS 1.2".into(),
        (3, 2) => "TLS 1.1".into(),
        (3, 1) => "TLS 1.0".into(),
        (3, 0) => "SSL 3.0".into(),
        (m, n) => format!("TLS {m}.{n}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_capture_core::{LinkType, PacketRecord};
    use socshark_dissectors::view::dissect;

    fn eth_ipv4_tcp(payload: &[u8], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&sport.to_be_bytes());
        tcp.extend_from_slice(&dport.to_be_bytes());
        tcp.extend_from_slice(&1u32.to_be_bytes());
        tcp.extend_from_slice(&2u32.to_be_bytes());
        tcp.push(0x50);
        tcp.push(flags);
        tcp.extend_from_slice(&64_000u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(payload);
        let total = 20 + tcp.len();
        let mut ip = vec![
            0x45u8,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            1,
            0x40,
            0,
            64,
            6,
            0,
            0,
        ];
        ip.extend_from_slice(&[192, 168, 1, 50]);
        ip.extend_from_slice(&[185, 22, 1, 9]);
        ip.extend_from_slice(&tcp);
        let mut f = vec![0u8; 14];
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        f.extend_from_slice(&ip);
        f
    }

    #[test]
    fn agrupa_direcciones_en_una_conversacion() {
        let mut t = SessionTable::new();
        let a = eth_ipv4_tcp(b"hola", 49_812, 4444, 0x18);
        let mut b = eth_ipv4_tcp(b"adios", 4444, 49_812, 0x18);
        // La respuesta sale de otra IP: reconstruye con src/dst intercambiados
        b[26..30].copy_from_slice(&[185, 22, 1, 9]); // src
        b[30..34].copy_from_slice(&[192, 168, 1, 50]); // dst
        for (i, buf) in [&a, &b].iter().enumerate() {
            let rec = PacketRecord {
                index: i as u64,
                ts_us: 1_000 + i as u64,
                orig_len: buf.len() as u32,
                data: buf,
            };
            let dp = dissect(&rec, LinkType::Ethernet);
            t.feed(&dp, i as u64 * 100);
        }
        assert_eq!(t.len(), 1);
        let f = &t.flows()[0];
        assert_eq!(f.packets_c2s, 1);
        assert_eq!(f.packets_s2c, 1);
        assert_eq!(f.bytes_c2s, 4);
        assert_eq!(f.bytes_s2c, 5);
        assert_eq!(f.packet_offsets, vec![0, 100]);
        assert_eq!(f.l7_protocol, "TCP");
    }

    #[test]
    fn estado_tcp_rst() {
        let mut t = SessionTable::new();
        let buf = eth_ipv4_tcp(b"", 49_812, 4444, 0x04); // RST
        let rec = PacketRecord {
            index: 0,
            ts_us: 1,
            orig_len: buf.len() as u32,
            data: &buf,
        };
        let dp = dissect(&rec, LinkType::Ethernet);
        t.feed(&dp, 0);
        assert_eq!(t.flows()[0].state, FlowState::Reset);
    }
}
