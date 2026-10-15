//! Puente entre el filter-dsl y los tipos del motor.
//!
//! Implementa `FactSource` para paquetes (`PacketFacts`) y flujos
//! (`FlowFacts`), mapeando los campos punteados del catálogo
//! (`filter_dsl::registry`) a valores reales. Vive en el daemon para no
//! invertir las dependencias de los crates del motor.

use socshark_dissectors::view::DissectedPacket;
use socshark_filter_dsl::{FactSource, Val};
use socshark_flow_aggregator::model::EnrichedFlow;

/// Hechos a nivel de **paquete**.
pub struct PacketFacts<'a>(pub &'a DissectedPacket<'a>);

impl FactSource for PacketFacts<'_> {
    fn fact(&self, field: &str) -> Option<Val> {
        let dp = self.0;
        match field {
            "frame.number" => Some(Val::Int(dp.index as i64)),
            "frame.len" => Some(Val::Int(dp.cap_len as i64)),
            "frame.ts" => Some(Val::Int(dp.ts_us as i64)),
            "ip.src" => dp.src_ip().map(ip_val),
            "ip.dst" => dp.dst_ip().map(ip_val),
            "ip.proto" => dp.five_tuple.as_ref().map(|t| Val::Int(t.proto as i64)),
            "ip.frag" => Some(Val::Bool(dp.ip_fragmented)),
            "tcp.port" => tcp_port(dp),
            "tcp.srcport" => dp.src_port().map(|p| Val::Int(p as i64)),
            "tcp.dstport" => dp.dst_port().map(|p| Val::Int(p as i64)),
            "tcp.flags.syn" => flag(dp, 0x02),
            "tcp.flags.ack" => flag(dp, 0x10),
            "tcp.flags.fin" => flag(dp, 0x01),
            "tcp.flags.rst" => flag(dp, 0x04),
            "tcp.flags.psh" => flag(dp, 0x08),
            "udp.port" => udp_port(dp),
            "arp.op" => match &dp.net {
                Some(socshark_dissectors::view::NetInfo::Arp(a)) => Some(Val::Int(a.oper as i64)),
                _ => None,
            },
            "icmp.type" => match &dp.trans {
                Some(socshark_dissectors::view::TransInfo::Icmp(i)) => {
                    Some(Val::Int(i.kind as i64))
                }
                _ => None,
            },
            "dns.qname" => dp
                .app
                .as_ref()
                .and_then(|a| a.as_dns())
                .and_then(|d| d.qname())
                .map(|q| Val::Str(q.to_string())),
            "dns.qtype" => dp
                .app
                .as_ref()
                .and_then(|a| a.as_dns())
                .and_then(|d| d.questions.first())
                .map(|q| Val::Int(q.qtype as i64)),
            "dns.is_response" => dp
                .app
                .as_ref()
                .and_then(|a| a.as_dns())
                .map(|d| Val::Bool(d.is_response)),
            "http.method" => dp
                .app
                .as_ref()
                .and_then(|a| a.as_http_request())
                .map(|r| Val::Str(r.method.clone())),
            "http.target" => dp
                .app
                .as_ref()
                .and_then(|a| a.as_http_request())
                .map(|r| Val::Str(r.target.clone())),
            "http.host" => dp
                .app
                .as_ref()
                .and_then(|a| a.as_http_request())
                .and_then(|r| r.header("host"))
                .map(|h| Val::Str(h.to_string())),
            "http.user_agent" => dp
                .app
                .as_ref()
                .and_then(|a| a.as_http_request())
                .and_then(|r| r.header("user-agent"))
                .map(|h| Val::Str(h.to_string())),
            "http.status" => dp
                .app
                .as_ref()
                .and_then(|a| a.as_http_response())
                .map(|r| Val::Int(r.status as i64)),
            "tls.sni" => dp
                .app
                .as_ref()
                .and_then(|a| a.as_tls())
                .and_then(|t| t.client_hello.as_ref())
                .and_then(|ch| ch.sni.clone())
                .map(Val::Str),
            "tls.alpn" => dp
                .app
                .as_ref()
                .and_then(|a| a.as_tls())
                .and_then(|t| t.client_hello.as_ref())
                .and_then(|ch| ch.alpn.clone())
                .map(Val::Str),
            "tls.ja4" => dp.app.as_ref().and_then(|a| a.as_tls()).and_then(|t| {
                t.client_hello
                    .as_ref()
                    .map(|ch| Val::Str(ch.ja4_like(t.version)))
            }),
            "proto" => Some(Val::Str(dp.l7_proto.to_string())),
            // Campos futuros: presentes en el catálogo, vacíos en fase 1.
            "proc.name" | "proc.pid" | "geo.dst" => None,
            _ => None,
        }
    }
}

fn ip_val(ip: socshark_common::ipaddr::IpAddr) -> Val {
    Val::Ip(ip)
}

fn tcp_port(dp: &DissectedPacket) -> Option<Val> {
    dp.five_tuple
        .as_ref()
        .filter(|t| t.proto == 6)
        .map(|t| Val::Int(t.src_port.max(t.dst_port) as i64))
}

fn udp_port(dp: &DissectedPacket) -> Option<Val> {
    dp.five_tuple
        .as_ref()
        .filter(|t| t.proto == 17)
        .map(|t| Val::Int(t.src_port.max(t.dst_port) as i64))
}

fn flag(dp: &DissectedPacket, mask: u8) -> Option<Val> {
    dp.tcp_flags().map(|f| Val::Bool(f & mask != 0))
}

/// Hechos a nivel de **flujo** (la unidad Flow-First).
pub struct FlowFacts<'a>(pub &'a EnrichedFlow);

impl FactSource for FlowFacts<'_> {
    fn fact(&self, field: &str) -> Option<Val> {
        let f = self.0;
        match field {
            "ip.src" => Some(Val::Ip(f.key.src)),
            "ip.dst" => Some(Val::Ip(f.key.dst)),
            "ip.proto" => Some(Val::Int(f.key.proto as i64)),
            "tcp.port" if f.key.proto == 6 => Some(Val::Int(f.key.dport as i64)),
            "tcp.srcport" if f.key.proto == 6 => Some(Val::Int(f.key.sport as i64)),
            "tcp.dstport" if f.key.proto == 6 => Some(Val::Int(f.key.dport as i64)),
            "udp.port" if f.key.proto == 17 => Some(Val::Int(f.key.dport as i64)),
            "dns.qname" => f.dns_queries.first().map(|q| Val::Str(q.clone())),
            "http.method" => f.http_method.clone().map(Val::Str),
            "http.target" => f.http_target.clone().map(Val::Str),
            "http.host" => f.http_host.clone().map(Val::Str),
            "http.status" => f.http_status.map(|s| Val::Int(s as i64)),
            "http.user_agent" => None, // fase 4 (stream reassembly)
            "tls.sni" => f.tls_sni.clone().map(Val::Str),
            "tls.alpn" => f.tls_alpn.clone().map(Val::Str),
            "tls.ja4" => f.ja4_fingerprint.clone().map(Val::Str),
            "proto" | "flow.proto" => Some(Val::Str(f.l7_protocol.to_string())),
            "proc.name" => f.process_name.clone().map(Val::Str),
            "proc.pid" => f.process_pid.map(|p| Val::Int(p as i64)),
            "geo.dst" => f.dst_geo_asn.clone().map(Val::Str),
            "flow.risk" => Some(Val::Int(f.risk_score as i64)),
            "flow.noise" => Some(Val::Bool(f.is_background_noise)),
            "flow.domain" => f.resolved_domain.clone().map(Val::Str),
            "flow.duration_ms" => Some(Val::Int(f.duration_ms as i64)),
            "flow.packets" => Some(Val::Int(f.packet_count as i64)),
            "flow.bytes" => Some(Val::Int((f.bytes_c2s + f.bytes_s2c) as i64)),
            "flow.state" => Some(Val::Str(f.state.as_str().to_string())),
            "flow.has_alert" => Some(Val::Bool(!f.alerts.is_empty())),
            "alert.count" => Some(Val::Int(f.alerts.len() as i64)),
            "alert.max_severity" => f
                .alerts
                .iter()
                .map(|a| a.severity)
                .max()
                .map(|s| Val::Str(s.as_str().to_string())),
            "artifact.magic" => f
                .extracted_files
                .first()
                .map(|a| Val::Str(a.magic.to_string())),
            "artifact.masquerade" => {
                Some(Val::Bool(f.extracted_files.iter().any(|a| a.masquerade)))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_capture_core::{LinkType, PacketRecord};
    use socshark_dissectors::view::dissect;

    #[test]
    fn hechos_de_paquete_http() {
        let payload =
            b"POST /x HTTP/1.1\r\nHost: evil\r\nUser-Agent: curl/8\r\nContent-Length: 0\r\n\r\n";
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&50_000u16.to_be_bytes());
        tcp.extend_from_slice(&4444u16.to_be_bytes());
        tcp.extend_from_slice(&1u32.to_be_bytes());
        tcp.extend_from_slice(&1u32.to_be_bytes());
        tcp.push(0x50);
        tcp.push(0x18);
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
        ip.extend_from_slice(&[10, 0, 0, 5]);
        ip.extend_from_slice(&[185, 22, 1, 9]);
        ip.extend_from_slice(&tcp);
        let mut f = vec![0u8; 14];
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        f.extend_from_slice(&ip);
        let rec = PacketRecord {
            index: 3,
            ts_us: 99,
            orig_len: f.len() as u32,
            data: &f,
        };
        let dp = dissect(&rec, LinkType::Ethernet);
        let facts = PacketFacts(&dp);
        assert!(socshark_filter_dsl::matches(&facts, "http.method == POST").unwrap());
        assert!(socshark_filter_dsl::matches(&facts, "tcp.dstport == 4444").unwrap());
        assert!(socshark_filter_dsl::matches(&facts, "proto == HTTP").unwrap());
        assert!(socshark_filter_dsl::matches(&facts, "http.user_agent contains curl").unwrap());
        assert!(!socshark_filter_dsl::matches(&facts, "proc.name == curl").unwrap());
        // fase 3
    }
}
