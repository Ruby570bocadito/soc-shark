//! Detectores de anomalías heurísticos.
//!
//! - **Port Mismatch**: protocolo identificado por el disector ≠ puerto
//!   estándar (HTTP en 4444, DNS por 8080...). T1071.
//! - **DNS Tunneling**: subdominios largos y de alta entropía, qtypes TXT/
//!   NULL repetidos. T1071.004.
//! - **Conexión directa por IP**: flujo hacia IP externa sin resolución DNS
//!   previa en el passive DNS. T1095.

use crate::DnsEvent;
use socshark_common::ipaddr::IpAddr;
use socshark_common::soc_types::{Severity, SocAlert};
use socshark_flow_aggregator::model::EnrichedFlow;
use socshark_flow_aggregator::passive_dns::PassiveDns;
use std::collections::HashMap;

/// Puertos estándar por protocolo L7 identificado.
const HTTP_PORTS: &[u16] = &[80, 8080, 8000, 8888, 8081];
const TLS_PORTS: &[u16] = &[443, 8443, 993, 995, 465, 636];
const DNS_PORTS: &[u16] = &[53];

/// Alerta de protocolo en puerto no estándar.
pub fn port_mismatch_alert(flow: &EnrichedFlow) -> Option<SocAlert> {
    let dport = flow.key.dport;
    let (proto, ports, sev) = match flow.l7_protocol {
        "HTTP" => ("HTTP", HTTP_PORTS, Severity::High),
        "TLS" => ("TLS", TLS_PORTS, Severity::Medium),
        "DNS" => ("DNS", DNS_PORTS, Severity::Medium),
        _ => return None,
    };
    if ports.contains(&dport) || flow.key.sport == dport && ports.contains(&flow.key.sport) {
        return None;
    }
    // Las respuestas del servidor usan el puerto servicio como origen: el
    // mismatch solo aplica a la dirección "cliente".
    let client_port = if ports.contains(&flow.key.sport) {
        flow.key.sport
    } else {
        dport
    };
    if ports.contains(&client_port) {
        return None;
    }
    Some(SocAlert {
        id: "PORT-MISMATCH",
        severity: sev,
        title: format!("{proto} en puerto no estándar {client_port}"),
        detail: format!(
            "El disector identificó {proto} pero el puerto {} no es estándar para ese protocolo. Patrón típico de C2 (ej. HTTP en 4444/8081).",
            client_port
        ),
        mitre: Some("T1071"),
        evidence: Some(format!(
            "{}:{} → {}:{} ({proto})",
            flow.key.src, flow.key.sport, flow.key.dst, flow.key.dport
        )),
    })
}

/// Alerta de conexión directa a IP sin DNS previo.
pub fn direct_ip_alert(flow: &EnrichedFlow) -> SocAlert {
    SocAlert {
        id: "DIRECT-IP",
        severity: Severity::Medium,
        title: format!("Conexión a {} sin consulta DNS previa", flow.key.dst),
        detail: "El destino es una IP externa y no hay ninguna respuesta DNS que la resuelva. \
                 Los procesos legítimos casi siempre resuelven dominios; conectarse a IPs \
                 crudas es típico de malware/C2 con dominios hardcodeados."
            .into(),
        mitre: Some("T1095"),
        evidence: Some(format!(
            "first_seen={}, l7={}",
            flow.first_seen_us, flow.l7_protocol
        )),
    }
}

/// Umbrales de la heurística de DNS tunneling (documentados en docs/06).
pub const TUNNEL_MIN_EVENTS: usize = 3;
pub const TUNNEL_MAX_LABEL: usize = 30;
pub const TUNNEL_MIN_ENTROPY: f64 = 3.8;
/// Qtypes asociados a tunneling.
const TUNNEL_QTYPES: &[u16] = &[16, 10, 255]; // TXT, NULL, ANY

/// Detecta tunneling por (src, dominio base): ≥ N queries con etiquetas
/// largas/entropía alta, o qtype TXT/NULL repetido hacia el mismo dominio.
pub fn dns_tunneling(events: &[DnsEvent]) -> HashMap<IpAddr, SocAlert> {
    #[derive(Default)]
    struct Acc {
        count: usize,
        suspicious: usize,
        sample: Option<String>,
        max_entropy: f64,
    }
    let mut groups: HashMap<(IpAddr, String), Acc> = HashMap::new();
    for e in events {
        let base = base_domain(&e.qname);
        let acc = groups.entry((e.src, base)).or_default();
        acc.count += 1;
        let suspicious = e.max_label_len >= TUNNEL_MAX_LABEL
            || e.entropy >= TUNNEL_MIN_ENTROPY
            || TUNNEL_QTYPES.contains(&e.qtype);
        if suspicious {
            acc.suspicious += 1;
            if acc.sample.is_none() {
                acc.sample = Some(e.qname.clone());
            }
            acc.max_entropy = acc.max_entropy.max(e.entropy);
        }
    }
    let mut out = HashMap::new();
    for ((src, base), acc) in groups {
        if acc.suspicious >= TUNNEL_MIN_EVENTS {
            out.insert(
                src,
                SocAlert {
                    id: "DNS-TUNNEL",
                    severity: Severity::High,
                    title: format!("Posible DNS tunneling hacia {base}"),
                    detail: format!(
                        "{} de {} consultas con etiquetas largas/entropía alta (máx {:.2} bits/byte) \
                         o qtypes TXT/NULL. Patrón de exfiltración o C2 por DNS.",
                        acc.suspicious, acc.count, acc.max_entropy
                    ),
                    mitre: Some("T1071.004"),
                    // evidence = dominio base: el enriquecimiento usa este
                    // campo para adjuntar la alerta SOLO a los flujos DNS
                    // cuyas queries caen bajo ese dominio.
                    evidence: Some(base),
                },
            );
        }
    }
    out
}

/// Dominio base naive: últimos dos labels (falla con co.uk, aceptable en fase 1).
fn base_domain(qname: &str) -> String {
    let labels: Vec<&str> = qname.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        qname.to_string()
    } else {
        format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1])
    }
}

/// Referencia al passive DNS para uso futuro (p. ej. alertas de dominio recién registrado).
pub fn _pd_ref(_pd: &PassiveDns) {}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_common::ipaddr::IpAddr;
    use socshark_flow_aggregator::model::{FlowKey, FlowState};

    fn flow(l7: &'static str, dport: u16) -> EnrichedFlow {
        let key = FlowKey {
            src: IpAddr::parse("192.168.1.50").unwrap(),
            sport: 49_812,
            dst: IpAddr::parse("185.22.1.9").unwrap(),
            dport,
            proto: 6,
        };
        let mut f = EnrichedFlow::new(1, key, 0);
        f.l7_protocol = l7;
        f.state = FlowState::Active;
        f
    }

    #[test]
    fn http_en_4444_alerta() {
        let a = port_mismatch_alert(&flow("HTTP", 4444)).unwrap();
        assert_eq!(a.id, "PORT-MISMATCH");
        assert_eq!(a.severity, Severity::High);
        assert_eq!(a.mitre, Some("T1071"));
        // HTTP en 80: normal
        assert!(port_mismatch_alert(&flow("HTTP", 80)).is_none());
        // TLS en 443: normal
        assert!(port_mismatch_alert(&flow("TLS", 443)).is_none());
        // TLS en 8443: estándar alternativo
        assert!(port_mismatch_alert(&flow("TLS", 8443)).is_none());
    }

    #[test]
    fn dns_fuera_de_53() {
        let a = port_mismatch_alert(&flow("DNS", 8080)).unwrap();
        assert_eq!(a.severity, Severity::Medium);
    }

    #[test]
    fn tunneling_requiere_varios_eventos() {
        let events: Vec<DnsEvent> = (0..4)
            .map(|i| {
                let payload = format!("a7x9k2p1m4q8z5n3b6v{i}c1d2f4g5h7j9.evil.ru");
                DnsEvent {
                    ts_us: i * 1_000_000,
                    src: IpAddr::parse("192.168.1.77").unwrap(),
                    qname: payload.clone(),
                    qtype: 16,
                    max_label_len: payload.split('.').next().unwrap().len(),
                    entropy: socshark_common::entropy::str_entropy(&payload),
                }
            })
            .collect();
        let out = dns_tunneling(&events);
        let a = out.get(&IpAddr::parse("192.168.1.77").unwrap()).unwrap();
        assert_eq!(a.id, "DNS-TUNNEL");
        assert_eq!(a.mitre, Some("T1071.004"));
        // Consultas normales: no alerta
        let normal: Vec<DnsEvent> = (0..10)
            .map(|i| DnsEvent {
                ts_us: i,
                src: IpAddr::parse("192.168.1.78").unwrap(),
                qname: format!("www{i}.google.com"),
                qtype: 1,
                max_label_len: 6,
                entropy: 2.5,
            })
            .collect();
        assert!(dns_tunneling(&normal).is_empty());
    }

    #[test]
    fn base_domain_naive() {
        assert_eq!(base_domain("a.b.example.com"), "example.com");
        assert_eq!(base_domain("example.com"), "example.com");
    }
}
