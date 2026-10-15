//! Traducción semántica: cabeceras técnicas → frases legibles.
//!
//! En vez de `Standard query 0x4a1b A update.evil-cdn.ru` el analista ve
//! `Consulta DNS update.evil-cdn.ru → 185.220.101.4`. Las plantillas se
//! aplican sobre los digests flat de `EnrichedFlow` durante el
//! enriquecimiento final (`soc-engine`).

use crate::model::EnrichedFlow;

/// Genera el resumen humano del flujo a partir de sus digests acumulados.
pub fn summarize(flow: &EnrichedFlow) -> String {
    match flow.l7_protocol {
        "DNS" => summarize_dns(flow),
        "HTTP" => summarize_http(flow),
        "TLS" => summarize_tls(flow),
        "ICMP" => summarize_icmp(flow),
        "TCP" => summarize_tcp(flow),
        "UDP" => summarize_udp(flow),
        other => format!("Tráfico {other}"),
    }
}

fn summarize_dns(flow: &EnrichedFlow) -> String {
    let qname = flow
        .dns_queries
        .first()
        .cloned()
        .unwrap_or_else(|| "(sin nombre)".into());
    if flow.dns_answers.is_empty() {
        format!("Consulta DNS {qname}")
    } else {
        let answers: Vec<String> = flow
            .dns_answers
            .iter()
            .take(3)
            .map(|a| {
                a.split_once(' ')
                    .map(|(_, v)| v.to_string())
                    .unwrap_or_else(|| a.clone())
            })
            .collect();
        format!("Consulta DNS {qname} → {}", answers.join(", "))
    }
}

fn summarize_http(flow: &EnrichedFlow) -> String {
    if let Some(method) = &flow.http_method {
        let target = flow.http_target.as_deref().unwrap_or("/");
        let host = flow
            .http_host
            .as_deref()
            .map(|h| format!(" (Host: {h})"))
            .unwrap_or_default();
        format!("{method} {target}{host}")
    } else if let Some(status) = flow.http_status {
        let len = flow
            .http_content_length
            .map(|l| format!(" ({l} bytes)"))
            .unwrap_or_default();
        format!("HTTP {status}{len}")
    } else {
        "Tráfico HTTP".into()
    }
}

fn summarize_tls(flow: &EnrichedFlow) -> String {
    let ver = flow.tls_version.as_deref().unwrap_or("TLS");
    match &flow.tls_sni {
        Some(sni) => format!("Handshake {ver} (SNI: {sni})"),
        None => format!("Handshake {ver} (sin SNI)"),
    }
}

fn summarize_icmp(flow: &EnrichedFlow) -> String {
    match flow.icmp_type {
        Some(8) => "Ping (echo request)".into(),
        Some(0) => "Ping (echo reply)".into(),
        Some(3) => "ICMP destino inalcanzable".into(),
        Some(11) => "ICMP TTL excedido".into(),
        _ => "Tráfico ICMP".into(),
    }
}

fn summarize_tcp(flow: &EnrichedFlow) -> String {
    if flow.packets_c2s + flow.packets_s2c <= 3 && flow.human_summary.is_empty() {
        // Handshake sin datos.
        return "Handshake/conversación TCP corta".into();
    }
    format!(
        "Conversación TCP ({} paq., {} bytes)",
        flow.packet_count,
        flow.bytes_c2s + flow.bytes_s2c
    )
}

fn summarize_udp(flow: &EnrichedFlow) -> String {
    format!(
        "Tráfico UDP {}:{} → {}:{}",
        flow.key.src, flow.key.sport, flow.key.dst, flow.key.dport
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DomainSource, FlowKey, FlowState};
    use socshark_common::ipaddr::IpAddr;

    fn sample_flow() -> EnrichedFlow {
        let key = FlowKey {
            src: IpAddr::parse("192.168.1.50").unwrap(),
            sport: 49_812,
            dst: IpAddr::parse("185.22.1.9").unwrap(),
            dport: 4444,
            proto: 6,
        };
        EnrichedFlow::new(1, key, 1_000_000)
    }

    #[test]
    fn resumenes_por_protocolo() {
        let mut f = sample_flow();
        f.l7_protocol = "DNS";
        f.dns_queries = vec!["update.evil-cdn.ru".into()];
        f.dns_answers = vec!["A 185.220.101.4".into()];
        assert_eq!(
            summarize(&f),
            "Consulta DNS update.evil-cdn.ru → 185.220.101.4"
        );

        f.l7_protocol = "HTTP";
        f.http_method = Some("POST".into());
        f.http_target = Some("/gate.php".into());
        f.http_host = Some("c2.evil.ru".into());
        assert_eq!(summarize(&f), "POST /gate.php (Host: c2.evil.ru)");

        f.http_method = None;
        f.http_status = Some(200);
        f.http_content_length = Some(1024);
        assert_eq!(summarize(&f), "HTTP 200 (1024 bytes)");

        f.l7_protocol = "TLS";
        f.tls_version = Some("TLS 1.3".into());
        f.tls_sni = Some("api.example.com".into());
        assert_eq!(summarize(&f), "Handshake TLS 1.3 (SNI: api.example.com)");

        f.l7_protocol = "ICMP";
        f.icmp_type = Some(8);
        assert_eq!(summarize(&f), "Ping (echo request)");
    }

    #[test]
    fn dominio_y_fuente_en_json() {
        let mut f = sample_flow();
        f.resolved_domain = Some("evil.example".into());
        f.domain_source = DomainSource::PassiveDns;
        let j = f.to_json().to_string();
        assert!(j.contains("evil.example"));
        assert!(j.contains("PassiveDns") || j.contains("passive"));
    }
}
