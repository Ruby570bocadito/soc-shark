//! Exportación a SIEM: formato ECS (Elastic Common Schema) y regla Suricata.
//!
//! En la GUI/TUI final es el atajo `E` sobre el flujo seleccionado; en la
//! fase 1 el daemon lo expone con `--export-ecs`. Compatible con la ingesta
//! de Wazuh / Elasticsearch / TheHive (JSONL).

use socshark_common::json::Json;
use socshark_common::timefmt;
use socshark_flow_aggregator::model::EnrichedFlow;

/// Convierte un flujo enriquecido a un objeto ECS + extensiones soc-shark.
pub fn flow_to_ecs(flow: &EnrichedFlow) -> Json {
    let transport = match flow.key.proto {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        _ => "unknown",
    };
    let severity = if flow.risk_score >= 60 {
        5
    } else if flow.risk_score >= 30 {
        4
    } else if flow.risk_score >= 15 {
        3
    } else if flow.risk_score > 0 {
        2
    } else {
        1
    };
    let mitre: Vec<Json> = flow
        .alerts
        .iter()
        .filter_map(|a| a.mitre.map(|m| Json::s(m)))
        .collect();
    let rule_names: Vec<Json> = flow
        .alerts
        .iter()
        .map(|a| Json::s(format!("[{}] {}", a.severity.as_str(), a.title)))
        .collect();
    let hashes: Vec<Json> = flow
        .extracted_files
        .iter()
        .map(|a| Json::s(a.sha256.clone()))
        .collect();

    Json::obj(vec![
        (
            "@timestamp",
            Json::s(timefmt::format_ts_us(flow.first_seen_us)),
        ),
        (
            "event",
            Json::obj(vec![
                (
                    "kind",
                    Json::s(if flow.alerts.is_empty() {
                        "flow"
                    } else {
                        "alert"
                    }),
                ),
                ("category", Json::Arr(vec![Json::s("network")])),
                ("type", Json::s("connection")),
                ("severity", Json::Int(severity)),
                ("duration", Json::Int((flow.duration_ms * 1_000_000) as i64)), // ns
                ("dataset", Json::s("socshark.flows")),
                ("module", Json::s("soc-shark")),
            ]),
        ),
        (
            "source",
            Json::obj(vec![
                ("ip", Json::s(flow.key.src.to_string())),
                ("port", Json::Int(flow.key.sport as i64)),
                (
                    "process",
                    match &flow.process_name {
                        Some(p) => Json::s(p.clone()),
                        None => Json::Null,
                    },
                ),
            ]),
        ),
        (
            "destination",
            Json::obj(vec![
                ("ip", Json::s(flow.key.dst.to_string())),
                ("port", Json::Int(flow.key.dport as i64)),
                (
                    "domain",
                    match &flow.resolved_domain {
                        Some(d) => Json::s(d.clone()),
                        None => Json::Null,
                    },
                ),
            ]),
        ),
        (
            "network",
            Json::obj(vec![
                ("transport", Json::s(transport)),
                ("bytes", Json::Int((flow.bytes_c2s + flow.bytes_s2c) as i64)),
                ("packets", Json::Int(flow.packet_count as i64)),
                ("protocol", Json::s(flow.l7_protocol)),
            ]),
        ),
        (
            "rule",
            Json::obj(vec![
                ("name", Json::Arr(rule_names)),
                ("category", Json::Arr(mitre)),
            ]),
        ),
        ("message", Json::s(flow.human_summary.clone())),
        (
            "file",
            Json::obj(vec![(
                "hash",
                Json::obj(vec![("sha256", Json::Arr(hashes))]),
            )]),
        ),
        // Extensiones propias del producto.
        (
            "socshark",
            Json::obj(vec![
                ("flow_id", Json::Int(flow.flow_id as i64)),
                ("risk_score", Json::Int(flow.risk_score as i64)),
                ("is_background_noise", Json::Bool(flow.is_background_noise)),
                ("domain_source", Json::s(flow.domain_source.as_str())),
                (
                    "ja4_fingerprint",
                    match &flow.ja4_fingerprint {
                        Some(j) => Json::s(j.clone()),
                        None => Json::Null,
                    },
                ),
                (
                    "state",
                    Json::s(match flow.state {
                        socshark_flow_aggregator::model::FlowState::Active => "active",
                        socshark_flow_aggregator::model::FlowState::Closed => "closed",
                        socshark_flow_aggregator::model::FlowState::Reset => "reset",
                        socshark_flow_aggregator::model::FlowState::Timeout => "timeout",
                    }),
                ),
                (
                    "alerts",
                    Json::Arr(flow.alerts.iter().map(|a| a.to_json()).collect()),
                ),
                (
                    "extracted_files",
                    Json::Arr(flow.extracted_files.iter().map(|a| a.to_json()).collect()),
                ),
            ]),
        ),
    ])
}

/// Genera una regla Suricata de bloqueo a partir del flujo sospechoso.
pub fn suricata_rule(flow: &EnrichedFlow) -> String {
    let proto = match flow.key.proto {
        6 => "tcp",
        17 => "udp",
        _ => "ip",
    };
    let reason = flow
        .alerts
        .first()
        .map(|a| a.title.clone())
        .unwrap_or_else(|| flow.human_summary.clone());
    format!(
        "alert {} {}:{} -> {}:{} (msg:\"soc-shark: {}\"; flow:established; \
         sid:{}; rev:1;)",
        proto,
        flow.key.src,
        flow.key.sport,
        flow.key.dst,
        flow.key.dport,
        reason.replace('"', "'"),
        9_000_000 + (flow.flow_id % 100_000) as u32
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_common::ipaddr::IpAddr;
    use socshark_common::soc_types::{Severity, SocAlert};
    use socshark_flow_aggregator::model::{DomainSource, FlowKey};

    fn flow_with_alert() -> EnrichedFlow {
        let key = FlowKey {
            src: IpAddr::parse("192.168.1.50").unwrap(),
            sport: 49_812,
            dst: IpAddr::parse("185.22.1.9").unwrap(),
            dport: 4444,
            proto: 6,
        };
        let mut f = EnrichedFlow::new(7, key, 1_735_689_600_123_456);
        f.l7_protocol = "HTTP";
        f.human_summary = "POST /gate.php".into();
        f.risk_score = 75;
        f.resolved_domain = Some("c2.evil.ru".into());
        f.domain_source = DomainSource::PassiveDns;
        f.alerts.push(SocAlert {
            id: "PORT-MISMATCH",
            severity: Severity::High,
            title: "HTTP en puerto no estándar 4444".into(),
            detail: "detalle".into(),
            mitre: Some("T1071"),
            evidence: None,
        });
        f
    }

    #[test]
    fn ecs_campos_clave() {
        let j = flow_to_ecs(&flow_with_alert());
        let s = j.to_string();
        for needle in [
            "\"source\":{\"ip\":\"192.168.1.50\"",
            "\"destination\":{\"ip\":\"185.22.1.9\",\"port\":4444",
            "\"domain\":\"c2.evil.ru\"",
            "\"transport\":\"tcp\"",
            "\"kind\":\"alert\"",
            "T1071",
            "\"risk_score\":75",
        ] {
            assert!(s.contains(needle), "falta {needle} en {s}");
        }
    }

    #[test]
    fn suricata_sintaxis() {
        let r = suricata_rule(&flow_with_alert());
        assert!(r.starts_with("alert tcp 192.168.1.50:49812 -> 185.22.1.9:4444"));
        assert!(r.contains("sid:9000007"));
    }
}
