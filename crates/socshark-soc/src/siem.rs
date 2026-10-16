//! Export a SIEM: mapeo ECS y salida Wazuh, sin dependencias nuevas.
//!
//! [`to_ecs`] convierte un [`EnrichedFlow`] a un objeto JSON con el Elastic
//! Common Schema (campos estándar donde existen, `socshark.*` como espacio
//! reservado para lo propio). [`to_wazuh`] produce el evento plano que los
//! decoders JSON de Wazuh consumen directamente (`srcip`/`dstip` reconocidos,
//! `data.*` anidado y `rule` + `mitre` para correlación). El contrato completo
//! campo a campo está en `docs/siem-export.md`.
//!
//! ISO-8601 propio (ADR-012): `@timestamp` requiere fecha civil desde
//! microsegundos Unix; el algoritmo de Howard Hinnant (días → y-m-d) son
//! 20 líneas frente a una dependencia de `chrono`/`time` que el proyecto no
//! necesita para nada más.

use serde_json::{json, Map, Value};

use socshark_core::{Alert, EnrichedFlow, L7Protocol, Severity, Transport};

// ------------------------------------------------------------- ISO-8601

/// Convierte microsegundos Unix (`0 = 1970-01-01T00:00:00Z`) a ISO-8601
/// UTC con precisión de microsegundos: `2023-11-14T22:13:20.000000Z`.
///
/// Algoritmo civil de Howard Hinnant (chrono_from_days): válido para el
/// rango completo de `u64` microsegundos (~año 586524).
pub fn micros_to_iso8601(micros: u64) -> String {
    let secs = (micros / 1_000_000) as i64;
    let rem = micros % 1_000_000;
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{rem:06}Z")
}

/// Días desde la época → fecha civil (Hinnant, "chrono_from_days").
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Severidad → nivel de regla Wazuh (escala 0-15 del manager).
/// 2 aviso, 4 bajo, 6 medio, 10 alto, 13 crítico.
pub fn severity_to_wazuh_level(s: Severity) -> u8 {
    match s {
        Severity::Info => 2,
        Severity::Low => 4,
        Severity::Medium => 6,
        Severity::High => 10,
        Severity::Critical => 13,
    }
}

fn l7_str(l7: L7Protocol) -> &'static str {
    match l7 {
        L7Protocol::Dns => "dns",
        L7Protocol::Dhcp => "dhcp",
        L7Protocol::Ntp => "ntp",
        L7Protocol::Http => "http",
        L7Protocol::Tls => "tls",
        L7Protocol::Ssh => "ssh",
        L7Protocol::Unknown => "unknown",
    }
}

fn transport_str(t: Transport) -> &'static str {
    match t {
        Transport::Tcp => "tcp",
        Transport::Udp => "udp",
        Transport::Icmp => "icmp",
        Transport::Other(_) => "other",
    }
}

/// IDs MITRE de todas las alertas del flujo, sin duplicados.
fn mitre_ids(alerts: &[Alert]) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for a in alerts {
        if let Some(m) = &a.mitre {
            if !ids.contains(m) {
                ids.push(m.clone());
            }
        }
    }
    ids
}

// ----------------------------------------------------------------- ECS

/// Mapea un flujo a un evento ECS (JSON). Campos estándar donde existen;
/// `socshark.*` para lo propio (riesgo, ruido, archivos, etiquetas intel).
pub fn to_ecs(flow: &EnrichedFlow) -> Value {
    let mut o = Map::new();
    o.insert(
        "@timestamp".into(),
        json!(micros_to_iso8601(flow.first_seen_micros)),
    );
    o.insert("event.module".into(), json!("socshark"));
    o.insert("event.dataset".into(), json!("network.flows"));
    o.insert("event.kind".into(), json!("event"));
    o.insert("event.category".into(), json!(["network"]));
    o.insert("event.type".into(), json!(["connection"]));
    o.insert("event.duration".into(), json!(flow.duration_micros * 1000)); // ns (ECS)
    o.insert("event.severity".into(), json!(flow.risk_score));

    o.insert("source.ip".into(), json!(flow.src_ip.to_string()));
    o.insert("source.port".into(), json!(flow.src_port));
    o.insert("destination.ip".into(), json!(flow.dst_ip.to_string()));
    o.insert("destination.port".into(), json!(flow.dst_port));
    o.insert(
        "network.transport".into(),
        json!(transport_str(flow.transport)),
    );
    o.insert("network.protocol".into(), json!(l7_str(flow.l7_protocol)));
    o.insert("network.bytes".into(), json!(flow.bytes + flow.bytes_rev));
    o.insert(
        "network.packets".into(),
        json!(flow.packets + flow.packets_rev),
    );
    o.insert("network.direction".into(), json!("outbound"));
    o.insert("flow.id".into(), json!(flow.flow_id.0));
    o.insert("network.community_id".into(), json!(flow.flow_id.0)); // sin hash de tuple: el id canónico hace de correlador

    if let Some(mac) = &flow.src_mac {
        o.insert("source.mac".into(), json!(mac));
    }
    if let Some(mac) = &flow.dst_mac {
        o.insert("destination.mac".into(), json!(mac));
    }
    if let Some(domain) = &flow.resolved_domain {
        o.insert("destination.domain".into(), json!(domain));
    }

    // Proceso (eBPF, Fase 3+; hoy normalmente ausente).
    if let Some(p) = &flow.process_name {
        o.insert("process.name".into(), json!(p));
    }
    if let Some(pid) = flow.pid {
        o.insert("process.pid".into(), json!(pid));
    }
    if let Some(u) = &flow.user {
        o.insert("user.name".into(), json!(u));
    }

    // DNS (ECS dns.*).
    if let Some(dns) = &flow.dns {
        if let Some(q) = dns.queries.first() {
            o.insert("dns.question.name".into(), json!(q.name));
            o.insert(
                "dns.question.type".into(),
                json!(socshark_core::dns_type_str(q.qtype)),
            );
        }
        if let Some(rc) = dns.rcode {
            o.insert(
                "dns.response_code".into(),
                json!(socshark_core::dns_rcode_str(rc)),
            );
        }
        if !dns.answers.is_empty() {
            let answers: Vec<Value> = dns
                .answers
                .iter()
                .map(|a| {
                    let mut obj = Map::new();
                    obj.insert("name".into(), json!(a.name));
                    obj.insert("type".into(), json!(socshark_core::dns_type_str(a.rtype)));
                    obj.insert("ttl".into(), json!(a.ttl));
                    if let Some(ip) = a.address {
                        obj.insert("data".into(), json!(ip.to_string()));
                    } else if let Some(t) = &a.target {
                        obj.insert("data".into(), json!(t));
                    }
                    Value::Object(obj)
                })
                .collect();
            o.insert("dns.answers".into(), Value::Array(answers));
        }
    }

    // TLS: SNI es campo estándar; JA4 va como extensión práctica.
    if let Some(sni) = &flow.tls_sni {
        o.insert("tls.client.server_name".into(), json!(sni));
    }
    if let Some(ja4) = &flow.ja4_fingerprint {
        o.insert("tls.ja4".into(), json!(ja4));
    }

    // Alertas y threat (MITRE ATT&CK).
    if !flow.alerts.is_empty() {
        let names: Vec<&str> = flow.alerts.iter().map(|a| a.name.as_str()).collect();
        o.insert("rule.name".into(), json!(names));
        o.insert("message".into(), json!(flow.alerts[0].detail));
        let techniques: Vec<String> = mitre_ids(&flow.alerts);
        if !techniques.is_empty() {
            o.insert("threat.technique.id".into(), json!(techniques));
        }
    }

    // Espacio propio socshark.* (objeto anidado, convención ECS para
    // campos personalizados: la referencia "socshark.risk_score" corresponde
    // al JSON anidado {"socshark": {"risk_score": ...}}).
    let mut socshark = Map::new();
    socshark.insert("risk_score".into(), json!(flow.risk_score));
    socshark.insert("background_noise".into(), json!(flow.is_background_noise));
    socshark.insert("human_summary".into(), json!(flow.human_summary));
    socshark.insert("flow_state".into(), json!(flow.state.as_str()));
    if !flow.threat_intel.is_empty() {
        socshark.insert("threat_intel".into(), json!(flow.threat_intel));
    }
    if !flow.extracted_files.is_empty() {
        let files: Vec<Value> = flow
            .extracted_files
            .iter()
            .map(|f| {
                json!({
                    "name": f.name,
                    "size": f.size,
                    "sha256": f.sha256,
                    "magic": f.magic,
                    "masquerading_suspect": f.masquerading_suspect,
                })
            })
            .collect();
        socshark.insert("extracted_files".into(), Value::Array(files));
    }
    o.insert("socshark".into(), Value::Object(socshark));

    Value::Object(o)
}

// --------------------------------------------------------------- Wazuh

/// Mapea un flujo a un evento Wazuh (JSON plano, una línea por flujo).
///
/// Contrato con el decoder JSON del manager:
/// - `srcip`/`srcport`/`dstip`/`dstport`/`protocol`: los reconoce de serie y
///   alimenta sus dashboards de red.
/// - `data`: objeto arbitrario que aterriza como `data.<clave>` en las reglas.
/// - `rule.level` + `rule.description`: si existen, el evento entra como
///   alerta con esa severidad (mapeo de [`severity_to_wazuh_level`]).
/// - `rule.mitre.id`: enlaza con el módulo ATT&CK del manager.
/// - Sin alertas el evento conserva `data` pero sin `rule`: queda como
///   evento archivado, no como alerta.
pub fn to_wazuh(flow: &EnrichedFlow) -> Value {
    let mut data = Map::new();
    data.insert(
        "socshark".into(),
        json!({
            "flow_id": flow.flow_id.0,
            "risk_score": flow.risk_score,
            "background_noise": flow.is_background_noise,
            "l7": l7_str(flow.l7_protocol),
            "bytes": flow.bytes + flow.bytes_rev,
            "packets": flow.packets + flow.packets_rev,
            "duration_secs": flow.duration_micros as f64 / 1_000_000.0,
            "human_summary": flow.human_summary,
        }),
    );
    if let Some(d) = &flow.resolved_domain {
        data.insert("domain".into(), json!(d));
    }
    if let Some(sni) = &flow.tls_sni {
        data.insert("tls_sni".into(), json!(sni));
    }
    if let Some(ja4) = &flow.ja4_fingerprint {
        data.insert("tls_ja4".into(), json!(ja4));
    }
    if !flow.threat_intel.is_empty() {
        data.insert("threat_intel".into(), json!(flow.threat_intel));
    }
    if !flow.extracted_files.is_empty() {
        let files: Vec<Value> = flow
            .extracted_files
            .iter()
            .map(|f| {
                json!({
                    "name": f.name,
                    "size": f.size,
                    "sha256": f.sha256,
                    "magic": f.magic,
                    "masquerading_suspect": f.masquerading_suspect,
                })
            })
            .collect();
        data.insert("extracted_files".into(), Value::Array(files));
    }
    if let Some(dns) = &flow.dns {
        if let Some(q) = dns.queries.first() {
            data.insert("dns_qname".into(), json!(q.name));
        }
    }

    let mut o = Map::new();
    o.insert("program_name".into(), json!("socshark"));
    o.insert(
        "timestamp".into(),
        json!(micros_to_iso8601(flow.first_seen_micros)),
    );
    o.insert("srcip".into(), json!(flow.src_ip.to_string()));
    o.insert("srcport".into(), json!(flow.src_port));
    o.insert("dstip".into(), json!(flow.dst_ip.to_string()));
    o.insert("dstport".into(), json!(flow.dst_port));
    o.insert("protocol".into(), json!(transport_str(flow.transport)));
    o.insert("data".into(), Value::Object(data));

    if let Some(max) = flow.alerts.iter().max_by_key(|a| a.severity) {
        let mut rule = Map::new();
        rule.insert("level".into(), json!(severity_to_wazuh_level(max.severity)));
        rule.insert(
            "description".into(),
            json!(flow
                .alerts
                .iter()
                .map(|a| a.name.as_str())
                .collect::<Vec<_>>()
                .join("; ")),
        );
        let techniques = mitre_ids(&flow.alerts);
        if !techniques.is_empty() {
            rule.insert("mitre".into(), json!({ "id": techniques }));
        }
        o.insert("rule".into(), Value::Object(rule));
    }

    Value::Object(o)
}

// --------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_core::{FlowId, FlowState, TcpFlagCounts};

    fn flujo_demo() -> EnrichedFlow {
        EnrichedFlow {
            flow_id: FlowId("tcp/192.168.1.10:52000-93.184.216.34:443".into()),
            state: FlowState::Closed,
            transport: Transport::Tcp,
            ip_version: 4,
            l7_protocol: L7Protocol::Tls,
            src_ip: "192.168.1.10".parse().unwrap(),
            src_port: 52000,
            dst_ip: "93.184.216.34".parse().unwrap(),
            dst_port: 443,
            src_mac: None,
            dst_mac: None,
            first_seen_micros: 1_700_000_000_000_000,
            last_seen_micros: 1_700_000_000_100_000,
            duration_micros: 100_000,
            packets: 7,
            bytes: 1_500,
            packets_rev: 5,
            bytes_rev: 2_800,
            tcp_flags: TcpFlagCounts::default(),
            process_name: None,
            pid: None,
            user: None,
            resolved_domain: Some("ejemplo.com".into()),
            dns: None,
            dst_geo_asn: None,
            ja4_fingerprint: Some("t13d0208h2_777cda164f4b_af51ac0c444f".into()),
            tls_sni: Some("store.ejemplo-corporativo.com".into()),
            interval_stats: None,
            threat_intel: vec![],
            is_background_noise: false,
            human_summary: "sesión TLS a ejemplo.com".into(),
            risk_score: 0,
            alerts: vec![],
            extracted_files: vec![],
        }
    }

    #[test]
    fn iso8601_epoca_y_fecha_conocida() {
        assert_eq!(micros_to_iso8601(0), "1970-01-01T00:00:00.000000Z");
        // t0 del escenario demo: 1_700_000_000_000_000 µs = 2023-11-14T22:13:20Z.
        assert_eq!(
            micros_to_iso8601(1_700_000_000_000_000),
            "2023-11-14T22:13:20.000000Z"
        );
        // Bisiesto y fin de mes: 2024-02-29T23:59:59.999999Z (1 s antes de
        // 2024-03-01T00:00:00Z, día 19783 de la época).
        assert_eq!(
            micros_to_iso8601(1_709_251_199_999_999),
            "2024-02-29T23:59:59.999999Z"
        );
    }

    #[test]
    fn ecs_campos_estandar_presentes() {
        let v = to_ecs(&flujo_demo());
        assert_eq!(v["@timestamp"], json!("2023-11-14T22:13:20.000000Z"));
        assert_eq!(v["source.ip"], json!("192.168.1.10"));
        assert_eq!(v["destination.port"], json!(443));
        assert_eq!(v["network.transport"], json!("tcp"));
        assert_eq!(v["network.protocol"], json!("tls"));
        assert_eq!(v["network.bytes"], json!(4_300));
        assert_eq!(v["network.packets"], json!(12));
        assert_eq!(v["destination.domain"], json!("ejemplo.com"));
        assert_eq!(
            v["tls.client.server_name"],
            json!("store.ejemplo-corporativo.com")
        );
        assert_eq!(v["tls.ja4"], json!("t13d0208h2_777cda164f4b_af51ac0c444f"));
        assert_eq!(
            v["event.duration"],
            json!(100_000_000),
            "ECS usa nanosegundos"
        );
    }

    #[test]
    fn ecs_alertas_aportan_rule_y_threat() {
        let mut f = flujo_demo();
        f.alerts.push(Alert {
            id: "BEACONING".into(),
            name: "Comunicación periódica".into(),
            severity: Severity::Medium,
            detail: "intervalo 30.0s".into(),
            mitre: Some("T1071".into()),
        });
        f.alerts.push(Alert {
            id: "X".into(),
            name: "Otra".into(),
            severity: Severity::High,
            detail: "detalle".into(),
            mitre: Some("T1071".into()), // duplicado: no se repite
        });
        let v = to_ecs(&f);
        assert_eq!(v["threat.technique.id"], json!(["T1071"]));
        assert!(v["rule.name"].as_array().unwrap().len() == 2);
    }

    #[test]
    fn wazuh_plano_con_rule_y_mitre_solo_si_hay_alertas() {
        let mut f = flujo_demo();
        f.threat_intel = vec!["FEODO-C2".into()];
        f.alerts.push(Alert {
            id: "THREAT-INTEL-FEODO".into(),
            name: "Destino en lista Feodo".into(),
            severity: Severity::High,
            detail: "dst 198.51.100.23".into(),
            mitre: Some("T1071.001".into()),
        });
        let v = to_wazuh(&f);
        assert_eq!(v["program_name"], json!("socshark"));
        assert_eq!(v["srcip"], json!("192.168.1.10"));
        assert_eq!(v["dstport"], json!(443));
        assert_eq!(v["protocol"], json!("tcp"));
        assert_eq!(v["rule"]["level"], json!(10), "High → nivel 10");
        assert_eq!(v["rule"]["mitre"]["id"], json!(["T1071.001"]));
        assert_eq!(v["data"]["socshark"]["risk_score"], json!(0));
        assert_eq!(v["data"]["threat_intel"], json!(["FEODO-C2"]));

        // Sin alertas no hay `rule`: evento archivado, no alerta.
        let sin = to_wazuh(&flujo_demo());
        assert!(sin.get("rule").is_none());
        assert!(sin.get("data").is_some());
    }

    #[test]
    fn severidad_a_nivel_wazuh_escala_completa() {
        assert_eq!(severity_to_wazuh_level(Severity::Info), 2);
        assert_eq!(severity_to_wazuh_level(Severity::Low), 4);
        assert_eq!(severity_to_wazuh_level(Severity::Medium), 6);
        assert_eq!(severity_to_wazuh_level(Severity::High), 10);
        assert_eq!(severity_to_wazuh_level(Severity::Critical), 13);
    }

    #[test]
    fn ecs_y_wazuh_son_json_validos_serializables() {
        let f = flujo_demo();
        // Serialize roundtrip: no debe fallar ni colgar con caracteres raros.
        let ecs = to_ecs(&f).to_string();
        let wazuh = to_wazuh(&f).to_string();
        assert!(ecs.contains("\"source.ip\""));
        assert!(wazuh.contains("\"srcip\""));
    }
}
