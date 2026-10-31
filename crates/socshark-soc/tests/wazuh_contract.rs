//! Test de contrato del export Wazuh (`siem::to_wazuh`) y de las reglas que
//! lo consumen (`docs/wazuh/local_rules.xml`).
//!
//! No sustituye a probar contra un manager real (`wazuh-logtest`, hoja de
//! ruta 0.8), pero fija lo que un manager necesita para que las reglas
//! funcionen y lo comprueba en cada `cargo test`:
//!
//! - claves de primer nivel: solo las documentadas, con su tipo;
//! - `srcip`/`dstip` son IPs válidas y `timestamp` es ISO-8601 UTC;
//! - `rule` aparece si y solo si el flujo tiene alertas, con un `level` de
//!   la escala documentada y IDs MITRE con forma `Tnnnn[.nnn]`;
//! - **cada nivel y cada técnica que puede emitir soc-shark tiene su regla**
//!   en `local_rules.xml` (si se añade una técnica nueva, el test falla hasta
//!   que alguien escriba su regla).

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;

use socshark_core::config::PipelineConfig;
use socshark_core::{EnrichedFlow, LinkType, RawPacket, Severity};
use socshark_dissectors::DissectorPipeline;
use socshark_flow::FlowAggregator;
use socshark_soc::siem::{severity_to_wazuh_level, to_wazuh};
use socshark_soc::{enrich_all, SocContext};
use socshark_testgen as tg;

/// Claves de primer nivel permitidas y si son obligatorias.
const TOP_LEVEL: &[(&str, bool)] = &[
    ("program_name", true),
    ("timestamp", true),
    ("srcip", true),
    ("srcport", true),
    ("dstip", true),
    ("dstport", true),
    ("protocol", true),
    ("data", true),
    ("rule", false),
];

fn rules_xml() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/wazuh/local_rules.xml");
    std::fs::read_to_string(p).expect("falta docs/wazuh/local_rules.xml")
}

/// Flujos del pipeline completo sobre todos los escenarios con alertas.
fn pipeline_flows() -> Vec<EnrichedFlow> {
    let cfg = PipelineConfig {
        collect_streams: true,
        file_carving: true,
        ..PipelineConfig::default()
    };
    let dissectors = DissectorPipeline::new();
    let mut all = Vec::new();
    for packets in [
        tg::sample_pcap_packets(),
        tg::home_pcap_packets(),
        tg::evasion::dns_low_entropy_tunnel_packets(),
        tg::evasion::jittered_beacon_packets(7),
    ] {
        let mut agg = FlowAggregator::new(cfg.max_flows, cfg.idle_timeout_secs, true);
        for (ts, frame) in packets {
            let raw = RawPacket {
                ts_micros: ts,
                orig_len: frame.len() as u32,
                data: frame,
            };
            if let Some(dp) = dissectors.dissect(&raw, LinkType::Ethernet) {
                agg.on_packet(raw.ts_micros, raw.data.len(), &dp);
            }
        }
        let (mut flows, streams) = agg.finish_with_streams();
        socshark_soc::carve::carve_all(&mut flows, &streams);
        let mut ctx = SocContext::default();
        enrich_all(&mut ctx, &mut flows, &cfg);
        all.extend(flows);
    }
    all
}

fn is_iso8601_utc(s: &str) -> bool {
    // 2023-11-14T22:13:20.000000Z
    let b = s.as_bytes();
    b.len() == 27
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'.'
        && b[26] == b'Z'
        && s.chars()
            .enumerate()
            .all(|(i, c)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19 | 26) || c.is_ascii_digit())
}

fn is_mitre_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('T') else {
        return false;
    };
    let (main, sub) = rest
        .split_once('.')
        .map_or((rest, None), |(m, s)| (m, Some(s)));
    main.len() == 4
        && main.chars().all(|c| c.is_ascii_digit())
        && sub.is_none_or(|s| s.len() == 3 && s.chars().all(|c| c.is_ascii_digit()))
}

#[test]
fn wazuh_cumple_el_contrato() {
    let flows = pipeline_flows();
    assert!(flows.iter().any(|f| !f.alerts.is_empty()));
    let mut problems = Vec::new();

    for f in &flows {
        let ev = to_wazuh(f);
        let obj = ev.as_object().expect("el evento es un objeto");
        let id = &f.flow_id.0;

        for k in obj.keys() {
            if !TOP_LEVEL.iter().any(|(name, _)| name == k) {
                problems.push(format!("{id}: clave no documentada `{k}`"));
            }
        }
        for (k, required) in TOP_LEVEL {
            if *required && !obj.contains_key(*k) {
                problems.push(format!("{id}: falta `{k}`"));
            }
        }
        if ev["program_name"] != "socshark" {
            problems.push(format!("{id}: program_name = {}", ev["program_name"]));
        }
        for k in ["srcip", "dstip"] {
            if ev[k]
                .as_str()
                .and_then(|s| s.parse::<IpAddr>().ok())
                .is_none()
            {
                problems.push(format!("{id}: `{k}` no es una IP: {}", ev[k]));
            }
        }
        for k in ["srcport", "dstport"] {
            if !ev[k].as_u64().is_some_and(|p| p <= 65_535) {
                problems.push(format!("{id}: `{k}` no es un puerto: {}", ev[k]));
            }
        }
        if !ev["timestamp"].as_str().is_some_and(is_iso8601_utc) {
            problems.push(format!("{id}: timestamp no ISO-8601: {}", ev["timestamp"]));
        }
        if !ev["data"]["socshark"]["risk_score"].is_u64() {
            problems.push(format!("{id}: falta data.socshark.risk_score"));
        }

        match (f.alerts.is_empty(), ev.get("rule")) {
            (true, Some(_)) => problems.push(format!("{id}: `rule` sin alertas")),
            (false, None) => problems.push(format!("{id}: alertas sin `rule`")),
            (false, Some(rule)) => {
                let max = f.alerts.iter().map(|a| a.severity).max().unwrap();
                if rule["level"] != severity_to_wazuh_level(max) {
                    problems.push(format!("{id}: rule.level {} ≠ {max:?}", rule["level"]));
                }
                if !rule["description"].is_string() {
                    problems.push(format!("{id}: rule.description no es texto"));
                }
                if let Some(ids) = rule.get("mitre").map(|m| &m["id"]) {
                    for t in ids.as_array().into_iter().flatten() {
                        if !t.as_str().is_some_and(is_mitre_id) {
                            problems.push(format!("{id}: ID MITRE mal formado {t}"));
                        }
                    }
                }
            }
            (true, None) => {}
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

/// Cada nivel de la escala tiene una regla de severidad en el XML.
#[test]
fn reglas_cubren_todos_los_niveles() {
    let xml = rules_xml();
    let level_fields: Vec<&str> = xml
        .split("<field name=\"rule.level\">")
        .skip(1)
        .filter_map(|s| s.split("</field>").next())
        .collect();
    for sev in [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        let lvl = format!("^{}$", severity_to_wazuh_level(sev));
        assert!(
            level_fields
                .iter()
                .any(|re| re.split('|').any(|alt| alt == lvl)),
            "ninguna regla de local_rules.xml casa rule.level {lvl} ({sev:?})"
        );
    }
}

/// Cada técnica MITRE que emite soc-shark tiene su regla con bloque
/// `<mitre>`. Las técnicas se recogen del código fuente de la capa SOC, no
/// de los escenarios, para que una técnica nueva sin escenario también falle.
#[test]
fn reglas_cubren_todas_las_tecnicas_mitre() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut techniques = BTreeSet::new();
    for entry in std::fs::read_dir(&src_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "rs") {
            let code = std::fs::read_to_string(&path).unwrap();
            // Solo el código de producción: los tests usan IDs inventados.
            let code = code.split("#[cfg(test)]").next().unwrap_or_default();
            for chunk in code.split('"').skip(1).step_by(2) {
                if is_mitre_id(chunk) {
                    techniques.insert(chunk.to_string());
                }
            }
        }
    }
    assert!(techniques.contains("T1071.004"), "{techniques:?}");

    let xml = rules_xml();
    let mapped: BTreeSet<&str> = xml
        .split("<mitre><id>")
        .skip(1)
        .filter_map(|s| s.split("</id>").next())
        .collect();
    let missing: Vec<_> = techniques
        .iter()
        .filter(|t| !mapped.contains(t.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "técnicas sin regla en docs/wazuh/local_rules.xml: {missing:?}"
    );

    // Y el XML no tiene IDs de regla repetidos.
    let ids: Vec<&str> = xml
        .split("<rule id=\"")
        .skip(1)
        .filter_map(|s| s.split('"').next())
        .collect();
    let unique: BTreeSet<_> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len(), "IDs de regla repetidos: {ids:?}");
}

#[test]
fn validadores_auxiliares() {
    assert!(is_iso8601_utc("2023-11-14T22:13:20.000000Z"));
    assert!(!is_iso8601_utc("2023-11-14 22:13:20"));
    assert!(is_mitre_id("T1071") && is_mitre_id("T1071.004"));
    assert!(!is_mitre_id("T107") && !is_mitre_id("T1071.4") && !is_mitre_id("X1071"));
}
