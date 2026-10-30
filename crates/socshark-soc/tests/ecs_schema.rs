//! Validación de la salida ECS (`siem::to_ecs`) contra el esquema oficial de
//! Elastic.
//!
//! El test lee la definición plana de campos de ECS (`ecs_flat.yml`) desde
//! la ruta de la variable de entorno `SOCSHARK_ECS_FLAT`; sin ella imprime
//! un aviso y pasa (el job `ecs` de CI descarga la versión fijada):
//!
//! ```bash
//! curl --proto '=https' -fsSLo ecs_flat.yml \
//!   https://raw.githubusercontent.com/elastic/ecs/v8.11.0/generated/ecs/ecs_flat.yml
//! SOCSHARK_ECS_FLAT=ecs_flat.yml cargo test -p socshark-soc --test ecs_schema
//! ```
//!
//! Comprueba, para cada evento generado por el pipeline sobre los
//! escenarios de `socshark-testgen` (y una variante con todos los campos
//! opcionales poblados):
//!
//! - que cada ruta de campo emitida existe en ECS o cae en un espacio de
//!   nombres personalizado permitido ([`CUSTOM_NAMESPACES`]);
//! - que el tipo JSON del valor es compatible con el tipo ECS (números para
//!   `long`/`float`, cadenas para `keyword`/`date`, IP válida para `ip`,
//!   booleanos para `boolean`, objetos para `object`/`nested`).
//!
//! Sin dependencias nuevas: del YAML basta con las claves de primer nivel
//! (nombres de campo con puntos en la columna 0) y su `type`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde_json::Value;
use socshark_core::config::PipelineConfig;
use socshark_core::{
    Alert, DnsAnswerSummary, DnsQuerySummary, DnsSummary, EnrichedFlow, ExtractedFile, LinkType,
    RawPacket, Severity,
};
use socshark_dissectors::DissectorPipeline;
use socshark_flow::FlowAggregator;
use socshark_soc::siem::to_ecs;
use socshark_soc::{enrich_all, SocContext};
use socshark_testgen as tg;

/// Espacios de nombres no-ECS permitidos explícitamente. ECS reserva
/// `labels.*` para etiquetas propias y recomienda un espacio de nombres del
/// proveedor para el resto (aquí `socshark.*`).
const CUSTOM_NAMESPACES: &[&str] = &["socshark", "labels"];

/// Lee `ecs_flat.yml` y devuelve `ruta → tipo` de cada campo.
fn parse_ecs_flat(yaml: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in yaml.lines() {
        let first = line.chars().next();
        if matches!(first, Some(c) if c != ' ' && c != '#' && c != '-') {
            // Clave de primer nivel: `campo.con.puntos:` o `'@timestamp':`.
            current = line
                .strip_suffix(':')
                .map(|k| k.trim_matches('\'').trim_matches('"').to_string());
        } else if let (Some(name), Some(ty)) = (&current, line.strip_prefix("  type: ")) {
            fields.insert(name.clone(), ty.trim().to_string());
        }
    }
    fields
}

/// Un hallazgo del validador (campo, valor emitido y lo que espera ECS).
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Mismatch {
    field: String,
    emitted: String,
    expected: String,
}

fn json_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "integer",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// ¿Es `v` (un valor escalar u objeto, nunca un array) válido para `ty`?
fn type_ok(ty: &str, v: &Value) -> bool {
    match ty {
        "keyword" | "constant_keyword" | "wildcard" | "text" | "match_only_text" | "version" => {
            v.is_string()
        }
        "long" | "integer" | "short" | "byte" | "unsigned_long" => v.is_u64() || v.is_i64(),
        "float" | "double" | "half_float" | "scaled_float" => v.is_number(),
        "boolean" => v.is_boolean(),
        "ip" => v.as_str().is_some_and(|s| s.parse::<IpAddr>().is_ok()),
        "date" => v.is_string(),
        "object" | "nested" | "flattened" => v.is_object(),
        "geo_point" => v.is_object() || v.is_string(),
        // Tipo que este validador no conoce: se señala para revisarlo.
        _ => false,
    }
}

fn is_custom(path: &str) -> bool {
    CUSTOM_NAMESPACES
        .iter()
        .any(|ns| path == *ns || path.strip_prefix(ns).is_some_and(|r| r.starts_with('.')))
}

/// Recorre el evento y valida cada hoja. Los objetos se aplanan uniendo
/// claves con `.` (ECS admite tanto `{"a.b": 1}` como `{"a": {"b": 1}}`);
/// en los arrays se valida cada elemento con la ruta del array.
fn check(
    schema: &BTreeMap<String, String>,
    path: &str,
    v: &Value,
    seen: &mut BTreeSet<String>,
    out: &mut BTreeSet<Mismatch>,
) {
    match v {
        Value::Array(items) => {
            for item in items {
                check(schema, path, item, seen, out);
            }
        }
        Value::Object(map) => {
            if let Some(ty) = schema.get(path) {
                seen.insert(path.to_string());
                if !type_ok(ty, v) {
                    out.insert(Mismatch {
                        field: path.to_string(),
                        emitted: "object".into(),
                        expected: ty.clone(),
                    });
                }
            }
            for (k, child) in map {
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                check(schema, &p, child, seen, out);
            }
        }
        _ => {
            seen.insert(path.to_string());
            if is_custom(path) {
                return;
            }
            match schema.get(path) {
                None => {
                    out.insert(Mismatch {
                        field: path.to_string(),
                        emitted: json_kind(v).into(),
                        expected: "campo inexistente en ECS".into(),
                    });
                }
                Some(ty) if !type_ok(ty, v) => {
                    out.insert(Mismatch {
                        field: path.to_string(),
                        emitted: format!("{} ({v})", json_kind(v)),
                        expected: ty.clone(),
                    });
                }
                Some(_) => {}
            }
        }
    }
}

/// Flujos del pipeline completo (dissector → agregador con reensamblado →
/// carving → SOC) sobre los escenarios demo y doméstico.
fn pipeline_flows() -> Vec<EnrichedFlow> {
    let cfg = PipelineConfig {
        collect_streams: true,
        file_carving: true,
        ..PipelineConfig::default()
    };
    let dissectors = DissectorPipeline::new();
    let mut all = Vec::new();
    for packets in [tg::sample_pcap_packets(), tg::home_pcap_packets()] {
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

/// Variante con todos los campos opcionales poblados, para cubrir las ramas
/// de `to_ecs` que el escenario no alcanza (proceso, usuario, intel...).
fn maximal(base: &EnrichedFlow) -> EnrichedFlow {
    let mut f = base.clone();
    f.src_mac = Some("00:11:22:33:44:55".into());
    f.dst_mac = Some("66:77:88:99:aa:bb".into());
    f.process_name = Some("curl".into());
    f.pid = Some(4242);
    f.user = Some("analista".into());
    f.resolved_domain = Some("example.com".into());
    f.tls_sni = Some("example.com".into());
    f.ja4_fingerprint = Some("t13d1516h2_8daaf6152771_02713d6af862".into());
    f.threat_intel = vec!["TOR-EXIT".into()];
    f.dns = Some(DnsSummary {
        is_response: true,
        rcode: Some(3),
        queries: vec![DnsQuerySummary {
            name: "example.com".into(),
            qtype: 1,
        }],
        answers: vec![
            DnsAnswerSummary {
                name: "example.com".into(),
                rtype: 1,
                ttl: 300,
                address: Some("93.184.216.34".parse().unwrap()),
                target: None,
            },
            DnsAnswerSummary {
                name: "www.example.com".into(),
                rtype: 5,
                ttl: 300,
                address: None,
                target: Some("example.com".into()),
            },
        ],
    });
    f.alerts.push(Alert {
        id: "MASQUERADING".into(),
        name: "Archivo disfrazado".into(),
        severity: Severity::High,
        detail: "factura.jpg es PE32".into(),
        mitre: Some("T1036".into()),
    });
    f.extracted_files.push(ExtractedFile {
        name: "factura.jpg".into(),
        size: 1024,
        sha256: Some("00".repeat(32)),
        magic: Some("PE32".into()),
        masquerading_suspect: true,
    });
    f
}

#[test]
fn ecs_cumple_el_esquema_oficial() {
    let Some(path) = std::env::var_os("SOCSHARK_ECS_FLAT") else {
        eprintln!(
            "[omitido] SOCSHARK_ECS_FLAT no definida: descarga ecs_flat.yml \
             (ver cabecera de tests/ecs_schema.rs) para validar contra ECS"
        );
        return;
    };
    let yaml = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("no se pudo leer {}: {e}", path.to_string_lossy()));
    let schema = parse_ecs_flat(&yaml);
    assert!(
        schema.len() > 1000 && schema.get("@timestamp").map(String::as_str) == Some("date"),
        "ecs_flat.yml no parece la definición plana de ECS ({} campos)",
        schema.len()
    );

    let flows = pipeline_flows();
    assert!(!flows.is_empty(), "el escenario no produjo flujos");
    let mut events: Vec<Value> = flows.iter().map(to_ecs).collect();
    events.extend(flows.iter().map(|f| to_ecs(&maximal(f))));

    let mut seen = BTreeSet::new();
    let mut mismatches = BTreeSet::new();
    for ev in &events {
        assert!(ev.is_object(), "un evento ECS debe ser un objeto JSON");
        check(&schema, "", ev, &mut seen, &mut mismatches);
    }

    eprintln!(
        "[ecs] {} eventos, {} rutas de campo distintas validadas",
        events.len(),
        seen.len()
    );
    let report: Vec<String> = mismatches
        .iter()
        .map(|m| {
            format!(
                "  {}: emitido {}, ECS espera {}",
                m.field, m.emitted, m.expected
            )
        })
        .collect();
    assert!(
        mismatches.is_empty(),
        "campos que no cumplen ECS:\n{}",
        report.join("\n")
    );
}

#[test]
fn parser_de_ecs_flat_lee_claves_y_tipos() {
    let yaml = "'@timestamp':\n  dashed_name: timestamp\n  description: 'Fecha.\n\n    type: falso'\n  type: date\n\
                source.port:\n  flat_name: source.port\n  multi_fields:\n  - flat_name: x.text\n    type: match_only_text\n  type: long\n";
    let s = parse_ecs_flat(yaml);
    assert_eq!(s.get("@timestamp").map(String::as_str), Some("date"));
    assert_eq!(s.get("source.port").map(String::as_str), Some("long"));
    assert_eq!(s.len(), 2);
}
