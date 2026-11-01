//! Corpus de verificación de detecciones (hoja de ruta 0.8).
//!
//! Cada captura de `corpus/manifest.json` declara su **verdad de campo**:
//!
//! - `must`: reglas que tienen que saltar al menos una vez (verdaderos
//!   positivos esperados);
//! - `must_not`: reglas que no pueden saltar (falsos positivos conocidos);
//! - `max_severity`: severidad máxima aceptable en toda la captura.
//!
//! Y un *golden file* (`corpus/golden/<name>.json`) con el resultado
//! esperado: número de flujos, alertas por regla y los flujos alertados con
//! su riesgo. Cualquier cambio en las detecciones aparece como diferencia en
//! ese fichero, que se revisa en el PR como cualquier otro código.
//!
//! ```bash
//! cargo test -p socshark-cli --test corpus                     # comprobar
//! SOCSHARK_BLESS=1 cargo test -p socshark-cli --test corpus    # regenerar golden
//! ```
//!
//! Las capturas reales (`"file"`) no se versionan si pesan o tienen licencia
//! incompatible: si faltan se omiten con un aviso, salvo con
//! `SOCSHARK_CORPUS_STRICT=1` (para CI con el corpus descargado). Su
//! `sha256` se comprueba siempre que el archivo esté.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use socshark_cli::pipeline::run_capture;
use socshark_core::config::PipelineConfig;
use socshark_core::{EnrichedFlow, Severity};
use socshark_testgen as tg;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn env_on(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| v != "0" && !v.is_empty())
}

/// Paquetes de un escenario sintético de `socshark-testgen` por nombre.
fn synthetic(name: &str) -> Vec<(u64, Vec<u8>)> {
    match name {
        "sample" => tg::sample_pcap_packets(),
        "home" => tg::home_pcap_packets(),
        "dns_benign" => tg::evasion::dns_benign_packets(),
        "dns_low_entropy_tunnel" => tg::evasion::dns_low_entropy_tunnel_packets(),
        "jittered_beacon" => tg::evasion::jittered_beacon_packets(7),
        "interactive_sessions" => tg::evasion::interactive_sessions_packets(),
        other => panic!("escenario sintético desconocido en el manifiesto: {other}"),
    }
}

fn strings(entry: &Value, key: &str) -> Vec<String> {
    entry[key]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Resultado comparable de una captura (lo que se guarda como golden).
fn summarize(flows: &[EnrichedFlow]) -> Value {
    let mut by_rule: BTreeMap<&str, u64> = BTreeMap::new();
    let mut alerted: Vec<Value> = Vec::new();
    for f in flows {
        for a in &f.alerts {
            *by_rule.entry(a.id.as_str()).or_default() += 1;
        }
        if !f.alerts.is_empty() {
            let mut ids: Vec<&str> = f.alerts.iter().map(|a| a.id.as_str()).collect();
            ids.sort_unstable();
            alerted.push(json!({
                "flow_id": f.flow_id.0,
                "risk_score": f.risk_score,
                "alerts": ids,
            }));
        }
    }
    alerted.sort_by(|a, b| a["flow_id"].as_str().cmp(&b["flow_id"].as_str()));
    json!({
        "flows": flows.len(),
        "alerts_by_rule": by_rule,
        "alerted_flows": alerted,
    })
}

/// Ejecuta el pipeline sobre una entrada del manifiesto. `None` si es una
/// captura real que no está descargada.
fn run_entry(entry: &Value, tmp_tag: &str) -> Option<Vec<EnrichedFlow>> {
    let cfg = PipelineConfig {
        file_carving: entry["carve_files"].as_bool().unwrap_or(false),
        ..PipelineConfig::default()
    };

    let (path, temp) = if let Some(gen) = entry["synthetic"].as_str() {
        let p = std::env::temp_dir().join(format!(
            "socshark-corpus-{tmp_tag}-{}.pcap",
            std::process::id()
        ));
        tg::write_pcap(&p, 1, &synthetic(gen)).unwrap();
        (p, true)
    } else {
        let file = entry["file"]
            .as_str()
            .expect("cada entrada necesita `synthetic` o `file`");
        let p = corpus_dir().join(file);
        if !p.exists() {
            assert!(
                !env_on("SOCSHARK_CORPUS_STRICT"),
                "falta la captura del corpus {file} (SOCSHARK_CORPUS_STRICT=1)"
            );
            eprintln!("aviso: {file} no está descargada; se omite");
            return None;
        }
        if let Some(expected) = entry["sha256"].as_str() {
            let got = socshark_core::to_hex(&socshark_core::sha256(&std::fs::read(&p).unwrap()));
            assert_eq!(got, expected, "sha256 distinto para {file}");
        }
        (p, false)
    };

    // Con ruido: la verdad de campo es sobre todos los flujos.
    let out = run_capture(&path, None, true, &cfg).unwrap();
    if temp {
        std::fs::remove_file(&path).ok();
    }
    Some(out.flows)
}

#[test]
fn corpus_cumple_verdad_de_campo_y_golden() {
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(corpus_dir().join("manifest.json")).unwrap())
            .expect("corpus/manifest.json no es JSON válido");
    let bless = env_on("SOCSHARK_BLESS");
    let mut failures: Vec<String> = Vec::new();
    // regla → [VP en capturas reales, VP en sintéticas, FP]: el criterio de
    // la 0.8 pide verdaderos positivos *reales*, así que se cuentan aparte.
    let mut tally: BTreeMap<String, [u32; 3]> = BTreeMap::new();
    let mut known_misses: Vec<String> = Vec::new();

    for entry in manifest["captures"].as_array().expect("falta `captures`") {
        let name = entry["name"]
            .as_str()
            .expect("cada captura necesita `name`");
        let Some(flows) = run_entry(entry, name) else {
            continue;
        };

        // ---- Verdad de campo ----
        let real = entry.get("file").is_some();
        if let Some(miss) = entry["known_miss"].as_str() {
            known_misses.push(format!("{name}: {miss}"));
        }
        let fired = |rule: &str| flows.iter().any(|f| f.alerts.iter().any(|a| a.id == rule));
        for rule in strings(entry, "must") {
            if fired(&rule) {
                tally.entry(rule).or_default()[if real { 0 } else { 1 }] += 1;
            } else {
                failures.push(format!("{name}: la regla {rule} debía saltar y no saltó"));
            }
        }
        for rule in strings(entry, "must_not") {
            if fired(&rule) {
                tally.entry(rule.clone()).or_default()[2] += 1;
                failures.push(format!("{name}: falso positivo de {rule}"));
            }
        }
        if let Some(max) = entry["max_severity"].as_str() {
            let max: Severity = serde_json::from_value(json!(max)).expect("max_severity inválida");
            for f in &flows {
                for a in f.alerts.iter().filter(|a| a.severity > max) {
                    failures.push(format!(
                        "{name}: {} con severidad {:?} (máximo {max:?}) en {}",
                        a.id, a.severity, f.flow_id.0
                    ));
                }
            }
        }

        // ---- Golden file ----
        let got = summarize(&flows);
        let golden = corpus_dir().join("golden").join(format!("{name}.json"));
        let pretty = serde_json::to_string_pretty(&got).unwrap() + "\n";
        if bless {
            std::fs::write(&golden, pretty).unwrap();
            continue;
        }
        match std::fs::read_to_string(&golden) {
            Ok(text) => {
                let expected: Value = serde_json::from_str(&text).unwrap();
                if expected != got {
                    failures.push(format!(
                        "{name}: el resultado no coincide con {}.\n\
                         Si el cambio es intencionado: SOCSHARK_BLESS=1 cargo test -p socshark-cli --test corpus\n\
                         obtenido:\n{pretty}",
                        golden.display()
                    ));
                }
            }
            Err(_) => failures.push(format!(
                "{name}: falta {} (genéralo con SOCSHARK_BLESS=1)",
                golden.display()
            )),
        }
    }

    eprintln!("\nregla                      VP reales  VP sintéticos  FP prohibidos");
    for (rule, [real, synth, fp]) in &tally {
        eprintln!("{rule:<26} {real:>9}  {synth:>13}  {fp:>13}");
    }
    if !known_misses.is_empty() {
        eprintln!("\nfallos conocidos (sin regla todavía):");
        for m in &known_misses {
            eprintln!("  - {m}");
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
