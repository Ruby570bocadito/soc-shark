//! Capa de salida: tabla resumen legible y volcado JSONL.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::Result;
use socshark_core::EnrichedFlow;
use socshark_soc::summarize::fmt_bytes;

use crate::pipeline::CaptureOutput;

/// Escribe los flujos como JSONL (un `EnrichedFlow` por línea).
///
/// JSONL y no un array JSON: permite `jq`, `grep` y lectura en streaming
/// sin cargar todo el archivo; es también el formato que consumirán los
/// exportadores SIEM (ECS) de Fase 4.
pub fn write_jsonl(path: &Path, flows: &[EnrichedFlow]) -> Result<()> {
    let file = File::create(path)?;
    let mut w = BufWriter::new(file);
    for flow in flows {
        serde_json::to_writer(&mut w, flow)?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(())
}

/// Imprime la tabla resumen de los `top` flujos más voluminosos y la sección
/// de alertas SOC ordenada por riesgo.
pub fn print_summary(out: &CaptureOutput, top: usize) {
    let mut sorted: Vec<&EnrichedFlow> = out.flows.iter().collect();
    sorted.sort_by_key(|f| std::cmp::Reverse(f.bytes + f.bytes_rev));

    println!();
    println!(
        "═══ soc-shark · {} flujos ({}) ═══",
        out.flows.len(),
        out.pcap_path.display()
    );
    println!(
        "{:<60} {:<5} {:>7} {:>10} {:>7}  ALERTAS",
        "FLUJO", "L7", "PAQ", "BYTES", "RIESGO"
    );
    for flow in sorted.iter().take(top) {
        println!(
            "{:<60} {:<5} {:>7} {:>10} {:>7}  {}",
            truncate(&flow.flow_id.0, 60),
            flow.l7_protocol.as_str(),
            flow.packets + flow.packets_rev,
            fmt_bytes(flow.bytes + flow.bytes_rev),
            flow.risk_score,
            alerts_cell(flow),
        );
    }
    if sorted.len() > top {
        println!(
            "… y {} flujos más (usa --json para el volcado completo)",
            sorted.len() - top
        );
    }

    let mut alerted: Vec<&EnrichedFlow> =
        out.flows.iter().filter(|f| !f.alerts.is_empty()).collect();
    alerted.sort_by_key(|f| std::cmp::Reverse(f.risk_score));
    if !alerted.is_empty() {
        println!();
        println!("─── Alertas SOC ───");
        for flow in alerted {
            for alert in &flow.alerts {
                println!(
                    "▸ ({}) {} · {} · {}{}",
                    alert.severity.as_str(),
                    alert.name,
                    flow.flow_id.0,
                    alert.detail,
                    alert
                        .mitre
                        .as_ref()
                        .map(|m| format!(" · MITRE {m}"))
                        .unwrap_or_default()
                );
            }
        }
    }

    println!();
    println!("Estadísticas: {}", out.stats.summary());
    println!("DNS pasivo: {} entradas", out.passive_dns_entries);
}

fn alerts_cell(flow: &EnrichedFlow) -> String {
    if flow.alerts.is_empty() {
        "-".to_string()
    } else {
        flow.alerts
            .iter()
            .map(|a| a.id.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Recorta una cadena para la tabla (respetando límites de caracteres, no
/// bytes, para no partir UTF-8).
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!(
            "{}…",
            s.chars().take(max.saturating_sub(1)).collect::<String>()
        )
    }
}
