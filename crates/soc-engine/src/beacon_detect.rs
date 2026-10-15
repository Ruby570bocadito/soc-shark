//! Detección de C2 beaconing por regularidad temporal.
//!
//! Un implante que "llama a casa" repite la misma conexión a intervalos casi
//! constantes (jitter bajo). Métrica: coeficiente de variación (CV = σ/μ) de
//! los intervalos entre paquetes de datos agrupados por destino.
//!
//! Umbrales (documentados en docs/06-soc-engine.md):
//! - n ≥ 4 eventos de datos
//! - intervalo medio entre 1s y 600s (los beacons reales son minutos)
//! - CV ≤ 0.35 (regularidad alta)

use socshark_common::soc_types::{Severity, SocAlert};
use socshark_flow_aggregator::session_table::SessionTable;
use std::collections::HashMap;

pub const MIN_EVENTS: usize = 4;
pub const MIN_MEAN_US: u64 = 1_000_000;
pub const MAX_MEAN_US: u64 = 600_000_000;
pub const MAX_CV: f64 = 0.35;

/// Detecta beaconing; devuelve una alerta por cada flujo implicado en un
/// grupo regular (índice de flujo → alerta).
pub fn detect(table: &SessionTable) -> HashMap<usize, SocAlert> {
    // Agrupa índices de flujo por identidad de destino.
    let mut groups: HashMap<(String, String, u16, u8), Vec<usize>> = HashMap::new();
    for (i, f) in table.flows().iter().enumerate() {
        groups
            .entry((
                f.key
                    .src
                    .to_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
                    + if f.key.src.is_ipv4() { ".4" } else { ".6" },
                f.key
                    .dst
                    .to_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
                    + if f.key.dst.is_ipv4() { ".4" } else { ".6" },
                f.key.dport,
                f.key.proto,
            ))
            .or_default()
            .push(i);
    }

    let mut out = HashMap::new();
    for idxs in groups.values() {
        // Fusiona timestamps de paquetes con datos de todos los flujos del grupo.
        let mut ts: Vec<u64> = idxs
            .iter()
            .flat_map(|&i| {
                let f = &table.flows()[i];
                // Solo eventos de datos del cliente: el beacon es la llamada
                // saliente; las respuestas del servidor ensuciarían el CV.
                f.packet_ts
                    .iter()
                    .zip(f.packet_data.iter())
                    .filter(|(_, &d)| d == 1)
                    .map(|(&t, _)| t)
            })
            .collect();
        if ts.len() < MIN_EVENTS {
            continue;
        }
        ts.sort_unstable();
        ts.dedup();
        if ts.len() < MIN_EVENTS {
            continue;
        }
        let intervals: Vec<u64> = ts.windows(2).map(|w| w[1] - w[0]).collect();
        if intervals.is_empty() {
            continue;
        }
        let n = intervals.len() as f64;
        let mean = intervals.iter().sum::<u64>() as f64 / n;
        if mean < MIN_MEAN_US as f64 || mean > MAX_MEAN_US as f64 {
            continue;
        }
        let var = intervals
            .iter()
            .map(|&i| {
                let d = i as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / n;
        let sd = var.sqrt();
        let cv = if mean > 0.0 { sd / mean } else { f64::INFINITY };
        if cv > MAX_CV {
            continue;
        }
        let severity = if mean < 60_000_000.0 {
            Severity::Critical
        } else {
            Severity::High
        };
        let sample = &table.flows()[idxs[0]];
        let alert = SocAlert {
            id: "C2-BEACON",
            severity,
            title: format!(
                "Beaconing hacia {}:{} (CV {:.2}, n={})",
                sample.key.dst,
                sample.key.dport,
                cv,
                ts.len()
            ),
            detail: format!(
                "{} eventos de datos con intervalo medio {:.1}s y desviación {:.1}s \
                 (CV={:.2} ≤ {:.2}). La regularidad temporal es la firma de un \
                 implante con sleep fijo + jitter bajo.",
                ts.len(),
                mean / 1_000_000.0,
                sd / 1_000_000.0,
                cv,
                MAX_CV
            ),
            mitre: Some("T1071"),
            evidence: Some(format!(
                "intervalos_s={}",
                intervals
                    .iter()
                    .take(8)
                    .map(|i| format!("{:.1}", *i as f64 / 1_000_000.0))
                    .collect::<Vec<_>>()
                    .join(",")
            )),
        };
        for &i in idxs {
            out.insert(i, alert.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_common::ipaddr::IpAddr;
    use socshark_flow_aggregator::model::{EnrichedFlow, FlowKey};

    fn table_with_beacon(intervals_s: &[u64]) -> SessionTable {
        let mut t = SessionTable::new();
        let key = FlowKey {
            src: IpAddr::parse("192.168.1.50").unwrap(),
            sport: 49_812,
            dst: IpAddr::parse("185.22.1.9").unwrap(),
            dport: 4444,
            proto: 6,
        };
        let mut f = EnrichedFlow::new(0, key, 0);
        let mut ts = 1_000_000_000u64;
        for &d in intervals_s {
            f.packet_ts.push(ts);
            f.packet_data.push(1);
            ts += d * 1_000_000;
        }
        // inserta directo en flows vía feed de paquetes falsos no trivial;
        // usamos flows_mut de una tabla ya poblada con un flujo vacío
        t.insert_flow(f);
        t
    }

    #[test]
    fn detecta_beacon_regular() {
        let t = table_with_beacon(&[10, 10, 10, 10, 10]);
        let out = detect(&t);
        assert_eq!(out.len(), 1);
        let a = out.values().next().unwrap();
        assert_eq!(a.id, "C2-BEACON");
        assert_eq!(a.severity, Severity::Critical); // mean 10s < 60s
        assert!(a.evidence.as_ref().unwrap().contains("intervalos_s=10.0"));
    }

    #[test]
    fn ignora_trafico_irregular() {
        let t = table_with_beacon(&[3, 90, 7, 240, 15]);
        assert!(detect(&t).is_empty());
    }

    #[test]
    fn ignora_pocos_eventos() {
        let t = table_with_beacon(&[10, 10, 10]);
        assert!(detect(&t).is_empty());
    }
}
