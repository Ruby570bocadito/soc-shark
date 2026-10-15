//! Estadísticas agregadas estilo columna sobre los flujos de una captura.

use socshark_flow_aggregator::model::EnrichedFlow;
use std::collections::HashMap;

/// Histograma de protocolos L7.
pub fn protocol_histogram(flows: &[EnrichedFlow]) -> Vec<(&'static str, usize)> {
    let mut m: HashMap<&'static str, usize> = HashMap::new();
    for f in flows {
        *m.entry(f.l7_protocol).or_default() += 1;
    }
    let mut v: Vec<(&'static str, usize)> = m.into_iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    v
}

/// Top talkers por bytes totales (src o dst).
pub fn top_talkers(flows: &[EnrichedFlow], n: usize) -> Vec<(String, u64)> {
    let mut m: HashMap<String, u64> = HashMap::new();
    for f in flows {
        let bytes = f.bytes_c2s + f.bytes_s2c;
        if bytes == 0 {
            continue;
        }
        *m.entry(f.key.src.to_string()).or_default() += f.bytes_c2s;
        *m.entry(f.key.dst.to_string()).or_default() += f.bytes_s2c;
    }
    let mut v: Vec<(String, u64)> = m.into_iter().collect();
    v.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
    v.truncate(n);
    v
}

/// Alertas agrupadas por identificador de detector.
pub fn alert_histogram(flows: &[EnrichedFlow]) -> Vec<(&'static str, usize)> {
    let mut m: HashMap<&'static str, usize> = HashMap::new();
    for f in flows {
        for a in &f.alerts {
            *m.entry(a.id).or_default() += 1;
        }
    }
    let mut v: Vec<(&'static str, usize)> = m.into_iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    v
}
