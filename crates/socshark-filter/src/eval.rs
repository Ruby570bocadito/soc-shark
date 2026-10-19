//! Evaluación del AST contra un [`EnrichedFlow`].
//!
//! Semántica clave (documentada en `docs/filter-dsl.md`):
//! - `tcp.port` es multi-valor: devuelve ambos puertos del flujo, y `==`
//!   coincide si ALGUNO coincide. `!=` es la negación global (coincide solo
//!   si NINGUNO coincide), igual que el comportamiento intuitivo de tcpdump.
//! - Los campos desconocidos o ausentes no coinciden con nada (evalúan a
//!   `false`) en lugar de lanzar error: permite filtros compartidos entre
//!   flujos DNS y no-DNS.
//! - `contains` es insensible a mayúsculas para cadenas.

use std::cmp::Ordering;
use std::net::IpAddr;

use socshark_core::{dns_rcode_str, dns_type_str, EnrichedFlow, Transport};

use crate::ast::{CmpOp, Expr, FieldPath, Value};

/// Valor observable de un campo del flujo.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Num(f64),
    Str(String),
    Ip(IpAddr),
    Bool(bool),
}

impl FieldValue {
    fn to_string_lossy(&self) -> String {
        match self {
            FieldValue::Num(n) => format!("{n}"),
            FieldValue::Str(s) => s.clone(),
            FieldValue::Ip(ip) => ip.to_string(),
            FieldValue::Bool(b) => b.to_string(),
        }
    }
}

/// Resuelve un path a los valores observables del flujo.
///
/// Vacío = campo desconocido o no aplicable a este flujo.
pub fn get_fields(flow: &EnrichedFlow, path: &FieldPath) -> Vec<FieldValue> {
    let name = path.0.join(".");
    match name.as_str() {
        "ip.src" => vec![FieldValue::Ip(flow.src_ip)],
        "ip.dst" => vec![FieldValue::Ip(flow.dst_ip)],
        // Cualquiera de los dos extremos, como `ip.addr` en Wireshark.
        "ip.addr" | "host" => vec![FieldValue::Ip(flow.src_ip), FieldValue::Ip(flow.dst_ip)],
        // Fase 2: filtrar por familia (p. ej. `ip.version == 6`).
        "ip.version" => vec![FieldValue::Num(match flow.src_ip {
            IpAddr::V4(_) => 4.0,
            IpAddr::V6(_) => 6.0,
        })],
        "sport" | "src.port" => vec![FieldValue::Num(flow.src_port as f64)],
        "dport" | "dst.port" => vec![FieldValue::Num(flow.dst_port as f64)],
        // tcp.port/udp.port solo aplican si el transporte coincide (igual
        // que en tcpdump: filtrar udp.port no toca flujos TCP).
        "tcp.port" if flow.transport == Transport::Tcp => vec![
            FieldValue::Num(flow.src_port as f64),
            FieldValue::Num(flow.dst_port as f64),
        ],
        "udp.port" if flow.transport == Transport::Udp => vec![
            FieldValue::Num(flow.src_port as f64),
            FieldValue::Num(flow.dst_port as f64),
        ],
        "port" => vec![
            FieldValue::Num(flow.src_port as f64),
            FieldValue::Num(flow.dst_port as f64),
        ],
        "tcp.flags.syn" => vec![FieldValue::Bool(flow.tcp_flags.syn > 0)],
        "tcp.flags.ack" => vec![FieldValue::Bool(flow.tcp_flags.ack > 0)],
        "tcp.flags.fin" => vec![FieldValue::Bool(flow.tcp_flags.fin > 0)],
        "tcp.flags.rst" => vec![FieldValue::Bool(flow.tcp_flags.rst > 0)],
        "tcp.flags.psh" => vec![FieldValue::Bool(flow.tcp_flags.psh > 0)],
        "dns.qname" => flow
            .dns
            .as_ref()
            .map(|d| {
                d.queries
                    .iter()
                    .map(|q| FieldValue::Str(q.name.clone()))
                    .collect()
            })
            .unwrap_or_default(),
        "dns.qtype" => flow
            .dns
            .as_ref()
            .and_then(|d| d.queries.first())
            .map(|q| FieldValue::Str(dns_type_str(q.qtype)))
            .into_iter()
            .collect(),
        "dns.rcode" => flow
            .dns
            .as_ref()
            .and_then(|d| d.rcode)
            .map(|r| FieldValue::Str(dns_rcode_str(r).to_string()))
            .into_iter()
            .collect(),
        "dns.answer" => flow
            .dns
            .as_ref()
            .map(|d| {
                d.answers
                    .iter()
                    .filter_map(|a| match a.address {
                        Some(ip) => Some(FieldValue::Ip(ip)),
                        None => a.target.clone().map(FieldValue::Str),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        "net.l7" | "l7" | "proto" => vec![FieldValue::Str(flow.l7_protocol.as_str().to_string())],
        "net.transport" | "transport" => {
            vec![FieldValue::Str(flow.transport.as_str().to_string())]
        }
        "net.domain" | "domain" => flow
            .resolved_domain
            .clone()
            .map(FieldValue::Str)
            .into_iter()
            .collect(),
        // Fase 3: huella y SNI del ClientHello TLS.
        "tls.ja4" => flow
            .ja4_fingerprint
            .clone()
            .map(FieldValue::Str)
            .into_iter()
            .collect(),
        "tls.sni" => flow
            .tls_sni
            .clone()
            .map(FieldValue::Str)
            .into_iter()
            .collect(),
        // Fase 3: estadística de intervalos (beaconing).
        "flow.interval_mean_secs" => flow
            .interval_stats
            .map(|s| FieldValue::Num(s.mean_micros as f64 / 1_000_000.0))
            .into_iter()
            .collect(),
        "flow.interval_cv" => flow
            .interval_stats
            .map(|s| FieldValue::Num(s.cv()))
            .into_iter()
            .collect(),
        "flow.bytes" => vec![FieldValue::Num((flow.bytes + flow.bytes_rev) as f64)],
        "flow.packets" => vec![FieldValue::Num((flow.packets + flow.packets_rev) as f64)],
        "flow.risk" | "flow.risk_score" => vec![FieldValue::Num(flow.risk_score as f64)],
        "flow.noise" => vec![FieldValue::Bool(flow.is_background_noise)],
        "flow.alerts" => vec![FieldValue::Num(flow.alerts.len() as f64)],
        "flow.state" => vec![FieldValue::Str(flow.state.as_str().to_string())],
        "process.name" => flow
            .process_name
            .clone()
            .map(FieldValue::Str)
            .into_iter()
            .collect(),
        "process.pid" => flow
            .pid
            .map(|p| FieldValue::Num(p as f64))
            .into_iter()
            .collect(),
        // Fase 4: archivos tallados y threat intel offline.
        "file.count" => vec![FieldValue::Num(flow.extracted_files.len() as f64)],
        "file.name" => flow
            .extracted_files
            .iter()
            .map(|f| FieldValue::Str(f.name.clone()))
            .collect(),
        "file.magic" => flow
            .extracted_files
            .iter()
            .filter_map(|f| f.magic.clone().map(FieldValue::Str))
            .collect(),
        "file.masquerading" => vec![FieldValue::Bool(
            flow.extracted_files.iter().any(|f| f.masquerading_suspect),
        )],
        "intel.tag" => flow
            .threat_intel
            .iter()
            .map(|t| FieldValue::Str(t.clone()))
            .collect(),
        _ => Vec::new(),
    }
}

/// Evalúa la expresión contra un flujo.
pub fn eval(expr: &Expr, flow: &EnrichedFlow) -> bool {
    match expr {
        Expr::Or(a, b) => eval(a, flow) || eval(b, flow),
        Expr::And(a, b) => eval(a, flow) && eval(b, flow),
        Expr::Not(a) => !eval(a, flow),
        Expr::Truthy(path) => get_fields(flow, path).iter().any(truthy),
        Expr::Cmp { path, op, value } => {
            let fields = get_fields(flow, path);
            if fields.is_empty() {
                return false;
            }
            match op {
                CmpOp::Eq => fields.iter().any(|f| val_eq(f, value)),
                // != es global: coincide solo si NINGÚN valor del campo cumple.
                CmpOp::Ne => !fields.iter().any(|f| val_eq(f, value)),
                CmpOp::Contains => fields.iter().any(|f| val_contains(f, value)),
                CmpOp::Lt => fields
                    .iter()
                    .any(|f| val_ord(f, value) == Some(Ordering::Less)),
                CmpOp::Le => fields.iter().any(|f| {
                    matches!(
                        val_ord(f, value),
                        Some(Ordering::Less) | Some(Ordering::Equal)
                    )
                }),
                CmpOp::Gt => fields
                    .iter()
                    .any(|f| val_ord(f, value) == Some(Ordering::Greater)),
                CmpOp::Ge => fields.iter().any(|f| {
                    matches!(
                        val_ord(f, value),
                        Some(Ordering::Greater) | Some(Ordering::Equal)
                    )
                }),
            }
        }
    }
}

fn truthy(v: &FieldValue) -> bool {
    match v {
        FieldValue::Bool(b) => *b,
        FieldValue::Num(n) => *n != 0.0,
        FieldValue::Str(s) => !s.is_empty(),
        FieldValue::Ip(_) => true,
    }
}

/// Igualdad con tolerancia cruzada razonable (Num↔Str numérico, Ip↔Str).
fn val_eq(f: &FieldValue, v: &Value) -> bool {
    match (f, v) {
        (FieldValue::Num(a), Value::Num(b)) => a == b,
        (FieldValue::Str(a), Value::Str(b)) => a == b,
        (FieldValue::Ip(a), Value::Ip(b)) => a == b,
        (FieldValue::Bool(a), Value::Bool(b)) => a == b,
        (FieldValue::Num(a), Value::Str(b)) => b.parse::<f64>().map(|b| a == &b).unwrap_or(false),
        (FieldValue::Str(a), Value::Num(b)) => a.parse::<f64>().map(|a| a == *b).unwrap_or(false),
        (FieldValue::Ip(a), Value::Str(b)) => b.parse::<IpAddr>().map(|b| a == &b).unwrap_or(false),
        (FieldValue::Str(a), Value::Ip(b)) => a.parse::<IpAddr>().map(|a| a == *b).unwrap_or(false),
        (FieldValue::Num(a), Value::Bool(b)) => (*a != 0.0) == *b,
        (FieldValue::Bool(a), Value::Num(b)) => *a == (*b != 0.0),
        _ => false,
    }
}

/// Comparación de orden cuando ambos lados son numéricos (Num, Str numérica,
/// Bool). IPs no se ordenan: devolver None.
fn val_ord(f: &FieldValue, v: &Value) -> Option<Ordering> {
    let a = match f {
        FieldValue::Num(n) => Some(*n),
        FieldValue::Str(s) => s.parse::<f64>().ok(),
        FieldValue::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        FieldValue::Ip(_) => None,
    };
    let b = match v {
        Value::Num(n) => Some(*n),
        Value::Str(s) => s.parse::<f64>().ok(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Ip(_) => None,
    };
    match (a, b) {
        (Some(a), Some(b)) => a.partial_cmp(&b),
        _ => None,
    }
}

/// Contiene subcadena (insensible a mayúsculas). Sobre valores no-cadena se
/// compara su representación textual.
fn val_contains(f: &FieldValue, v: &Value) -> bool {
    let needle: String = match v {
        Value::Str(s) => s.clone(),
        Value::Num(n) => format!("{n}"),
        Value::Ip(ip) => ip.to_string(),
        Value::Bool(b) => b.to_string(),
    };
    let needle = needle.to_lowercase();
    match f {
        FieldValue::Str(s) => s.to_lowercase().contains(&needle),
        other => other.to_string_lossy().to_lowercase().contains(&needle),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    fn flow_from(json: &str) -> EnrichedFlow {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn campos_dns_qname_y_answer() {
        // Se construye un flujo DNS mediante JSON para no depender del testgen.
        let f = flow_from(
            r#"{
                "flow_id": "udp/10.0.0.1:5300-8.8.8.8:53",
                "state": "Idle", "transport": "Udp", "l7_protocol": "Dns",
                "src_ip": "10.0.0.1", "src_port": 5300,
                "dst_ip": "8.8.8.8", "dst_port": 53,
                "first_seen_micros": 0, "last_seen_micros": 1, "duration_micros": 1,
                "packets": 1, "bytes": 80, "packets_rev": 1, "bytes_rev": 100,
                "tcp_flags": {"syn":0,"ack":0,"fin":0,"rst":0,"psh":0,"urg":0},
                "human_summary": "", "risk_score": 0,
                "alerts": [], "extracted_files": [],
                "dns": {
                    "is_response": true, "rcode": 0,
                    "queries": [{"name": "Evil.Example", "qtype": 1}],
                    "answers": [{"name": "Evil.Example", "rtype": 1, "ttl": 300,
                                 "address": "1.2.3.4", "target": null}]
                }
            }"#,
        );
        assert!(eval(&parse("dns.qname contains \"evil\"").unwrap(), &f));
        assert!(eval(&parse("dns.qtype == \"A\"").unwrap(), &f));
        assert!(eval(&parse("dns.rcode == \"NOERROR\"").unwrap(), &f));
        assert!(eval(&parse("dns.answer == 1.2.3.4").unwrap(), &f));
        // ip.addr: cualquiera de los extremos; negarlo excluye el equipo.
        assert!(eval(&parse("ip.addr == 8.8.8.8").unwrap(), &f));
        assert!(eval(&parse("host == 10.0.0.1").unwrap(), &f));
        assert!(!eval(&parse("!(ip.addr == 8.8.8.8)").unwrap(), &f));
        assert!(eval(&parse("!(ip.addr == 9.9.9.9)").unwrap(), &f));
    }

    #[test]
    fn comparaciones_orden_con_cadenas_numericas() {
        let f = crate::tests::flujo_tls();
        assert!(eval(&parse("flow.risk > 40").unwrap(), &f));
        assert!(eval(&parse("flow.packets >= 7").unwrap(), &f));
        assert!(!eval(&parse("flow.risk < 40").unwrap(), &f));
    }

    #[test]
    fn campos_tls_ja4_y_sni_fase_3() {
        let f = flow_from(
            r#"{
                "flow_id": "tcp/10.0.0.1:52000-93.184.216.34:443",
                "state": "Idle", "transport": "Tcp", "l7_protocol": "Tls",
                "src_ip": "10.0.0.1", "src_port": 52000,
                "dst_ip": "93.184.216.34", "dst_port": 443,
                "first_seen_micros": 0, "last_seen_micros": 1, "duration_micros": 1,
                "packets": 2, "bytes": 500, "packets_rev": 2, "bytes_rev": 900,
                "tcp_flags": {"syn":1,"ack":0,"fin":0,"rst":0,"psh":0,"urg":0},
                "human_summary": "", "risk_score": 0,
                "alerts": [], "extracted_files": [],
                "ja4_fingerprint": "t13d1516h2_8daaf6152771_e5627efa2ab1",
                "tls_sni": "ejemplo.com",
                "interval_stats": {"intervals": 6, "mean_micros": 30000000, "std_micros": 200000}
            }"#,
        );
        assert!(eval(&parse("tls.sni contains \"ejemplo\"").unwrap(), &f));
        assert!(eval(&parse("tls.sni == \"ejemplo.com\"").unwrap(), &f));
        // La huella canónica del spec coincide completa.
        assert!(eval(
            &parse("tls.ja4 == \"t13d1516h2_8daaf6152771_e5627efa2ab1\"").unwrap(),
            &f
        ));
        // Y por prefijo vía contains.
        assert!(eval(
            &parse("tls.ja4 contains \"8daaf6152771\"").unwrap(),
            &f
        ));

        // Beaconing: intervalo medio 30 s, CV ~0.7%.
        assert!(eval(&parse("flow.interval_mean_secs > 29").unwrap(), &f));
        assert!(eval(&parse("flow.interval_cv < 0.01").unwrap(), &f));
        // Flujos sin estadística no coinciden (semántica de campo ausente).
        assert!(!eval(
            &parse("flow.interval_cv < 0.01").unwrap(),
            &crate::tests::flujo_tls()
        ));
    }
}
