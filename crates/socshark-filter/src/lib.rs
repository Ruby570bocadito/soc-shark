//! socshark-filter: DSL de filtrado estilo tcpdump con parser por precedencia.
//!
//! Gramática (EBNF simplificada, documento completo en `docs/filter-dsl.md`):
//!
//! ```text
//! expr    := or
//! or      := and ( "||" | "or"  ) and )*
//! and     := not ( "&&" | "and"  ) not )*
//! not     := "!" | "not" , not | cmp | "(" or ")"
//! cmp     := campo op valor | campo
//! valor   := ip | número | booleano | cadena
//! op      := "==" | "!=" | "<" | "<=" | ">" | ">=" | "contains"
//! ```
//!
//! Ejemplos:
//! - `ip.src == 10.0.0.5 && tcp.port == 443`
//! - `dns.qname contains "evil" || flow.risk >= 50`
//! - `!(net.l7 == "DNS") && flow.noise == false`

pub mod ast;
pub mod eval;
pub mod lexer;
pub mod parser;

pub use ast::{CmpOp, Expr, FieldPath, Value};
pub use eval::{eval, get_fields, FieldValue};
pub use lexer::{lex, Tok};
pub use parser::{parse, FilterError};

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_core::{EnrichedFlow, FlowId, FlowState, L7Protocol, Transport};

    /// Flujo TLS de ejemplo para los tests del DSL.
    pub(crate) fn flujo_tls() -> EnrichedFlow {
        EnrichedFlow {
            flow_id: FlowId("tcp/10.0.0.5:52000-93.184.216.34:443".into()),
            state: FlowState::Closed,
            transport: Transport::Tcp,
            ip_version: 4,
            l7_protocol: L7Protocol::Tls,
            src_ip: "10.0.0.5".parse().unwrap(),
            src_port: 52000,
            dst_ip: "93.184.216.34".parse().unwrap(),
            dst_port: 443,
            src_mac: None,
            dst_mac: None,
            first_seen_micros: 1,
            last_seen_micros: 2,
            duration_micros: 1,
            packets: 4,
            bytes: 1200,
            packets_rev: 3,
            bytes_rev: 3000,
            tcp_flags: Default::default(),
            process_name: None,
            pid: None,
            user: None,
            resolved_domain: Some("example.com".into()),
            dns: None,
            dst_geo_asn: None,
            ja4_fingerprint: None,
            is_background_noise: false,
            human_summary: String::new(),
            risk_score: 55,
            alerts: vec![],
            extracted_files: vec![],
        }
    }

    #[test]
    fn evalua_comparaciones_basicas() {
        let f = flujo_tls();
        assert!(eval(&parse("ip.dst == 93.184.216.34").unwrap(), &f));
        assert!(eval(&parse("tcp.port == 443").unwrap(), &f));
        assert!(eval(&parse("sport == 52000").unwrap(), &f));
        assert!(eval(&parse("flow.risk >= 50").unwrap(), &f));
        assert!(!eval(&parse("udp.port == 443").unwrap(), &f));
        assert!(!eval(&parse("ip.src == 93.184.216.34").unwrap(), &f));
    }

    #[test]
    fn operadores_logicos_y_precedencia() {
        let f = flujo_tls();
        // && tiene precedencia sobre ||
        assert!(eval(
            &parse("flow.noise == true || flow.risk >= 50 && ip.dst == 93.184.216.34").unwrap(),
            &f
        ));
        assert!(eval(
            &parse("!(tcp.port == 80) && l7 == \"TLS\"").unwrap(),
            &f
        ));
        assert!(!eval(&parse("!(tcp.port == 443)").unwrap(), &f));
    }

    #[test]
    fn contains_insensible_a_mayusculas() {
        let f = flujo_tls();
        assert!(eval(&parse("domain contains \"EXAMPLE\"").unwrap(), &f));
        assert!(!eval(
            &parse("domain contains \"inexistente\"").unwrap(),
            &f
        ));
    }

    #[test]
    fn ne_es_global_sobre_campos_multi() {
        let f = flujo_tls(); // sport 52000, dport 443
        assert!(eval(&parse("tcp.port != 80").unwrap(), &f));
        assert!(!eval(&parse("tcp.port != 443").unwrap(), &f));
    }

    #[test]
    fn campo_desconocido_no_coincide() {
        let f = flujo_tls();
        assert!(!eval(&parse("campo.inexistente == 1").unwrap(), &f));
    }

    #[test]
    fn errores_de_sintaxis_con_posicion() {
        assert!(parse("ip.src ==").is_err());
        assert!(parse("(a == 1").is_err());
        assert!(parse("a == 1 cola-sobrante").is_err());
    }
}
