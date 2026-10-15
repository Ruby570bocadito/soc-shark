//! Máquina de evaluación del DSL sobre cualquier fuente de hechos.
//!
//! El trait [`FactSource`] invierte la dependencia: `filter-dsl` no conoce
//! los tipos `DissectedPacket`/`EnrichedFlow`; las implementaciones viven en
//! el daemon (`daemon/src/bridge.rs`), que mapea nombres de campo a valores.

use crate::parser::{CmpOp, Expr, Val};
use socshark_common::ipaddr::IpAddr;

/// Fuente de hechos: resuelve un nombre de campo punteado a un valor.
pub trait FactSource {
    /// `None` = campo no aplicable a este paquete/flujo (comparación falsa).
    fn fact(&self, field: &str) -> Option<Val>;

    /// ¿Existe el campo aunque el valor esté ausente? (para `soc-shark fields`)
    fn has_field(&self, _field: &str) -> bool {
        false
    }
}

/// Evalúa el AST contra una fuente de hechos.
pub fn eval(expr: &Expr, src: &dyn FactSource) -> bool {
    match expr {
        Expr::Cmp { field, op, val } => eval_cmp(src.fact(field).as_ref(), *op, val),
        Expr::Bare(field) => match src.fact(field) {
            Some(Val::Bool(b)) => b,
            Some(_) => true, // el campo existe (semántica Wireshark)
            None => false,
        },
        Expr::And(a, b) => eval(a, src) && eval(b, src),
        Expr::Or(a, b) => eval(a, src) || eval(b, src),
        Expr::Not(inner) => !eval(inner, src),
    }
}

fn eval_cmp(fact: Option<&Val>, op: CmpOp, rhs: &Val) -> bool {
    let Some(lhs) = fact else {
        // Campo ausente → comparación falsa (excepto != que Wireshark también
        // trata como falsa con campo ausente; mantenemos esa semántica).
        return false;
    };
    match op {
        CmpOp::Eq => eq(lhs, rhs),
        CmpOp::Ne => !eq(lhs, rhs),
        CmpOp::Gt => cmp(lhs, rhs) == Some(std::cmp::Ordering::Greater),
        CmpOp::Ge => {
            matches!(
                cmp(lhs, rhs),
                Some(std::cmp::Ordering::Greater) | Some(std::cmp::Ordering::Equal)
            )
        }
        CmpOp::Lt => cmp(lhs, rhs) == Some(std::cmp::Ordering::Less),
        CmpOp::Le => {
            matches!(
                cmp(lhs, rhs),
                Some(std::cmp::Ordering::Less) | Some(std::cmp::Ordering::Equal)
            )
        }
        CmpOp::Contains => match (lhs, rhs) {
            (Val::Str(a), Val::Str(b)) => a.contains(b.as_str()),
            (Val::Str(a), other) => a.contains(&val_to_string(other)),
            _ => false,
        },
    }
}

fn eq(a: &Val, b: &Val) -> bool {
    match (a, b) {
        (Val::Int(x), Val::Int(y)) => x == y,
        (Val::Float(x), Val::Float(y)) => x == y,
        (Val::Int(x), Val::Float(y)) | (Val::Float(y), Val::Int(x)) => (*x as f64) == *y,
        (Val::Str(x), Val::Str(y)) => x.eq_ignore_ascii_case(y),
        (Val::Bool(x), Val::Bool(y)) => x == y,
        (Val::Ip(x), Val::Ip(y)) => x == y,
        // Cadena vs IP: compara por forma textual.
        (Val::Str(x), Val::Ip(y)) | (Val::Ip(y), Val::Str(x)) => {
            IpAddr::parse(x).map(|p| p == *y).unwrap_or(false)
        }
        _ => false,
    }
}

/// Orden total para <, >, <=, >=: numérico si ambos son números; strings
/// lexicográficos en caso contrario.
fn cmp(a: &Val, b: &Val) -> Option<std::cmp::Ordering> {
    let num = |v: &Val| -> Option<f64> {
        match v {
            Val::Int(i) => Some(*i as f64),
            Val::Float(f) => Some(*f),
            Val::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            _ => None,
        }
    };
    match (num(a), num(b)) {
        (Some(x), Some(y)) => x.partial_cmp(&y),
        _ => {
            let sa = val_to_string(a);
            let sb = val_to_string(b);
            sa.partial_cmp(&sb)
        }
    }
}

fn val_to_string(v: &Val) -> String {
    match v {
        Val::Int(i) => i.to_string(),
        Val::Float(f) => f.to_string(),
        Val::Str(s) => s.clone(),
        Val::Ip(ip) => ip.to_string(),
        Val::Bool(b) => b.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;
    use std::collections::HashMap;

    struct MapSrc(HashMap<String, Val>);
    impl FactSource for MapSrc {
        fn fact(&self, field: &str) -> Option<Val> {
            self.0.get(field).cloned()
        }
    }

    fn src(pairs: &[(&str, Val)]) -> MapSrc {
        MapSrc(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        )
    }

    #[test]
    fn comparaciones_numericas() {
        let s = src(&[("flow.risk", Val::Int(45))]);
        assert!(eval(&parse("flow.risk >= 30").unwrap(), &s));
        assert!(eval(&parse("flow.risk > 44.5").unwrap(), &s));
        assert!(!eval(&parse("flow.risk > 45").unwrap(), &s));
        assert!(eval(&parse("flow.risk != 0").unwrap(), &s));
    }

    #[test]
    fn coercion_y_orden_lexico() {
        let s = src(&[("dns.qname", Val::Str("bbb.evil.ru".into()))]);
        assert!(eval(&parse("dns.qname < ccc").unwrap(), &s));
        assert!(eval(&parse("dns.qname == BBB.EVIL.RU").unwrap(), &s)); // case-insensitive
    }

    #[test]
    fn campos_ausentes_en_operadores() {
        let s = src(&[]);
        assert!(!eval(&parse("noexiste == 1").unwrap(), &s));
        assert!(!eval(&parse("noexiste != 1").unwrap(), &s));
        assert!(!eval(&parse("noexiste >= 1").unwrap(), &s));
    }

    #[test]
    fn contains_case_sensitive() {
        let s = src(&[("http.target", Val::Str("/gate.php?x=1".into()))]);
        assert!(eval(&parse("http.target contains gate.php").unwrap(), &s));
        assert!(!eval(&parse("http.target contains GATE").unwrap(), &s));
    }
}
