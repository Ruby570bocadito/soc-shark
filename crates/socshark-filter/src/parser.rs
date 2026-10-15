//! Parser del DSL: precedencia fija estilo Pratt/precedence-climbing.
//!
//! Precedencias (de menor a mayor): `||` < `&&` < `!` prefijo < comparaciones
//! < primarios (campos, valores, paréntesis). Es un subconjunto deliberado:
//! las comparaciones solo aceptan `campo op valor` (no `valor op campo`),
//! que es la forma natural en tcpdump/Wireshark y simplifica la inferencia
//! de tipos del valor.

use crate::ast::{CmpOp, Expr, FieldPath, Value};
use crate::lexer::{lex, Tok};
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;

/// Error de parseo con posición byte en la entrada original.
#[derive(Debug, Error)]
#[error("error de sintaxis en la posición {pos}: {message}")]
pub struct FilterError {
    pub pos: usize,
    pub message: String,
}

/// Parsea una expresión de filtrado completa (consumiendo todo el input).
pub fn parse(input: &str) -> Result<Expr, FilterError> {
    let toks = lex(input).map_err(|e| FilterError {
        pos: e.pos,
        message: e.message,
    })?;
    let mut p = Parser { toks, pos: 0 };
    let expr = p.parse_or()?;
    if let Some((pos, tok)) = p.peek() {
        return Err(FilterError {
            pos,
            message: format!("token inesperado {tok} tras el final de la expresión"),
        });
    }
    Ok(expr)
}

/// Lado izquierdo de una comparación: campo o (en error) un valor suelto.
enum Prim {
    Path(FieldPath),
    Value(Value),
}

struct Parser {
    toks: Vec<(usize, Tok)>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<(usize, Tok)> {
        self.toks.get(self.pos).cloned()
    }

    fn next(&mut self) -> Option<(usize, Tok)> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek().map(|(_, x)| &x == t).unwrap_or(false) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn err_eof(&self) -> FilterError {
        FilterError {
            pos: usize::MAX,
            message: "fin de la expresión inesperado".into(),
        }
    }

    fn parse_or(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.parse_and()?;
        while self.eat(&Tok::Or) {
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.parse_not()?;
        while self.eat(&Tok::And) {
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, FilterError> {
        if self.eat(&Tok::Not) {
            return Ok(Expr::Not(Box::new(self.parse_not()?)));
        }
        if self.eat(&Tok::LParen) {
            let e = self.parse_or()?;
            if !self.eat(&Tok::RParen) {
                return Err(FilterError {
                    pos: self.peek().map(|(p, _)| p).unwrap_or(usize::MAX),
                    message: "se esperaba ')'".into(),
                });
            }
            return Ok(e);
        }
        self.parse_cmp()
    }

    fn parse_cmp(&mut self) -> Result<Expr, FilterError> {
        let (pos, tok) = self.next().ok_or_else(|| self.err_eof())?;
        let left = match tok {
            Tok::Word(w) => classify_word(&w),
            Tok::Str(s) => Prim::Value(Value::Str(s)),
            other => {
                return Err(FilterError {
                    pos,
                    message: format!("se esperaba un campo, encontrado {other}"),
                })
            }
        };

        let op = match self.peek() {
            Some((_, Tok::Eq)) => Some(CmpOp::Eq),
            Some((_, Tok::Ne)) => Some(CmpOp::Ne),
            Some((_, Tok::Lt)) => Some(CmpOp::Lt),
            Some((_, Tok::Le)) => Some(CmpOp::Le),
            Some((_, Tok::Gt)) => Some(CmpOp::Gt),
            Some((_, Tok::Ge)) => Some(CmpOp::Ge),
            Some((_, Tok::Contains)) => Some(CmpOp::Contains),
            _ => None,
        };

        if let Some(op) = op {
            self.pos += 1; // consumir el operador
            let (vpos, vtok) = self.next().ok_or_else(|| self.err_eof())?;
            let value = match vtok {
                Tok::Word(w) => word_to_value(&w),
                Tok::Str(s) => Value::Str(s),
                other => {
                    return Err(FilterError {
                        pos: vpos,
                        message: format!("se esperaba un valor, encontrado {other}"),
                    })
                }
            };
            match left {
                Prim::Path(path) => Ok(Expr::Cmp { path, op, value }),
                Prim::Value(_) => Err(FilterError {
                    pos,
                    message: "el lado izquierdo debe ser un campo (p. ej. ip.src)".into(),
                }),
            }
        } else {
            // Sin operador: solo un campo booleano tiene sentido.
            match left {
                Prim::Path(path) => Ok(Expr::Truthy(path)),
                Prim::Value(v) => Err(FilterError {
                    pos,
                    message: format!("el valor {v} no es una expresión válida por sí sola"),
                }),
            }
        }
    }
}

/// Clasifica el lado izquierdo: ¿es un valor literal (IP, número) o un campo?
fn classify_word(word: &str) -> Prim {
    if let Some(ip) = parse_ip_literal(word) {
        Prim::Value(Value::Ip(ip))
    } else if !word.is_empty() && word.bytes().all(|b| b.is_ascii_digit()) {
        // Un número suelto no es un campo válido: se marca como valor para
        // que el parser dé un error claro ("el valor 443 no es una
        // expresión válida por sí sola").
        Prim::Value(Value::Num(word.parse::<f64>().unwrap()))
    } else {
        Prim::Path(FieldPath(word.split('.').map(str::to_string).collect()))
    }
}

/// Convierte un lado derecho en valor: IP, booleano, número o cadena.
fn word_to_value(word: &str) -> Value {
    if let Some(ip) = parse_ip_literal(word) {
        return Value::Ip(ip);
    }
    if word == "true" {
        return Value::Bool(true);
    }
    if word == "false" {
        return Value::Bool(false);
    }
    if let Ok(n) = word.parse::<f64>() {
        return Value::Num(n);
    }
    Value::Str(word.to_string())
}

/// Reconoce literales IPv4 (`192.168.1.1`): 4 partes numéricas de 0-255.
fn parse_ip_literal(word: &str) -> Option<IpAddr> {
    let parts: Vec<&str> = word.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        octets[i] = part.parse::<u8>().ok()?;
    }
    Some(IpAddr::V4(Ipv4Addr::from(octets)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ast_de_operadores_anidados() {
        let e = parse("a == 1 || b == 2 && c == 3").unwrap();
        // || en la raíz; && como hijo derecho (precedencia correcta).
        match e {
            Expr::Or(_, right) => assert!(matches!(*right, Expr::And(_, _))),
            other => panic!("AST inesperado: {other:?}"),
        }
    }

    #[test]
    fn ips_literales_vs_campos() {
        let e = parse("ip.src == 192.168.1.1").unwrap();
        match e {
            Expr::Cmp { path, value, .. } => {
                assert_eq!(path.as_str_path(), "ip.src");
                assert!(matches!(value, Value::Ip(IpAddr::V4(_))));
            }
            other => panic!("AST inesperado: {other:?}"),
        }
    }

    #[test]
    fn palabra_sola_es_truthy() {
        let e = parse("flow.noise").unwrap();
        assert!(matches!(e, Expr::Truthy(_)));
    }

    #[test]
    fn valor_solo_es_error() {
        assert!(parse("443").is_err());
        assert!(parse("192.168.1.1").is_err());
    }

    #[test]
    fn ip_mal_formada_no_es_ip() {
        // 999.1.1.1 no cabe en u8: se trata como campo/cadena, no como IP.
        let e = parse("ip.src == 999.1.1.1").unwrap();
        match e {
            Expr::Cmp { value, .. } => assert!(matches!(value, Value::Str(_))),
            other => panic!("AST inesperado: {other:?}"),
        }
    }

    #[test]
    fn parentesis_y_not() {
        let e = parse("!(a == 1 || !(b == 2))").unwrap();
        assert!(matches!(e, Expr::Not(_)));
    }
}
