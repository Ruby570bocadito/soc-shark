//! Pratt parser: tokens → AST.
//!
//! Precedencias (de menor a mayor):
//! `or`/`||` (1) < `and`/`&&` (2) < unario `not`/`!` (3) < comparaciones (4).
//!
//! Una comparación es siempre `campo op valor` (el campo va a la izquierda,
//! como en Wireshark).

use crate::lexer::Tok;
use socshark_common::ipaddr::IpAddr;

/// Operador de comparación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Contains,
}

/// Valor literal del lado derecho.
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    Int(i64),
    Float(f64),
    Str(String),
    Ip(IpAddr),
    Bool(bool),
}

/// Árbol de expresión.
#[derive(Debug, Clone)]
pub enum Expr {
    /// `campo op valor`.
    Cmp {
        field: String,
        op: CmpOp,
        val: Val,
    },
    /// `campo` a secas: verdad si existe y (si es bool) es true — estilo
    /// Wireshark (`tcp.flags.syn and not flow.noise`).
    Bare(String),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

/// Parsea una expresión completa; error con mensaje amigable.
pub fn parse(input: &str) -> Result<Expr, String> {
    let toks = crate::lexer::lex(input)?;
    if toks.is_empty() {
        return Err("expresión vacía".into());
    }
    let mut p = Parser { toks, pos: 0 };
    let e = p.parse_or()?;
    if p.pos < p.toks.len() {
        return Err(format!(
            "tokens sobrantes después de la expresión (col. {}/{}): {:?}",
            p.pos,
            p.toks.len(),
            p.toks[p.pos]
        ));
    }
    Ok(e)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn word_is(&self, kw: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word(w)) if w.eq_ignore_ascii_case(kw))
    }

    fn advance(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    // or (bp=1)
    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and()?;
        loop {
            if self.word_is("or") || matches!(self.peek(), Some(Tok::Op2("||"))) {
                self.advance();
                let right = self.parse_and()?;
                left = Expr::Or(Box::new(left), Box::new(right));
            } else {
                return Ok(left);
            }
        }
    }

    // and (bp=2)
    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_unary()?;
        loop {
            if self.word_is("and") || matches!(self.peek(), Some(Tok::Op2("&&"))) {
                self.advance();
                let right = self.parse_unary()?;
                left = Expr::And(Box::new(left), Box::new(right));
            } else {
                return Ok(left);
            }
        }
    }

    // not (bp=3, unario)
    fn parse_unary(&mut self) -> Result<Expr, String> {
        if self.word_is("not") || matches!(self.peek(), Some(Tok::Op1('!'))) {
            self.advance();
            let inner = self.parse_unary()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_cmp()
    }

    // comparaciones (bp=4): campo op valor — o paréntesis
    fn parse_cmp(&mut self) -> Result<Expr, String> {
        if matches!(self.peek(), Some(Tok::Op1('('))) {
            self.advance();
            let inner = self.parse_or()?;
            match self.advance() {
                Some(Tok::Op1(')')) => {}
                other => return Err(format!("se esperaba ')', encontrado {other:?}")),
            }
            return Ok(inner);
        }
        let field = match self.advance() {
            Some(Tok::Word(w)) => w,
            other => return Err(format!("se esperaba un campo, encontrado {other:?}")),
        };
        // Campo a secas: si lo que sigue no es un operador de comparación,
        // lo tratamos como booleano (`flow.has_alert and ...`).
        let is_op = matches!(
            self.peek(),
            Some(Tok::Op2("=="))
                | Some(Tok::Op2("!="))
                | Some(Tok::Op2(">="))
                | Some(Tok::Op2("<="))
                | Some(Tok::Op1('>'))
                | Some(Tok::Op1('<'))
        ) || matches!(self.peek(), Some(Tok::Word(w)) if w.eq_ignore_ascii_case("contains"));
        if !is_op {
            return Ok(Expr::Bare(field));
        }
        let op = match self.peek() {
            Some(Tok::Op2("==")) => CmpOp::Eq,
            Some(Tok::Op2("!=")) => CmpOp::Ne,
            Some(Tok::Op2(">=")) => CmpOp::Ge,
            Some(Tok::Op2("<=")) => CmpOp::Le,
            Some(Tok::Op1('>')) => CmpOp::Gt,
            Some(Tok::Op1('<')) => CmpOp::Lt,
            Some(Tok::Word(w)) if w.eq_ignore_ascii_case("contains") => CmpOp::Contains,
            other => {
                return Err(format!(
                    "se esperaba un operador tras '{field}', encontrado {other:?}"
                ))
            }
        };
        self.advance();
        let val = self.parse_value()?;
        Ok(Expr::Cmp { field, op, val })
    }

    fn parse_value(&mut self) -> Result<Val, String> {
        match self.advance() {
            Some(Tok::Int(i)) => Ok(Val::Int(i)),
            Some(Tok::Float(f)) => Ok(Val::Float(f)),
            Some(Tok::Str(s)) => Ok(Val::Str(s)),
            Some(Tok::Word(w)) => {
                if w.eq_ignore_ascii_case("true") {
                    Ok(Val::Bool(true))
                } else if w.eq_ignore_ascii_case("false") {
                    Ok(Val::Bool(false))
                } else if w.contains('.')
                    && w.split('.')
                        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                {
                    // Segmentos numéricos punteados = IP (v4 o v6 inexistente → error)
                    IpAddr::parse(&w)
                        .map(Val::Ip)
                        .ok_or_else(|| format!("IP inválida: {w}"))
                } else {
                    // Palabra suelta: cadena implícita (proc.name == curl)
                    Ok(Val::Str(w))
                }
            }
            other => Err(format!("se esperaba un valor, encontrado {other:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{eval, FactSource};
    use std::collections::HashMap;

    fn src(pairs: &[(&str, Val)]) -> MapSrc {
        MapSrc(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        )
    }

    struct MapSrc(HashMap<String, Val>);
    impl FactSource for MapSrc {
        fn fact(&self, field: &str) -> Option<Val> {
            self.0.get(field).cloned()
        }
    }

    fn v_ip(s: &str) -> Val {
        Val::Ip(IpAddr::parse(s).unwrap())
    }

    #[test]
    fn precedencia_and_or() {
        // a==1 or b==2 and c==3 → a==1 or (b==2 and c==3)
        let e = parse("a == 1 or b == 2 and c == 3").unwrap();
        let s = src(&[
            ("a", Val::Int(1)),
            ("b", Val::Int(9)), // b != 2
            ("c", Val::Int(3)),
        ]);
        // or con rama derecha falsa → true por a
        assert!(eval(&e, &s));
        let s2 = src(&[("a", Val::Int(9)), ("b", Val::Int(2)), ("c", Val::Int(3))]);
        assert!(eval(&e, &s2));
        let s3 = src(&[("a", Val::Int(9)), ("b", Val::Int(2)), ("c", Val::Int(9))]);
        assert!(!eval(&e, &s3));
    }

    #[test]
    fn parentesis_y_not() {
        let e = parse("not (a == 1 and b == 2)").unwrap();
        let s = src(&[("a", Val::Int(1)), ("b", Val::Int(9))]);
        assert!(eval(&e, &s));
        let s2 = src(&[("a", Val::Int(1)), ("b", Val::Int(2))]);
        assert!(!eval(&e, &s2));
    }

    #[test]
    fn campos_ausentes_son_falsos() {
        let e = parse("x == 1").unwrap();
        let s = src(&[]);
        assert!(!eval(&e, &s));
        // not sobre comparación falsa → true (semántica Wireshark-like)
        let e2 = parse("not x == 1").unwrap();
        assert!(eval(&e2, &s));
    }

    #[test]
    fn ips_strings_y_contains() {
        let s = src(&[
            ("ip.src", v_ip("192.168.1.50")),
            ("dns.qname", Val::Str("beacon.evil.ru".into())),
        ]);
        assert!(eval(&parse("ip.src == 192.168.1.50").unwrap(), &s));
        assert!(!eval(&parse("ip.src == 10.0.0.1").unwrap(), &s));
        assert!(eval(&parse("dns.qname contains evil").unwrap(), &s));
    }

    #[test]
    fn campos_a_secas_son_booleanos() {
        let e = parse("flow.has_alert and not flow.noise").unwrap();
        let s1 = src(&[
            ("flow.has_alert", Val::Bool(true)),
            ("flow.noise", Val::Bool(false)),
        ]);
        assert!(eval(&e, &s1));
        let s2 = src(&[
            ("flow.has_alert", Val::Bool(true)),
            ("flow.noise", Val::Bool(true)),
        ]);
        assert!(!eval(&e, &s2));
        let s3 = src(&[("flow.noise", Val::Bool(false))]); // has_alert ausente
        assert!(!eval(&e, &s3));
        // Campo no-bool existente a secas → true.
        let s4 = src(&[("http.target", Val::Str("/x".into()))]);
        assert!(eval(&parse("http.target").unwrap(), &s4));
    }

    #[test]
    fn errores_de_sintaxis() {
        assert!(parse("").is_err());
        assert!(parse("a ==").is_err());
        assert!(parse("== 1").is_err());
        assert!(parse("(a == 1").is_err());
        assert!(parse("a == 1 basura").is_err());
        assert!(parse("a == 192.168.1").is_err()); // IP incompleta
    }
}
