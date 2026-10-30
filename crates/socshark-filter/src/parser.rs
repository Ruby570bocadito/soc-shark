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

/// Anidamiento máximo de `(`, `!` y `not`. La recursión del parser, del
/// evaluador y del `Drop` del AST es proporcional a esta profundidad: sin
/// límite, unos miles de `(` desbordaban la pila y abortaban el proceso.
pub const MAX_DEPTH: usize = 128;

/// Número máximo de tokens de una expresión. Acota el tamaño del AST; junto
/// con las cadenas `&&`/`||` construidas como árboles equilibrados (ver
/// `balanced`) mantiene acotada la profundidad total del árbol.
pub const MAX_TOKENS: usize = 4096;

/// Parsea una expresión de filtrado completa (consumiendo todo el input).
pub fn parse(input: &str) -> Result<Expr, FilterError> {
    let toks = lex(input).map_err(|e| FilterError {
        pos: e.pos,
        message: e.message,
    })?;
    if let Some((pos, _)) = toks.get(MAX_TOKENS) {
        return Err(FilterError {
            pos: *pos,
            message: format!("expresión demasiado larga (máximo {MAX_TOKENS} tokens)"),
        });
    }
    let mut p = Parser {
        toks,
        pos: 0,
        end: input.len(),
        depth: 0,
    };
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
    /// Longitud de la entrada: posición que se reporta al faltar tokens.
    end: usize,
    /// Anidamiento actual de `(`/`!`/`not` (ver [`MAX_DEPTH`]).
    depth: usize,
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
            pos: self.end,
            message: "la expresión termina antes de tiempo".into(),
        }
    }

    fn parse_or(&mut self) -> Result<Expr, FilterError> {
        let mut items = vec![self.parse_and()?];
        while self.eat(&Tok::Or) {
            items.push(self.parse_and()?);
        }
        Ok(balanced(items, Expr::Or))
    }

    fn parse_and(&mut self) -> Result<Expr, FilterError> {
        let mut items = vec![self.parse_not()?];
        while self.eat(&Tok::And) {
            items.push(self.parse_not()?);
        }
        Ok(balanced(items, Expr::And))
    }

    /// Entra en un nivel de anidamiento; error si se supera [`MAX_DEPTH`].
    fn enter(&mut self, pos: usize) -> Result<(), FilterError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(FilterError {
                pos,
                message: format!("anidamiento demasiado profundo (máximo {MAX_DEPTH} niveles)"),
            });
        }
        Ok(())
    }

    fn parse_not(&mut self) -> Result<Expr, FilterError> {
        let pos = self.peek().map(|(p, _)| p).unwrap_or(self.end);
        if self.eat(&Tok::Not) {
            self.enter(pos)?;
            let e = Expr::Not(Box::new(self.parse_not()?));
            self.depth -= 1;
            return Ok(e);
        }
        if self.eat(&Tok::LParen) {
            self.enter(pos)?;
            let e = self.parse_or()?;
            if !self.eat(&Tok::RParen) {
                return Err(FilterError {
                    pos: self.peek().map(|(p, _)| p).unwrap_or(self.end),
                    message: "se esperaba ')'".into(),
                });
            }
            self.depth -= 1;
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

/// Combina una cadena `a op b op c ...` en un árbol binario equilibrado en
/// lugar de uno sesgado a la izquierda: `&&` y `||` son asociativos y el
/// recorrido en orden (y por tanto el cortocircuito de izquierda a derecha)
/// se conserva, pero la profundidad pasa de O(n) a O(log n), de modo que
/// `eval` y el `Drop` recursivo del AST no desbordan la pila.
fn balanced(mut items: Vec<Expr>, mk: fn(Box<Expr>, Box<Expr>) -> Expr) -> Expr {
    if items.len() == 1 {
        return items.pop().expect("al menos un operando");
    }
    let right = items.split_off(items.len() / 2);
    mk(Box::new(balanced(items, mk)), Box::new(balanced(right, mk)))
}

/// Número según la gramática documentada: `digit+` con parte decimal
/// opcional (`0.01`). Rechaza lo que `f64::parse` aceptaría de más
/// (`inf`, `nan`, `1e3`, `.5`, `+1`), que se tratan como cadenas.
pub(crate) fn parse_number(word: &str) -> Option<f64> {
    let (int, frac) = match word.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (word, None),
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(int) || !frac.map(digits).unwrap_or(true) {
        return None;
    }
    word.parse::<f64>().ok()
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
    if let Some(n) = parse_number(word) {
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
    fn numeros_segun_la_gramatica() {
        let valor = |src: &str| match parse(&format!("flow.risk == {src}")).unwrap() {
            Expr::Cmp { value, .. } => value,
            other => panic!("AST inesperado: {other:?}"),
        };
        assert_eq!(valor("443"), Value::Num(443.0));
        assert_eq!(valor("0.01"), Value::Num(0.01));
        // Lo que f64::parse aceptaría de más se queda como cadena.
        for raro in ["inf", "nan", "NaN", "infinity", "1e3", "1.", "1.2.3"] {
            assert_eq!(valor(raro), Value::Str(raro.into()), "{raro}");
        }
        assert!(parse_number(".5").is_none());
    }

    #[test]
    fn anidamiento_excesivo_es_error_normal() {
        // Antes ~2000 '(' desbordaban la pila y abortaban el proceso.
        let profundo = format!("{}a == 1{}", "(".repeat(2000), ")".repeat(2000));
        let e = parse(&profundo).unwrap_err();
        assert_eq!(e.pos, MAX_DEPTH);
        assert!(e.message.contains("anidamiento"));
        assert!(parse(&format!("{}a", "!".repeat(2000))).is_err());
        assert!(parse(&format!("{}a", "not ".repeat(1000))).is_err());
        // Justo en el límite sigue funcionando.
        let ok = format!("{}a == 1{}", "(".repeat(MAX_DEPTH), ")".repeat(MAX_DEPTH));
        assert!(parse(&ok).is_ok());
    }

    #[test]
    fn expresion_demasiado_larga_es_error() {
        let larga = vec!["a"; 3000].join(" || ");
        let e = parse(&larga).unwrap_err();
        assert!(e.message.contains("demasiado larga"));
    }

    #[test]
    fn cadenas_largas_son_arboles_equilibrados() {
        fn prof(e: &Expr) -> usize {
            match e {
                Expr::Or(a, b) | Expr::And(a, b) => 1 + prof(a).max(prof(b)),
                Expr::Not(a) => 1 + prof(a),
                _ => 1,
            }
        }
        let cadena = vec!["a"; 2000].join(" && ");
        let e = parse(&cadena).unwrap();
        assert!(prof(&e) <= 12, "profundidad {}", prof(&e));
    }

    #[test]
    fn peor_caso_cabe_en_una_pila_pequena() {
        // Máximo anidamiento con cadenas en cada nivel, parseado, evaluado
        // y destruido en un hilo de 512 KiB (el principal de Windows tiene
        // 1 MiB): demuestra que los límites acotan toda la recursión.
        let mut src = String::from("a == 1");
        // Cada "!(" suma dos niveles.
        for _ in 0..MAX_DEPTH / 2 {
            src = format!("!(a == 1 || b == 2 || {src})");
        }
        std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(move || {
                let e = parse(&src).unwrap();
                let f = crate::tests::flujo_tls();
                let _ = crate::eval(&e, &f);
                drop(e);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn parentesis_y_not() {
        let e = parse("!(a == 1 || !(b == 2))").unwrap();
        assert!(matches!(e, Expr::Not(_)));
    }
}
