//! Tokenizador del DSL de filtrado.
//!
//! - Palabras: `[A-Za-z0-9_.]+` (campos, IPs, números y booleanos se
//!   clasifican en el parser).
//! - Cadenas: entre comillas simples o dobles, con escapes `\n`, `\t`, `\\`,
//!   `\'` y `\"`.
//! - Operadores de dos caracteres primero: `==`, `!=`, `<=`, `>=`, `&&`, `||`.
//! - Palabras clave: `and`, `or`, `not`, `contains` (en minúsculas).
//! - Comentarios: de `#` a fin de línea.

use std::fmt;
use thiserror::Error;

/// Token del DSL.
#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    /// Palabra: campo (`ip.src`), IP (`10.0.0.1`), número (`443`) o booleano.
    Word(String),
    /// Cadena entre comillas.
    Str(String),
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Not,
    Contains,
    LParen,
    RParen,
}

/// Error léxico con posición.
#[derive(Debug, Error)]
#[error("error léxico en la posición {pos}: {message}")]
pub struct LexError {
    pub pos: usize,
    pub message: String,
}

/// Tokeniza la entrada con su posición (en bytes) para mensajes de error útiles.
pub fn lex(input: &str) -> Result<Vec<(usize, Tok)>, LexError> {
    let bytes = input.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'(' => {
                toks.push((i, Tok::LParen));
                i += 1;
            }
            b')' => {
                toks.push((i, Tok::RParen));
                i += 1;
            }
            b'"' | b'\'' => {
                let (tok, next) = lex_string(input, i)?;
                toks.push((i, tok));
                i = next;
            }
            b'&' => {
                if bytes.get(i + 1) == Some(&b'&') {
                    toks.push((i, Tok::And));
                    i += 2;
                } else {
                    return Err(err(i, "se esperaba '&&' (un solo '&' no es válido)"));
                }
            }
            b'|' => {
                if bytes.get(i + 1) == Some(&b'|') {
                    toks.push((i, Tok::Or));
                    i += 2;
                } else {
                    return Err(err(i, "se esperaba '||' (un solo '|' no es válido)"));
                }
            }
            b'!' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    toks.push((i, Tok::Ne));
                    i += 2;
                } else {
                    toks.push((i, Tok::Not));
                    i += 1;
                }
            }
            b'=' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    toks.push((i, Tok::Eq));
                    i += 2;
                } else {
                    toks.push((i, Tok::Eq)); // '=' simple aceptado como '=='
                    i += 1;
                }
            }
            b'<' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    toks.push((i, Tok::Le));
                    i += 2;
                } else {
                    toks.push((i, Tok::Lt));
                    i += 1;
                }
            }
            b'>' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    toks.push((i, Tok::Ge));
                    i += 2;
                } else {
                    toks.push((i, Tok::Gt));
                    i += 1;
                }
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.' => {
                let start = i;
                while i < bytes.len() && is_word_byte(bytes[i]) {
                    i += 1;
                }
                let word = &input[start..i];
                let tok = match word {
                    "and" => Tok::And,
                    "or" => Tok::Or,
                    "not" => Tok::Not,
                    "contains" => Tok::Contains,
                    _ => Tok::Word(word.to_string()),
                };
                toks.push((start, tok));
            }
            other => {
                return Err(err(i, format!("carácter inesperado '{}'", other as char)));
            }
        }
    }
    Ok(toks)
}

fn is_word_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.')
}

fn lex_string(input: &str, start: usize) -> Result<(Tok, usize), LexError> {
    let bytes = input.as_bytes();
    let quote = bytes[start];
    let mut i = start + 1;
    let mut out = Vec::new();
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' {
            let Some(&esc) = bytes.get(i + 1) else {
                return Err(err(i, "escape incompleto al final de la cadena"));
            };
            out.push(match esc {
                b'n' => b'\n',
                b't' => b'\t',
                other => other,
            });
            i += 2;
        } else if c == quote {
            let s = String::from_utf8_lossy(&out).into_owned();
            return Ok((Tok::Str(s), i + 1));
        } else {
            out.push(c);
            i += 1;
        }
    }
    Err(err(start, "cadena sin cerrar"))
}

fn err(pos: usize, message: impl Into<String>) -> LexError {
    LexError {
        pos,
        message: message.into(),
    }
}

impl fmt::Display for Tok {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tok::Word(w) => write!(f, "palabra '{w}'"),
            Tok::Str(s) => write!(f, "cadena \"{s}\""),
            Tok::Eq => f.write_str("'=='"),
            Tok::Ne => f.write_str("'!='"),
            Tok::Lt => f.write_str("'<'"),
            Tok::Le => f.write_str("'<='"),
            Tok::Gt => f.write_str("'>'"),
            Tok::Ge => f.write_str("'>='"),
            Tok::And => f.write_str("'&&'"),
            Tok::Or => f.write_str("'||'"),
            Tok::Not => f.write_str("'!'"),
            Tok::Contains => f.write_str("'contains'"),
            Tok::LParen => f.write_str("'('"),
            Tok::RParen => f.write_str("')'"),
        }
    }
}
