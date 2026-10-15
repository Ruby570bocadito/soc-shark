//! Tokenizador de la barra de búsqueda.

/// Token léxico.
#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    /// Identificador con puntos: campo (`ip.src`) o palabra (`and`, `true`,
    /// `curl`, o IP literal `192.168.1.1`).
    Word(String),
    /// Número entero.
    Int(i64),
    /// Número decimal.
    Float(f64),
    /// Cadena entre comillas simples o dobles.
    Str(String),
    /// Operador/puntuación de 2 bytes.
    Op2(&'static str),
    /// Operador/puntuación de 1 byte.
    Op1(char),
}

/// Tokeniza la expresión; devuelve error con posición si hay comillas sin
/// cerrar o caracteres inválidos.
pub fn lex(input: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        // Cadenas
        if c == '"' || c == '\'' {
            let quote = c;
            let mut s = String::new();
            i += 1;
            let mut closed = false;
            while i < chars.len() {
                let ch = chars[i];
                if ch == '\\' && i + 1 < chars.len() {
                    let nxt = chars[i + 1];
                    s.push(match nxt {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        other => other,
                    });
                    i += 2;
                    continue;
                }
                if ch == quote {
                    closed = true;
                    i += 1;
                    break;
                }
                s.push(ch);
                i += 1;
            }
            if !closed {
                return Err(format!("cadena sin cerrar empezando en col. {i}"));
            }
            out.push(Tok::Str(s));
            continue;
        }
        // Números (incluye negativos adyacentes a dígitos)
        if c.is_ascii_digit() {
            let start = i;
            let mut is_float = false;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                if chars[i] == '.' {
                    // No confundir con campo 1.2.3.4: si el siguiente char no
                    // es dígito, termina el número.
                    if i + 1 < chars.len() && !chars[i + 1].is_ascii_digit() {
                        break;
                    }
                    is_float = true;
                }
                i += 1;
            }
            let text: String = chars[start..i].iter().collect();
            let parsed = if is_float {
                text.parse::<f64>().ok().map(Tok::Float)
            } else {
                text.parse::<i64>().ok().map(Tok::Int)
            };
            if let Some(t) = parsed {
                out.push(t);
            } else {
                // Literal IPv4 (192.168.1.50) u otro token con puntos: palabra.
                while i < chars.len()
                    && (chars[i].is_alphanumeric() || matches!(chars[i], '_' | '.' | '-'))
                {
                    i += 1;
                }
                out.push(Tok::Word(chars[start..i].iter().collect()));
            }
            continue;
        }
        // Identificadores/palabras: letras, dígitos, _ y . (campos punteados)
        if c.is_alphanumeric() || c == '_' || c == '.' || c == '-' {
            let start = i;
            while i < chars.len()
                && (chars[i].is_alphanumeric()
                    || chars[i] == '_'
                    || chars[i] == '.'
                    || chars[i] == '-')
            {
                i += 1;
            }
            let w: String = chars[start..i].iter().collect();
            // `1.2.3.4` empiza por dígito pero tiene ≥2 puntos: palabra (IP).
            out.push(Tok::Word(w));
            continue;
        }
        // Operadores de 2 caracteres
        if i + 1 < chars.len() {
            let two: String = chars[i..i + 2].iter().collect();
            let op2 = match two.as_str() {
                "==" | "!=" | ">=" | "<=" | "&&" | "||" => Some(two),
                _ => None,
            };
            if let Some(op) = op2 {
                out.push(Tok::Op2(Box::leak(op.into_boxed_str())));
                i += 2;
                continue;
            }
        }
        // Operadores de 1 carácter
        match c {
            '>' | '<' | '(' | ')' | '!' | ',' => out.push(Tok::Op1(c)),
            other => return Err(format!("carácter inesperado {other:?} en col. {i}")),
        }
        i += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokeniza_expresion_completa() {
        let toks = lex("ip.src == 192.168.1.50 && tcp.port >= 443 or not flow.noise").unwrap();
        assert_eq!(
            toks,
            vec![
                Tok::Word("ip.src".into()),
                Tok::Op2("=="),
                Tok::Word("192.168.1.50".into()),
                Tok::Op2("&&"),
                Tok::Word("tcp.port".into()),
                Tok::Op2(">="),
                Tok::Int(443),
                Tok::Word("or".into()),
                Tok::Word("not".into()),
                Tok::Word("flow.noise".into()),
            ]
        );
    }

    #[test]
    fn numeros_cadenas_y_errores() {
        assert_eq!(lex("42").unwrap()[0], Tok::Int(42));
        assert_eq!(lex("3.14").unwrap()[0], Tok::Float(3.14));
        assert_eq!(
            lex("\"hola 'mundo'\"").unwrap()[0],
            Tok::Str("hola 'mundo'".into())
        );
        assert_eq!(lex("'a\\nb'").unwrap()[0], Tok::Str("a\nb".into()));
        assert!(lex("\"sin cerrar").is_err());
        assert!(lex("a @ b").is_err());
    }
}
