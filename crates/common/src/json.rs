//! Serializador JSON de escritura (sin parseo), std-only.
//!
//! Suficiente para toda la fase 1: informes del daemon, exportación ECS para
//! SIEM y líneas de eventos. El parseo JSON llegará con la API IPC (fase 2/4),
//! donde probablemente se justifique introducir `serde_json` (ver ADR-0001).

use std::fmt::Write as _;

/// Valor JSON construible.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Atajo para `Json::Str`.
    pub fn s(v: impl Into<String>) -> Json {
        Json::Str(v.into())
    }

    /// Atajo para construir objetos: `Json::obj(&[("k", v), ...])`.
    pub fn obj(pairs: Vec<(&str, Json)>) -> Json {
        Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    /// Busca una clave en el objeto (útil para tests).
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Serialización compacta.
    pub fn to_string(&self) -> String {
        let mut out = String::with_capacity(256);
        self.write(&mut out, false, 0);
        out
    }

    /// Serialización con sangría de 2 espacios.
    pub fn to_pretty(&self) -> String {
        let mut out = String::with_capacity(1024);
        self.write(&mut out, true, 0);
        out
    }

    pub fn write(&self, out: &mut String, pretty: bool, indent: usize) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(i) => {
                let _ = write!(out, "{i}");
            }
            Json::Num(f) => {
                if f.is_finite() {
                    if f.fract() == 0.0 && f.abs() < 1e15 {
                        let _ = write!(out, "{}", *f as i64);
                    } else {
                        let _ = write!(out, "{f}");
                    }
                } else {
                    out.push_str("null");
                }
            }
            Json::Str(s) => {
                out.push('"');
                escape_into(s, out);
                out.push('"');
            }
            Json::Arr(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    if pretty {
                        out.push('\n');
                        out.push_str(&"  ".repeat(indent + 1));
                    }
                    item.write(out, pretty, indent + 1);
                }
                if pretty {
                    out.push('\n');
                    out.push_str(&"  ".repeat(indent));
                }
                out.push(']');
            }
            Json::Obj(pairs) => {
                if pairs.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push('{');
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    if pretty {
                        out.push('\n');
                        out.push_str(&"  ".repeat(indent + 1));
                    }
                    out.push('"');
                    escape_into(k, out);
                    out.push_str("\":");
                    if pretty {
                        out.push(' ');
                    }
                    v.write(out, pretty, indent + 1);
                }
                if pretty {
                    out.push('\n');
                    out.push_str(&"  ".repeat(indent));
                }
                out.push('}');
            }
        }
    }
}

/// Escapa una cadena para inclusión segura dentro de un literal JSON.
pub fn escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializa_objetos_compactos() {
        let v = Json::obj(vec![
            ("n", Json::Int(42)),
            ("f", Json::Num(1.5)),
            ("s", Json::s("a\"b\n")),
            ("arr", Json::Arr(vec![Json::Bool(true), Json::Null])),
        ]);
        assert_eq!(
            v.to_string(),
            r#"{"n":42,"f":1.5,"s":"a\"b\n","arr":[true,null]}"#
        );
    }

    #[test]
    fn escapa_caracteres_de_control() {
        let mut out = String::new();
        escape_into("\u{01}\u{1f}", &mut out);
        assert_eq!(out, "\\u0001\\u001f");
    }

    #[test]
    fn anidados_y_pretty() {
        let v = Json::obj(vec![(
            "a",
            Json::Arr(vec![Json::obj(vec![("b", Json::Int(1))])]),
        )]);
        let p = v.to_pretty();
        assert!(p.contains("\"b\": 1"), "{p}");
        assert!(v.get("a").is_some());
    }
}
