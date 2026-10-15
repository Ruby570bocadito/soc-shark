//! AST y valores del DSL de filtrado.

use std::fmt;
use std::net::IpAddr;

/// Ruta de campo punteada, p. ej. `ip.src` o `tcp.flags.syn`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldPath(pub Vec<String>);

impl FieldPath {
    /// El path como cadena unida por puntos.
    pub fn as_str_path(&self) -> String {
        self.0.join(".")
    }
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join("."))
    }
}

/// Valor literal del DSL.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Num(f64),
    Str(String),
    Ip(IpAddr),
    Bool(bool),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Num(n) => write!(f, "{n}"),
            Value::Str(s) => write!(f, "\"{s}\""),
            Value::Ip(ip) => write!(f, "{ip}"),
            Value::Bool(b) => write!(f, "{b}"),
        }
    }
}

/// Operadores de comparación soportados.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    /// Subcadena, insensible a mayúsculas (pensado para qnames y dominios).
    Contains,
}

/// Árbol de sintaxis de una expresión de filtrado.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    /// `campo op valor`.
    Cmp {
        path: FieldPath,
        op: CmpOp,
        value: Value,
    },
    /// Campo booleano usado sin comparación: `flow.noise`.
    Truthy(FieldPath),
}
