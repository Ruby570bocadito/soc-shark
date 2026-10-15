//! Motor de consultas de soc-shark.
//!
//! Lenguaje estilo Wireshark en un subconjunto pragmático:
//!
//! ```text
//! tcp.port == 443 and (http.method == "POST" or dns.qname contains "evil")
//! ip.src == 192.168.1.50 && flow.risk >= 30
//! not flow.noise
//! ```
//!
//! - [`lexer`]: tokeniza la barra de búsqueda.
//! - [`parser`]: Pratt parser → AST ([`Expr`]).
//! - [`vm`]: evaluador sobre cualquier [`FactSource`] (paquete o flujo).
//! - [`registry`]: catálogo de campos para autocompletado y `soc-shark fields`.
//!
//! Semántica: un campo ausente hace que la comparación sea `false` (como
//! Wireshark); `not` invierte el resultado de la comparación.

pub mod lexer;
pub mod parser;
pub mod registry;
pub mod vm;

pub use parser::{parse, CmpOp, Expr, Val};
pub use vm::{eval, FactSource};

/// Parsea y evalúa de un tirón (atajo para el daemon).
pub fn matches(src: &dyn FactSource, expression: &str) -> Result<bool, String> {
    let expr = parse(expression)?;
    Ok(eval(&expr, src))
}
