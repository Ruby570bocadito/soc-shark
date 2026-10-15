//! Biblioteca del daemon de soc-shark: pipeline de análisis, puente del DSL
//! y render de salida. El binario `soc-shark` (main.rs) es una capa fina
//! sobre esto, y los tests de integración ejercitan la misma ruta que la CLI.

pub mod bridge;
pub mod output;
pub mod pipeline;
