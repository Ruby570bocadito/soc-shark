//! socshark-cli: librería del binario `socshark`.
//!
//! El binario es una cáscara fina sobre esta librería para que los tests de
//! integración puedan ejecutar el pipeline completo sin `std::process` (más
//! rápido, más depurable, mismas rutas de código).

pub mod cli;
pub mod daemon;
pub mod follow;
pub mod fuzz;
pub mod gui;
pub mod output;
pub mod pipeline;
pub mod tui;
