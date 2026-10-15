//! Gestión de memoria y disco para soc-shark (fase 1).
//!
//! - [`index`]: `CaptureIndex` — offset, timestamp y tamaño de cada paquete,
//!   construido en un solo barrido. Permite acceso aleatorio O(1) y es la
//!   base del virtual scrolling de la UI (fase 4).
//! - [`session_db`]: estadísticas agregadas estilo columnar (por protocolo,
//!   por segundo, top talkers por tamaño).
//! - [`mmap_store`]: diseño del store mmap que llegará en fase 2.

pub mod index;
pub mod mmap_store;
pub mod session_db;

pub use index::CaptureIndex;
