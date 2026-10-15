//! **El corazón de la legibilidad** de soc-shark (Flow-First).
//!
//! En vez de entregar a la UI paquetes sueltos, este crate agrupa la
//! captura en **conversaciones enriquecidas** ([`model::EnrichedFlow`]) con:
//! - [`session_table`]: agrupación por 5-tupla con estadísticas y offsets.
//! - [`passive_dns`]: correlación IP → dominio vista en respuestas DNS.
//! - [`noise_classifier`]: etiqueta ARP/mDNS/NTP/broadcast como ruido de
//!   fondo para atenuarlo en la UI.
//! - [`human_summary`]: traducción semántica de cabeceras a frases legibles.

pub mod human_summary;
pub mod model;
pub mod noise_classifier;
pub mod passive_dns;
pub mod session_table;

pub use model::{DomainSource, EnrichedFlow, FlowKey, FlowState};
pub use session_table::SessionTable;
