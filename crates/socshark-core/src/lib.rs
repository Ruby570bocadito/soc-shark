//! socshark-core: tipos fundamentales compartidos por todos los crates del workspace.
//!
//! Contiene el modelo de datos central ([`flow::EnrichedFlow`]), los tipos de
//! paquete crudo ([`packet::RawPacket`]), el hash SHA-256 propio
//! ([`hash`]) y la configuración del pipeline ([`config::PipelineConfig`]).
//! Cualquier crate puede depender de `core`, pero `core` no depende de nadie:
//! es la base del grafo de dependencias.

pub mod config;
pub mod flow;
pub mod hash;
pub mod packet;

pub use config::PipelineConfig;
pub use flow::{
    dns_rcode_str, dns_type_str, Alert, DnsAnswerSummary, DnsQuerySummary, DnsSummary,
    EnrichedFlow, ExtractedFile, FlowId, FlowState, IntervalStats, L7Protocol, Severity,
    TcpFlagCounts, Transport,
};
pub use hash::{sha256, to_hex};
pub use packet::{LinkType, RawPacket};
