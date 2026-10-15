//! socshark-core: tipos fundamentales compartidos por todos los crates del workspace.
//!
//! Contiene el modelo de datos central ([`flow::EnrichedFlow`]), los tipos de
//! paquete crudo ([`packet::RawPacket`]) y la configuración del pipeline
//! ([`config::PipelineConfig`]). Cualquier crate puede depender de `core`,
//! pero `core` no depende de nadie: es la base del grafo de dependencias.

pub mod config;
pub mod flow;
pub mod packet;

pub use config::PipelineConfig;
pub use flow::{
    dns_rcode_str, dns_type_str, Alert, DnsAnswerSummary, DnsQuerySummary, DnsSummary,
    EnrichedFlow, ExtractedFile, FlowId, FlowState, L7Protocol, Severity, TcpFlagCounts, Transport,
};
pub use packet::{LinkType, RawPacket};
