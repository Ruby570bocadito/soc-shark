//! Capa de ingesta de paquetes de **soc-shark**.
//!
//! Diseño (ver `docs/02-arquitectura.md`):
//! - **Zero-copy**: el archivo se carga (o se mapeará en fase 2) una sola vez
//!   y cada [`record::PacketRecord`] es una *vista* prestada (`&[u8]`) sobre
//!   ese buffer. Ningún byte se clona durante la lectura.
//! - **Formatos**: pcap clásico (μs y ns, ambos endianness) y pcapng
//!   (SHB/IDB/EPB/SPB, con `if_tsresol`).
//! - [`source::PacketSource`]: trait que abstrae la fuente (archivo hoy,
//!   libpcap/AF_XDP en vivo en fase 2) para que el resto del pipeline no
//!   cambie.
//! - [`ring_buffer::SpscRing`]: cola lock-free productor/consumidor que en
//!   fase 2 desacoplará el Ingestor del pool de dissectors.

pub mod linktype;
pub mod pcap;
pub mod pcapng;
pub mod record;
pub mod ring_buffer;
pub mod source;

pub use linktype::LinkType;
pub use record::PacketRecord;
pub use source::PacketSource;
