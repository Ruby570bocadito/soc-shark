//! socshark-capture: abstracción de fuentes de captura de paquetes.
//!
//! Lector de archivos pcap y pcapng ([`pcap_file`]), implementado en Rust
//! puro (no requiere libpcap instalado). Captura en vivo ([`live`]) con FFI
//! propio sobre libpcap/Npcap cargada al vuelo — sin dependencias nuevas ni
//! cabeceras en tiempo de compilación — detrás del mismo trait
//! [`CaptureSource`]. Y, para el tráfico de esta máquina, qué programa
//! tiene cada conexión ([`owners`]).
//!
//! Contrato de [`CaptureSource`]:
//! - `next_packet` devuelve `Ok(None)` al agotarse la fuente (EOF limpio).
//!   **En captura en vivo** `Ok(None)` es un *tick* (venció el timeout de
//!   lectura sin tráfico): el consumidor decide si significa fin (archivos)
//!   o continuidad (daemon). Los errores reales llegan como `Err`.
//! - Los paquetes llegan en orden de archivo; el agregador tolera
//!   reordenamientos leves (out-of-order) por su manejo de timestamps.
//! - `link_type` informa a los dissectors sobre la capa 2 a usar.

pub mod live;
pub mod owners;
pub mod pcap_file;

use socshark_core::{LinkType, RawPacket};
use thiserror::Error;

/// Errores de captura.
#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("pcap inválido: {0}")]
    InvalidPcap(String),
    #[error("captura en vivo: {0}")]
    Live(String),
    #[error("captura en vivo no disponible: {0}")]
    LiveUnavailable(String),
    /// La biblioteca de captura (Npcap en Windows, libpcap en Linux/macOS)
    /// no se pudo cargar: falta o está incompleta. Mismo texto que
    /// [`Self::LiveUnavailable`] para la CLI; variante aparte para que la
    /// GUI explique en lenguaje claro qué instalar (y no lo diga, por
    /// ejemplo, en una plataforma sin soporte, donde instalar no arregla
    /// nada).
    #[error("captura en vivo no disponible: {0}")]
    CaptureLibraryMissing(String),
}

/// Fuente de paquetes: archivo pcap, interfaz en vivo, etc.
pub trait CaptureSource {
    /// Siguiente paquete de la fuente; `Ok(None)` indica fin de captura.
    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError>;

    /// Tipo de enlace de la fuente; los dissectors lo usan para elegir el
    /// parser de capa 2 (Ethernet o IP crudo).
    fn link_type(&self) -> LinkType;
}

pub use live::{list_ifaces, LiveBreaker, LiveCapture, LiveCaptureConfig, LiveIface};
pub use owners::{SocketOwner, SocketTable};
pub use pcap_file::PcapFileReader;
