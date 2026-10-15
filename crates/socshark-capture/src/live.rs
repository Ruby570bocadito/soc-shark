//! Captura en vivo — INTENCIONALMENTE NO IMPLEMENTADA EN FASE 1.
//!
//! Este módulo es un stub que define el punto de enganche y documenta el
//! plan completo (ver `docs/roadmap.md` y `docs/architecture.md`):
//!
//! 1. **Fase 2 — backend libpcap** (crate `pcap`): compatibilidad inmediata
//!    con cualquier Linux/macOS, requiere CAP_NET_RAW o root, soporta
//!    *pushdown* de filtros BPF al kernel para reducir tráfico al userspace.
//! 2. **Fase 2/3 — backend AF_XDP**: captura de alto rendimiento sin copias
//!    en Linux >= 4.18; los paquetes se procesan desde memoria DMA.
//! 3. **Fase 3 — modelo de privilegios**: la captura pasa a un proceso daemon
//!    con CAP_NET_RAW + CAP_BPF; el resto del pipeline (dissectors, SOC,
//!    plugins) corre sin privilegios y consume por gRPC/UDS.
//!
//! El trait [`crate::CaptureSource`] ya define el contrato: la captura en
//! vivo solo tiene que implementarlo para enchufarse al mismo pipeline,
//! sin cambiar dissectors, agregador ni capa SOC.

use crate::{CaptureError, CaptureSource};
use socshark_core::{LinkType, RawPacket};

/// Captura en vivo desde una interfaz de red (no disponible aún).
#[derive(Debug)]
pub struct LiveCapture {
    _priv: (),
}

impl LiveCapture {
    /// Intenta abrir una interfaz para captura en vivo.
    ///
    /// En Fase 1 siempre devuelve [`CaptureError::LiveUnavailable`] con el
    /// plan de implementación en el mensaje.
    pub fn open(_iface: &str) -> Result<Self, CaptureError> {
        Err(CaptureError::LiveUnavailable(
            "la captura en vivo llega en la Fase 2; usa por ahora `socshark capture -r archivo.pcap`"
                .to_string(),
        ))
    }
}

impl CaptureSource for LiveCapture {
    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        Err(CaptureError::LiveUnavailable(
            "no implementado (Fase 2)".into(),
        ))
    }

    fn link_type(&self) -> LinkType {
        LinkType::Ethernet
    }
}
