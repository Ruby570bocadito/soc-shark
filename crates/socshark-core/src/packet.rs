//! Tipos de paquete crudo compartidos entre captura y dissectors.

/// Tipo de enlace de la captura (subconjunto de los link-layer de libpcap).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// Ethernet (LINKTYPE_ETHERNET = 1).
    Ethernet,
    /// IP crudo sin cabecera de enlace (LINKTYPE_RAW = 101, DLT_RAW = 12).
    RawIp,
    /// Cualquier otro link-layer: Linux SLL (113), BSD loopback (0), ...
    /// Aceptado por el lector pero no diseccionado en Fase 1.
    Unknown(u32),
}

impl LinkType {
    pub fn from_pcap_code(code: u32) -> Self {
        match code {
            1 => LinkType::Ethernet,
            101 | 12 => LinkType::RawIp,
            other => LinkType::Unknown(other),
        }
    }
}

/// Un paquete capturado sin interpretar.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// Timestamp Unix en microsegundos.
    pub ts_micros: u64,
    /// Longitud original del paquete en el cable (puede exceder `data.len()`
    /// si la captura usó un snaplen menor).
    pub orig_len: u32,
    /// Bytes capturados (marco completo según el `LinkType` de la fuente).
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapeo_de_codigos_pcap() {
        assert_eq!(LinkType::from_pcap_code(1), LinkType::Ethernet);
        assert_eq!(LinkType::from_pcap_code(101), LinkType::RawIp);
        assert_eq!(LinkType::from_pcap_code(12), LinkType::RawIp);
        assert_eq!(LinkType::from_pcap_code(113), LinkType::Unknown(113));
    }
}
