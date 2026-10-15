//! Tipos de enlace soportados por el disector de capa 2.

/// Encapsulamiento de enlace de la captura.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// BSD loopback (0): 4 bytes de family + IP.
    Null,
    /// Ethernet II (1): el caso dominante.
    Ethernet,
    /// IP crudo (12, 101, 228): sin cabecera L2.
    RawIp,
    /// Linux "cooked" (113): cabecera SLL de 16 bytes.
    LinuxSll,
    /// Cualquier otro DLT: el paquete queda sin disección L2.
    Unknown(u16),
}

impl Default for LinkType {
    fn default() -> Self {
        LinkType::Ethernet
    }
}

impl LinkType {
    pub fn from_code(code: u16) -> Self {
        match code {
            0 => LinkType::Null,
            1 => LinkType::Ethernet,
            12 | 101 | 228 => LinkType::RawIp,
            113 => LinkType::LinuxSll,
            other => LinkType::Unknown(other),
        }
    }

    pub fn code(&self) -> u16 {
        match self {
            LinkType::Null => 0,
            LinkType::Ethernet => 1,
            LinkType::RawIp => 101,
            LinkType::LinuxSll => 113,
            LinkType::Unknown(c) => *c,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LinkType::Null => "Null/Loopback",
            LinkType::Ethernet => "Ethernet",
            LinkType::RawIp => "Raw IP",
            LinkType::LinuxSll => "Linux SLL",
            LinkType::Unknown(_) => "Desconocido",
        }
    }
}
