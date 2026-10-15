//! Registro de paquete: vista zero-copy sobre el buffer de la captura.

/// Un paquete leído de una fuente, con timestamp y referencia a sus bytes.
///
/// `data` es prestado del buffer subyacente (archivo mmap/Vec) — copiarlo
/// sería O(caplen); ninguna API de soc-shark lo clona salvo que el consumidor
/// lo decida explícitamente (p. ej. carving).
#[derive(Debug, Clone, Copy)]
pub struct PacketRecord<'a> {
    /// Número secuencial dentro de la captura (0-based).
    pub index: u64,
    /// Timestamp en microsegundos epoch (normalizado desde μs/ns/pcapng).
    pub ts_us: u64,
    /// Longitud original del paquete en el cable.
    pub orig_len: u32,
    /// Bytes capturados (snaplen puede truncar `orig_len`).
    pub data: &'a [u8],
}

impl PacketRecord<'_> {
    pub fn cap_len(&self) -> usize {
        self.data.len()
    }

    /// ¿El snaplen truncó este paquete?
    pub fn is_truncated(&self) -> bool {
        (self.orig_len as usize) > self.data.len()
    }
}
