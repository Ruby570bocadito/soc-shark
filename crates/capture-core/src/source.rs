//! Abstracción de fuentes de paquetes.

use crate::linktype::LinkType;
use crate::record::PacketRecord;

/// Fuente secuencial de paquetes.
///
/// Fase 1: implementada por lectores de archivo (`pcap`, `pcapng`).
/// Fase 2: `libpcap` en vivo y `AF_XDP` implementarán este mismo trait, de
/// modo que el pipeline (`daemon`) no cambia.
pub trait PacketSource<'a> {
    /// Siguiente paquete, o `None` al agotar la fuente.
    /// `Err` = paquete corrupto; el pipeline puede continuar con el siguiente.
    fn next_packet(&mut self) -> Option<Result<PacketRecord<'a>, String>>;

    /// Tipo de enlace declarado por la fuente.
    fn link_type(&self) -> LinkType;

    /// Offset del último paquete entregado dentro del buffer de origen
    /// (para índices de acceso aleatorio — ver `storage-index`).
    fn last_offset(&self) -> u64 {
        0
    }
}
