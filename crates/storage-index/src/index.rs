//! Índice de captura: posición de cada paquete en el buffer/archivo.

use socshark_capture_core::{LinkType, PacketSource};
use socshark_common::timefmt;

/// Entrada del índice: un paquete.
#[derive(Debug, Clone, Copy)]
pub struct PacketIndexEntry {
    pub packet_index: u64,
    /// Offset del registro dentro del buffer de origen (mmap-ready).
    pub file_offset: u64,
    pub ts_us: u64,
    pub cap_len: usize,
    pub orig_len: u32,
}

/// Índice completo de una captura.
#[derive(Debug, Clone, Default)]
pub struct CaptureIndex {
    pub entries: Vec<PacketIndexEntry>,
    pub link: LinkType,
    pub errors: usize,
}

impl CaptureIndex {
    /// Construye el índice barriendo la fuente una vez (O(n), sin copias).
    pub fn build<'a>(source: &mut dyn PacketSource<'a>) -> CaptureIndex {
        let mut idx = CaptureIndex {
            link: source.link_type(),
            ..Default::default()
        };
        while let Some(item) = source.next_packet() {
            match item {
                Ok(rec) => idx.entries.push(PacketIndexEntry {
                    packet_index: rec.index,
                    file_offset: source.last_offset(),
                    ts_us: rec.ts_us,
                    cap_len: rec.cap_len(),
                    orig_len: rec.orig_len,
                }),
                Err(_) => idx.errors += 1,
            }
        }
        idx
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Rango temporal (epoch μs) o None si está vacía.
    pub fn time_range(&self) -> Option<(u64, u64)> {
        let first = self.entries.first()?.ts_us;
        let last = self.entries.last()?.ts_us;
        Some((first.min(last), first.max(last)))
    }

    /// Bytes capturados totales.
    pub fn total_captured_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.cap_len as u64).sum()
    }

    /// Histograma de paquetes por segundo (para sparklines de la UI).
    pub fn per_second(&self) -> Vec<(u64, u64)> {
        let mut out: Vec<(u64, u64)> = Vec::new();
        for e in &self.entries {
            let sec = e.ts_us / 1_000_000;
            match out.last_mut() {
                Some((s, c)) if *s == sec => *c += 1,
                _ => out.push((sec, 1)),
            }
        }
        out
    }

    /// Resumen legible del rango temporal.
    pub fn time_range_str(&self) -> String {
        match self.time_range() {
            Some((a, b)) => format!(
                "{} → {} ({})",
                timefmt::format_ts_short(a),
                timefmt::format_ts_short(b),
                timefmt::format_duration_us(b.saturating_sub(a))
            ),
            None => "—".into(),
        }
    }
}
