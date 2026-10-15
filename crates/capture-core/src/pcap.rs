//! Lector del formato pcap clásico (libpcap), ambos endianness y μs/ns.

use crate::linktype::LinkType;
use crate::record::PacketRecord;
use crate::source::PacketSource;

/// Lector zero-copy de archivos pcap.
///
/// El buffer completo se entrega prestado en la construcción; cada registro
/// es una rebanada de ese buffer. Límite actual (documentado): la fase 1
/// carga el archivo completo en RAM; la fase 2 sustituirá el `Vec` por mmap
/// (`storage-index::mmap_store`) para capturas de decenas de GB.
pub struct PcapFileSource<'a> {
    data: &'a [u8],
    pos: usize,
    last_off: u64,
    swap: bool,
    nano: bool,
    link: LinkType,
    index: u64,
    done: bool,
}

impl<'a> PcapFileSource<'a> {
    /// Valida la cabecera global y prepara la lectura.
    pub fn new(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 24 {
            return Err("archivo pcap truncado: cabecera global < 24 bytes".into());
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let (swap, nano) = match magic {
            0xa1b2_c3d4 => (false, false),
            0xd4c3_b2a1 => (true, false),
            0xa1b2_3c4d => (false, true),
            0x4d3c_b2a1 => (true, true),
            other => {
                return Err(format!(
                    "magic pcap no reconocido: 0x{other:08x} (¿es pcapng? pruébalo como .pcapng)"
                ))
            }
        };
        let le = |off: usize| -> u32 {
            let b = [data[off], data[off + 1], data[off + 2], data[off + 3]];
            if swap {
                u32::from_be_bytes(b)
            } else {
                u32::from_le_bytes(b)
            }
        };
        let link = LinkType::from_code((le(20) & 0xffff) as u16);
        Ok(PcapFileSource {
            data,
            pos: 24,
            last_off: 0,
            swap,
            nano,
            link,
            index: 0,
            done: false,
        })
    }

    fn read_u32(&self, off: usize) -> u32 {
        let b = [
            self.data[off],
            self.data[off + 1],
            self.data[off + 2],
            self.data[off + 3],
        ];
        if self.swap {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }
    }
}

impl<'a> PacketSource<'a> for PcapFileSource<'a> {
    fn next_packet(&mut self) -> Option<Result<PacketRecord<'a>, String>> {
        if self.done {
            return None;
        }
        if self.pos + 16 > self.data.len() {
            self.done = true; // cola limpia o basura final < 16 bytes
            return None;
        }
        self.last_off = self.pos as u64;
        let sec = self.read_u32(self.pos) as u64;
        let frac = self.read_u32(self.pos + 4) as u64;
        let incl = self.read_u32(self.pos + 8) as usize;
        let orig = self.read_u32(self.pos + 12);
        let start = self.pos + 16;
        if incl > 0x4000_0000
            || start
                .checked_add(incl)
                .map(|e| e > self.data.len())
                .unwrap_or(true)
        {
            self.done = true;
            return Some(Err(format!(
                "registro pcap #{}: incl_len={} excede los datos disponibles",
                self.index, incl
            )));
        }
        let data = &self.data[start..start + incl];
        self.pos = start + incl;
        // Normaliza a microsegundos.
        let ts_us = if self.nano {
            sec.saturating_mul(1_000_000) + (frac / 1_000).min(999_999)
        } else {
            sec.saturating_mul(1_000_000) + frac.min(999_999)
        };
        let rec = PacketRecord {
            index: self.index,
            ts_us,
            orig_len: orig,
            data,
        };
        self.index += 1;
        Some(Ok(rec))
    }

    fn link_type(&self) -> LinkType {
        self.link
    }

    fn last_offset(&self) -> u64 {
        self.last_off
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cabecera pcap LE μs con un paquete de 4 bytes.
    fn sample_pcap() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes()); // major
        v.extend_from_slice(&4u16.to_le_bytes()); // minor
        v.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        v.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        v.extend_from_slice(&65_535u32.to_le_bytes()); // snaplen
        v.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
        v.extend_from_slice(&1_000_000u32.to_le_bytes()); // sec
        v.extend_from_slice(&1_234u32.to_le_bytes()); // usec
        v.extend_from_slice(&4u32.to_le_bytes()); // incl
        v.extend_from_slice(&10u32.to_le_bytes()); // orig
        v.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        v
    }

    #[test]
    fn lee_un_paquete() {
        let buf = sample_pcap();
        let mut src = PcapFileSource::new(&buf).unwrap();
        assert_eq!(src.link_type(), LinkType::Ethernet);
        let rec = src.next_packet().unwrap().unwrap();
        assert_eq!(rec.index, 0);
        assert_eq!(rec.ts_us, 1_000_000_001_234); // 1_000_000s * 1e6 + 1234µs
        assert_eq!(rec.data, &[0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(rec.orig_len, 10);
        assert!(rec.is_truncated());
        assert!(src.next_packet().is_none());
        assert_eq!(src.last_offset(), 24);
    }

    #[test]
    fn endianness_swap() {
        let mut buf = sample_pcap();
        // Reescribe el magic como big-endian y todos los campos a BE.
        buf[0..4].copy_from_slice(&0xd4c3_b2a1u32.to_le_bytes());
        // (los campos siguen en LE aquí; con swap=TRUE se leerían al revés)
        // Test más simple: reconstruir todo en BE.
        let mut v = Vec::new();
        v.extend_from_slice(&0xa1b2_c3d4u32.to_be_bytes());
        v.extend_from_slice(&2u16.to_be_bytes());
        v.extend_from_slice(&4u16.to_be_bytes());
        v.extend_from_slice(&0i32.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&65_535u32.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&1_000_000u32.to_be_bytes());
        v.extend_from_slice(&1_234u32.to_be_bytes());
        v.extend_from_slice(&4u32.to_be_bytes());
        v.extend_from_slice(&10u32.to_be_bytes());
        v.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let mut src = PcapFileSource::new(&v).unwrap();
        let rec = src.next_packet().unwrap().unwrap();
        assert_eq!(rec.ts_us, 1_000_000_001_234);
    }

    #[test]
    fn rechaza_magic_desconocido() {
        let v = vec![0u8; 30];
        assert!(PcapFileSource::new(&v).is_err());
    }

    #[test]
    fn detecta_truncado_de_registro() {
        let mut buf = sample_pcap();
        buf.truncate(42); // cabecera de registro completa (40) pero payload cortado
        let mut src = PcapFileSource::new(&buf).unwrap();
        assert!(matches!(src.next_packet(), Some(Err(_))));
        assert!(src.next_packet().is_none());
    }
}
