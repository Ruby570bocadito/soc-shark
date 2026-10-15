//! Lector de archivos pcap clásicos.
//!
//! Implementación propia en Rust puro, sin depender de libpcap:
//! - Compilable en cualquier plataforma sin librerías de sistema.
//! - Tests 100% deterministas (no hace falta capturar tráfico real).
//! - Soporta capturas en microsegundos y nanosegundos, en ambos endianness
//!   (los cuatro magics estándar del formato clásico).
//!
//! Decisión de diseño completa en `docs/decisions.md` (ADR-003). El registro
//! final truncado de un archivo cortado se trata como EOF limpio; un registro
//! con el payload truncado es un error explícito.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use socshark_core::{LinkType, RawPacket};

use crate::{CaptureError, CaptureSource};

/// Cota de seguridad para `incl_len`: evita reservas absurdas de memoria con
/// archivos corruptos o malintencionados (256 MiB, muy por encima de cualquier
/// snaplen real).
const MAX_PACKET_BYTES: usize = 256 * 1024 * 1024;

/// Endianness del archivo pcap (se detecta con el magic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endianness {
    Little,
    Big,
}

impl Endianness {
    fn u16(self, b: [u8; 2]) -> u16 {
        match self {
            Endianness::Little => u16::from_le_bytes(b),
            Endianness::Big => u16::from_be_bytes(b),
        }
    }

    fn u32(self, b: [u8; 4]) -> u32 {
        match self {
            Endianness::Little => u32::from_le_bytes(b),
            Endianness::Big => u32::from_be_bytes(b),
        }
    }
}

/// Lector de un archivo pcap clásico.
pub struct PcapFileReader<R: Read> {
    reader: BufReader<R>,
    link: LinkType,
    endian: Endianness,
    /// True si el archivo usa granularidad de nanosegundos (magic 0xa1b23c4d).
    nanos: bool,
    ended: bool,
}

impl PcapFileReader<BufReader<File>> {
    /// Abre un archivo pcap del disco.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CaptureError> {
        let file = File::open(path)?;
        Self::new(BufReader::new(file))
    }
}

impl<R: Read> PcapFileReader<R> {
    /// Crea un lector sobre cualquier `Read` (útil para tests y para
    /// consumir pcaps por tubería).
    pub fn new(reader: R) -> Result<Self, CaptureError> {
        let mut reader = BufReader::new(reader);

        let mut magic = [0u8; 4];
        match reader.read_exact(&mut magic) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(CaptureError::InvalidPcap(
                    "archivo vacío (sin magic)".into(),
                ))
            }
            Err(e) => return Err(e.into()),
        }

        let (endian, nanos) = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => (Endianness::Little, false), // usec LE (el más común)
            [0xa1, 0xb2, 0xc3, 0xd4] => (Endianness::Big, false),    // usec BE
            [0x4d, 0x3c, 0xb2, 0xa1] => (Endianness::Little, true),  // nsec LE
            [0xa1, 0xb2, 0x3c, 0x4d] => (Endianness::Big, true),     // nsec BE
            other => {
                return Err(CaptureError::InvalidPcap(format!(
                    "magic {other:02x?} desconocido: no es un pcap clásico (¿pcapng? conviértelo con `editcap -F pcap`)"
                )))
            }
        };

        // Cabecera global: version(2+2), thiszone(4), sigfigs(4), snaplen(4), network(4).
        let mut hdr = [0u8; 20];
        reader.read_exact(&mut hdr)?;
        let version_major = endian.u16([hdr[0], hdr[1]]);
        if version_major != 2 {
            return Err(CaptureError::InvalidPcap(format!(
                "versión de pcap no soportada: {version_major}"
            )));
        }
        let network = endian.u32([hdr[16], hdr[17], hdr[18], hdr[19]]);
        let link = LinkType::from_pcap_code(network);

        Ok(Self {
            reader,
            link,
            endian,
            nanos,
            ended: false,
        })
    }

    /// Granularidad temporal del archivo (microsegundos o nanosegundos).
    pub fn nanosecond_resolution(&self) -> bool {
        self.nanos
    }
}

impl<R: Read> CaptureSource for PcapFileReader<R> {
    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        if self.ended {
            return Ok(None);
        }

        // Cabecera del registro: ts_sec, ts_frac, incl_len, orig_len.
        let mut rh = [0u8; 16];
        match self.reader.read_exact(&mut rh) {
            Ok(()) => {}
            // EOF exactamente en el límite de registro: fin limpio.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                self.ended = true;
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        }

        let ts_sec = self.endian.u32([rh[0], rh[1], rh[2], rh[3]]);
        let ts_frac = self.endian.u32([rh[4], rh[5], rh[6], rh[7]]);
        let incl_len = self.endian.u32([rh[8], rh[9], rh[10], rh[11]]) as usize;
        let orig_len = self.endian.u32([rh[12], rh[13], rh[14], rh[15]]);

        if incl_len > MAX_PACKET_BYTES {
            return Err(CaptureError::InvalidPcap(format!(
                "registro con incl_len={incl_len} sospechosamente grande (archivo corrupto)"
            )));
        }

        let mut data = vec![0u8; incl_len];
        if let Err(e) = self.reader.read_exact(&mut data) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Err(CaptureError::InvalidPcap(
                    "archivo truncado a mitad de un registro".into(),
                ));
            }
            return Err(e.into());
        }

        let ts_micros = if self.nanos {
            ts_sec as u64 * 1_000_000 + (ts_frac / 1_000) as u64
        } else {
            ts_sec as u64 * 1_000_000 + ts_frac as u64
        };

        Ok(Some(RawPacket {
            ts_micros,
            orig_len,
            data,
        }))
    }

    fn link_type(&self) -> LinkType {
        self.link
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_testgen::{sample_pcap_packets, write_pcap};

    #[test]
    fn lee_pcap_generado_completo() {
        let path = std::env::temp_dir().join(format!("socshark-cap-{}.pcap", std::process::id()));
        let pkts = sample_pcap_packets();
        write_pcap(&path, 1, &pkts).unwrap();

        let mut r = PcapFileReader::open(&path).unwrap();
        assert_eq!(r.link_type(), LinkType::Ethernet);
        assert!(!r.nanosecond_resolution());

        let mut n = 0;
        while let Some(p) = r.next_packet().unwrap() {
            assert!(!p.data.is_empty());
            assert!(p.ts_micros > 0);
            n += 1;
        }
        assert_eq!(n, pkts.len());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rechaza_magic_invalido() {
        let bytes = [0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0];
        assert!(PcapFileReader::new(&bytes[..]).is_err());
    }

    #[test]
    fn rechaza_archivo_vacio() {
        assert!(PcapFileReader::new(std::io::empty()).is_err());
    }

    #[test]
    fn lee_pcap_big_endian() {
        // Cabecera global big-endian + un registro de 4 bytes con ts=1.5s.
        let mut b = Vec::new();
        b.extend_from_slice(&0xa1b2c3d4u32.to_be_bytes());
        b.extend_from_slice(&2u16.to_be_bytes());
        b.extend_from_slice(&4u16.to_be_bytes());
        b.extend_from_slice(&0i32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&65535u32.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&500_000u32.to_be_bytes());
        b.extend_from_slice(&4u32.to_be_bytes());
        b.extend_from_slice(&4u32.to_be_bytes());
        b.extend_from_slice(&[1, 2, 3, 4]);

        let mut r = PcapFileReader::new(b.as_slice()).unwrap();
        let p = r.next_packet().unwrap().unwrap();
        assert_eq!(p.ts_micros, 1_500_000);
        assert_eq!(p.data, vec![1, 2, 3, 4]);
        assert!(r.next_packet().unwrap().is_none());
    }

    #[test]
    fn pcap_nanosegundos_se_convierte_a_micros() {
        let mut b = Vec::new();
        b.extend_from_slice(&0xa1b23c4du32.to_le_bytes()); // nsec LE
        b.extend_from_slice(&2u16.to_le_bytes());
        b.extend_from_slice(&4u16.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&65535u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        // ts = 5s + 123_456_789 ns
        b.extend_from_slice(&5u32.to_le_bytes());
        b.extend_from_slice(&123_456_789u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());

        let mut r = PcapFileReader::new(b.as_slice()).unwrap();
        assert!(r.nanosecond_resolution());
        let p = r.next_packet().unwrap().unwrap();
        assert_eq!(p.ts_micros, 5_123_456); // 789 ns truncados a micros
    }

    #[test]
    fn detecta_registro_truncado() {
        // Cabecera global válida + cabecera de registro que anuncia 100 bytes
        // pero solo siguen 8: debe fallar con InvalidPcap, no colgar ni OOM.
        let mut b = Vec::new();
        b.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        b.extend_from_slice(&2u16.to_le_bytes());
        b.extend_from_slice(&4u16.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&65535u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&100u32.to_le_bytes());
        b.extend_from_slice(&100u32.to_le_bytes());
        b.extend_from_slice(&[0u8; 8]);

        let mut r = PcapFileReader::new(b.as_slice()).unwrap();
        match r.next_packet() {
            Err(CaptureError::InvalidPcap(msg)) => assert!(msg.contains("truncado")),
            other => panic!("se esperaba InvalidPcap, obtenido {other:?}"),
        }
    }

    #[test]
    fn eof_en_limite_de_registro_es_fin_limpio() {
        let mut b = Vec::new();
        b.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        b.extend_from_slice(&2u16.to_le_bytes());
        b.extend_from_slice(&4u16.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&65535u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());

        let mut r = PcapFileReader::new(b.as_slice()).unwrap();
        assert!(r.next_packet().unwrap().is_none());
    }
}
