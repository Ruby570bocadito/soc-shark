//! Lector de archivos de captura: pcap clásico y **pcapng**.
//!
//! Implementación propia en Rust puro, sin depender de libpcap:
//! - Compilable en cualquier plataforma sin librerías de sistema.
//! - Tests 100% deterministas (no hace falta capturar tráfico real).
//! - pcap clásico: microsegundos y nanosegundos, en ambos endianness (los
//!   cuatro magics estándar).
//! - pcapng (lo que guarda Wireshark por defecto): secciones con su propio
//!   orden de bytes, interfaces con su resolución de tiempo (`if_tsresol`,
//!   `if_tsoffset`) y paquetes Enhanced, Simple y el antiguo Packet Block;
//!   el resto de bloques (nombres, estadísticas, comentarios…) se salta. Si
//!   hay interfaces con distinto tipo de enlace, se leen las del primero.
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

/// Bloques pcapng que importan.
const NG_SHB: u32 = 0x0A0D_0D0A;
const NG_IDB: u32 = 1;
const NG_PB: u32 = 2;
const NG_SPB: u32 = 3;
const NG_EPB: u32 = 6;
const NG_BYTE_ORDER: u32 = 0x1A2B_3C4D;
/// Opciones recorridas como mucho en un bloque (anti bucles).
const NG_MAX_OPTIONS: usize = 256;

/// Endianness del archivo (se detecta con el magic o el byte-order magic).
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

    fn u16_at(self, buf: &[u8], off: usize) -> Option<u16> {
        Some(self.u16(buf.get(off..off + 2)?.try_into().ok()?))
    }

    fn u32_at(self, buf: &[u8], off: usize) -> Option<u32> {
        Some(self.u32(buf.get(off..off + 4)?.try_into().ok()?))
    }
}

/// Resolución de las marcas de tiempo de una interfaz pcapng.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TsResolution {
    /// 10^-n segundos (6 = microsegundos, el valor por defecto).
    Decimal(u8),
    /// 2^-n segundos.
    Binary(u8),
}

impl TsResolution {
    fn to_micros(self, ts: u64) -> u64 {
        match self {
            TsResolution::Decimal(n) if n >= 6 => match 10u64.checked_pow(u32::from(n - 6)) {
                Some(div) => ts / div,
                None => 0,
            },
            TsResolution::Decimal(n) => ts.saturating_mul(10u64.pow(u32::from(6 - n))),
            // Con n pequeño el resultado no cabe en u64: se satura en vez de
            // truncar los bits altos (un `as` daría una marca arbitraria).
            TsResolution::Binary(n) => {
                u64::try_from((u128::from(ts) * 1_000_000) >> n.min(127)).unwrap_or(u64::MAX)
            }
        }
    }
}

#[derive(Debug, Clone)]
struct NgInterface {
    link: LinkType,
    snaplen: u32,
    resolution: TsResolution,
    /// `if_tsoffset`: segundos a sumar a cada marca de tiempo.
    offset_secs: i64,
}

/// Estado de lectura de un pcapng.
#[derive(Debug)]
struct NgState {
    endian: Endianness,
    interfaces: Vec<NgInterface>,
    /// Marca del último paquete (los Simple Packet Block no traen la suya).
    last_ts: u64,
}

#[derive(Debug)]
enum Format {
    Classic {
        endian: Endianness,
        /// True si el archivo usa granularidad de nanosegundos (magic 0xa1b23c4d).
        nanos: bool,
    },
    Ng(NgState),
}

/// Lector de un archivo pcap o pcapng.
pub struct PcapFileReader<R: Read> {
    reader: BufReader<R>,
    link: LinkType,
    format: Format,
    ended: bool,
}

impl PcapFileReader<BufReader<File>> {
    /// Abre una captura del disco (pcap o pcapng).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CaptureError> {
        let file = File::open(path)?;
        Self::new(BufReader::new(file))
    }
}

/// Lee exactamente `buf.len()` bytes. `Ok(false)` si el archivo terminó
/// justo antes (fin limpio); error si terminó a medias.
fn read_or_eof(reader: &mut impl Read, buf: &mut [u8]) -> Result<bool, CaptureError> {
    let mut got = 0;
    while got < buf.len() {
        match reader.read(&mut buf[got..]) {
            Ok(0) if got == 0 => return Ok(false),
            Ok(0) => {
                return Err(CaptureError::InvalidPcap(
                    "archivo truncado a mitad de un bloque".into(),
                ))
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

fn truncated(e: std::io::Error) -> CaptureError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        CaptureError::InvalidPcap("archivo truncado a mitad de un registro".into())
    } else {
        e.into()
    }
}

impl<R: Read> PcapFileReader<R> {
    /// Crea un lector sobre cualquier `Read` (útil para tests y para
    /// consumir capturas por tubería).
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
            [0x0a, 0x0d, 0x0d, 0x0a] => return Self::new_ng(reader),
            other => {
                return Err(CaptureError::InvalidPcap(format!(
                    "magic {other:02x?} desconocido: no es una captura pcap ni pcapng"
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
            format: Format::Classic { endian, nanos },
            ended: false,
        })
    }

    /// pcapng: ya se leyó el tipo del primer bloque (SHB). Se lee la
    /// sección y se avanza hasta la primera interfaz para saber el enlace.
    fn new_ng(mut reader: BufReader<R>) -> Result<Self, CaptureError> {
        let endian = read_shb(&mut reader)?;
        let mut me = Self {
            reader,
            link: LinkType::Ethernet,
            format: Format::Ng(NgState {
                endian,
                interfaces: Vec::new(),
                last_ts: 0,
            }),
            ended: false,
        };
        // Hasta la primera interfaz no puede haber paquetes.
        loop {
            match me.ng_block()? {
                None => {
                    me.ended = true;
                    break;
                }
                Some((NG_IDB, _)) => {
                    if let Format::Ng(ng) = &me.format {
                        if let Some(first) = ng.interfaces.first() {
                            me.link = first.link;
                        }
                    }
                    break;
                }
                Some((kind @ (NG_PB | NG_SPB | NG_EPB), _)) => {
                    return Err(CaptureError::InvalidPcap(format!(
                        "pcapng: bloque de paquete ({kind}) antes de declarar ninguna interfaz"
                    )))
                }
                Some(_) => {}
            }
        }
        Ok(me)
    }

    /// Siguiente bloque pcapng (tipo y cuerpo). Las secciones y las
    /// interfaces se procesan aquí mismo. `None` = fin del archivo.
    fn ng_block(&mut self) -> Result<Option<(u32, Vec<u8>)>, CaptureError> {
        let Format::Ng(ng) = &mut self.format else {
            return Ok(None);
        };
        let mut kind_raw = [0u8; 4];
        if !read_or_eof(&mut self.reader, &mut kind_raw)? {
            return Ok(None);
        }
        let kind = ng.endian.u32(kind_raw);
        if kind == NG_SHB {
            // Nueva sección: su propio orden de bytes y sus interfaces.
            ng.endian = read_shb(&mut self.reader)?;
            ng.interfaces.clear();
            return Ok(Some((NG_SHB, Vec::new())));
        }
        let mut len_raw = [0u8; 4];
        self.reader.read_exact(&mut len_raw).map_err(truncated)?;
        let len = ng.endian.u32(len_raw) as usize;
        if len < 12 || len & 3 != 0 || len > MAX_PACKET_BYTES + 4096 {
            return Err(CaptureError::InvalidPcap(format!(
                "pcapng: bloque de {len} bytes imposible (archivo corrupto)"
            )));
        }
        let mut body = vec![0u8; len - 8];
        self.reader.read_exact(&mut body).map_err(truncated)?;
        body.truncate(len - 12); // fuera la longitud repetida del final
        if kind == NG_IDB {
            ng.interfaces.push(parse_idb(ng.endian, &body)?);
        }
        Ok(Some((kind, body)))
    }

    fn ng_next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        loop {
            let Some((kind, body)) = self.ng_block()? else {
                return Ok(None);
            };
            let Format::Ng(ng) = &mut self.format else {
                return Ok(None);
            };
            let e = ng.endian;
            let bad =
                || CaptureError::InvalidPcap(format!("pcapng: bloque de paquete {kind} corrupto"));
            // (interfaz, marca de tiempo cruda, capturados, original, inicio de datos)
            let (iface, ts, cap, orig, start) = match kind {
                NG_EPB => {
                    let id = e.u32_at(&body, 0).ok_or_else(bad)? as usize;
                    let hi = e.u32_at(&body, 4).ok_or_else(bad)?;
                    let lo = e.u32_at(&body, 8).ok_or_else(bad)?;
                    let cap = e.u32_at(&body, 12).ok_or_else(bad)? as usize;
                    let orig = e.u32_at(&body, 16).ok_or_else(bad)?;
                    (
                        id,
                        Some((u64::from(hi) << 32) | u64::from(lo)),
                        cap,
                        orig,
                        20,
                    )
                }
                NG_PB => {
                    let id = e.u16_at(&body, 0).ok_or_else(bad)? as usize;
                    let hi = e.u32_at(&body, 4).ok_or_else(bad)?;
                    let lo = e.u32_at(&body, 8).ok_or_else(bad)?;
                    let cap = e.u32_at(&body, 12).ok_or_else(bad)? as usize;
                    let orig = e.u32_at(&body, 16).ok_or_else(bad)?;
                    (
                        id,
                        Some((u64::from(hi) << 32) | u64::from(lo)),
                        cap,
                        orig,
                        20,
                    )
                }
                NG_SPB => {
                    let orig = e.u32_at(&body, 0).ok_or_else(bad)?;
                    let snap = ng.interfaces.first().map_or(0, |i| i.snaplen);
                    let mut cap = (orig as usize).min(body.len() - 4);
                    if snap > 0 {
                        cap = cap.min(snap as usize);
                    }
                    (0, None, cap, orig, 4)
                }
                _ => continue,
            };
            let Some(iface) = ng.interfaces.get(iface).cloned() else {
                return Err(CaptureError::InvalidPcap(format!(
                    "pcapng: paquete de la interfaz {iface}, que no se declaró"
                )));
            };
            let end = usize::checked_add(start, cap).ok_or_else(bad)?;
            let data = body.get(start..end).ok_or_else(bad)?.to_vec();
            let ts_micros = match ts {
                Some(raw) => {
                    let base = iface.resolution.to_micros(raw);
                    let off = iface.offset_secs.saturating_mul(1_000_000);
                    base.saturating_add_signed(off)
                }
                None => ng.last_ts,
            };
            ng.last_ts = ts_micros;
            // Solo las interfaces del mismo enlace que la primera.
            if iface.link != self.link {
                continue;
            }
            return Ok(Some(RawPacket {
                ts_micros,
                orig_len: orig,
                data,
            }));
        }
    }

    /// Granularidad temporal del archivo (microsegundos o nanosegundos).
    pub fn nanosecond_resolution(&self) -> bool {
        match &self.format {
            Format::Classic { nanos, .. } => *nanos,
            Format::Ng(ng) => ng
                .interfaces
                .first()
                .is_some_and(|i| i.resolution == TsResolution::Decimal(9)),
        }
    }

    /// ¿Es pcapng (y no pcap clásico)?
    pub fn is_pcapng(&self) -> bool {
        matches!(self.format, Format::Ng(_))
    }
}

/// Resto de un Section Header Block (tras su tipo): devuelve su orden de
/// bytes y deja el lector al principio del bloque siguiente.
fn read_shb(reader: &mut impl Read) -> Result<Endianness, CaptureError> {
    let mut head = [0u8; 8]; // longitud + byte-order magic
    reader.read_exact(&mut head).map_err(truncated)?;
    let bom = [head[4], head[5], head[6], head[7]];
    let endian = if u32::from_le_bytes(bom) == NG_BYTE_ORDER {
        Endianness::Little
    } else if u32::from_be_bytes(bom) == NG_BYTE_ORDER {
        Endianness::Big
    } else {
        return Err(CaptureError::InvalidPcap(
            "pcapng: cabecera de sección sin orden de bytes válido".into(),
        ));
    };
    let len = endian.u32([head[0], head[1], head[2], head[3]]) as usize;
    if len < 28 || len & 3 != 0 || len > 1 << 20 {
        return Err(CaptureError::InvalidPcap(format!(
            "pcapng: cabecera de sección de {len} bytes imposible"
        )));
    }
    // versión(4) + longitud de sección(8) + opciones + longitud final.
    let mut rest = vec![0u8; len - 12];
    reader.read_exact(&mut rest).map_err(truncated)?;
    let major = endian.u16([rest[0], rest[1]]);
    if major != 1 {
        return Err(CaptureError::InvalidPcap(format!(
            "versión de pcapng no soportada: {major}"
        )));
    }
    Ok(endian)
}

/// Interface Description Block: enlace, snaplen y opciones de tiempo.
fn parse_idb(e: Endianness, body: &[u8]) -> Result<NgInterface, CaptureError> {
    let bad = || CaptureError::InvalidPcap("pcapng: descripción de interfaz corrupta".into());
    let link = e.u16_at(body, 0).ok_or_else(bad)?;
    let snaplen = e.u32_at(body, 4).ok_or_else(bad)?;
    let mut iface = NgInterface {
        link: LinkType::from_pcap_code(u32::from(link)),
        snaplen,
        resolution: TsResolution::Decimal(6),
        offset_secs: 0,
    };
    let mut off = 8;
    for _ in 0..NG_MAX_OPTIONS {
        let (Some(code), Some(len)) = (e.u16_at(body, off), e.u16_at(body, off + 2)) else {
            break;
        };
        let len = len as usize;
        let Some(value) = body.get(off + 4..off + 4 + len) else {
            break;
        };
        match (code, len) {
            (0, _) => break,
            (9, 1) => {
                let v = value[0];
                iface.resolution = if v & 0x80 == 0 {
                    TsResolution::Decimal(v)
                } else {
                    TsResolution::Binary(v & 0x7f)
                };
            }
            (14, 8) => {
                let raw: [u8; 8] = value.try_into().map_err(|_| bad())?;
                iface.offset_secs = match e {
                    Endianness::Little => i64::from_le_bytes(raw),
                    Endianness::Big => i64::from_be_bytes(raw),
                };
            }
            _ => {}
        }
        off += 4 + len.div_ceil(4) * 4;
    }
    Ok(iface)
}

impl<R: Read> CaptureSource for PcapFileReader<R> {
    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        if self.ended {
            return Ok(None);
        }
        let (endian, nanos) = match &self.format {
            Format::Classic { endian, nanos } => (*endian, *nanos),
            Format::Ng(_) => {
                let p = self.ng_next_packet()?;
                self.ended = p.is_none();
                return Ok(p);
            }
        };

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

        let ts_sec = endian.u32([rh[0], rh[1], rh[2], rh[3]]);
        let ts_frac = endian.u32([rh[4], rh[5], rh[6], rh[7]]);
        let incl_len = endian.u32([rh[8], rh[9], rh[10], rh[11]]) as usize;
        let orig_len = endian.u32([rh[12], rh[13], rh[14], rh[15]]);

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

        let ts_micros = if nanos {
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

    // ------------------------------------------------------------ pcapng

    use socshark_testgen::{pcapng_bytes, PcapNgOptions};

    fn read_all(bytes: &[u8]) -> Result<Vec<RawPacket>, CaptureError> {
        let mut r = PcapFileReader::new(bytes)?;
        let mut out = Vec::new();
        while let Some(p) = r.next_packet()? {
            out.push(p);
        }
        Ok(out)
    }

    #[test]
    fn pcapng_igual_que_pcap_en_ambos_ordenes_y_resoluciones() {
        let pkts = sample_pcap_packets();
        for little_endian in [true, false] {
            for nanos in [true, false] {
                let bytes = pcapng_bytes(
                    1,
                    &pkts,
                    PcapNgOptions {
                        little_endian,
                        nanos,
                        extra_blocks: false,
                    },
                );
                let r = PcapFileReader::new(bytes.as_slice()).unwrap();
                assert!(r.is_pcapng());
                assert_eq!(r.link_type(), LinkType::Ethernet);
                assert_eq!(r.nanosecond_resolution(), nanos);
                let got = read_all(&bytes).unwrap();
                assert_eq!(got.len(), pkts.len(), "le={little_endian} ns={nanos}");
                for (g, (ts, data)) in got.iter().zip(&pkts) {
                    assert_eq!(g.ts_micros, *ts);
                    assert_eq!(&g.data, data);
                    assert_eq!(g.orig_len as usize, data.len());
                }
            }
        }
    }

    #[test]
    fn pcapng_salta_bloques_ajenos_y_lee_simple_packet() {
        let pkts = sample_pcap_packets();
        let bytes = pcapng_bytes(
            1,
            &pkts,
            PcapNgOptions {
                extra_blocks: true,
                ..Default::default()
            },
        );
        let got = read_all(&bytes).unwrap();
        assert_eq!(got.len(), pkts.len());
        for (i, (g, (ts, data))) in got.iter().zip(&pkts).enumerate() {
            assert_eq!(&g.data, data);
            if i % 5 != 4 {
                assert_eq!(g.ts_micros, *ts);
            } else {
                // Sin marca propia: la del paquete anterior.
                assert_eq!(g.ts_micros, got[i - 1].ts_micros);
            }
        }
    }

    #[test]
    fn pcapng_resoluciones_de_tiempo() {
        assert_eq!(TsResolution::Decimal(6).to_micros(1_500_000), 1_500_000);
        assert_eq!(TsResolution::Decimal(9).to_micros(1_500_000_123), 1_500_000);
        assert_eq!(TsResolution::Decimal(3).to_micros(1_500), 1_500_000);
        assert_eq!(TsResolution::Binary(20).to_micros(1 << 20), 1_000_000);
        assert_eq!(TsResolution::Decimal(127).to_micros(u64::MAX), 0);
        // Resolución binaria fina con marca enorme: satura, no trunca.
        assert_eq!(TsResolution::Binary(0).to_micros(u64::MAX), u64::MAX);
        assert_eq!(TsResolution::Binary(1).to_micros(u64::MAX), u64::MAX);
    }

    #[test]
    fn pcapng_corrupto_o_truncado_no_explota() {
        let bytes = pcapng_bytes(
            1,
            &sample_pcap_packets()[..6],
            PcapNgOptions {
                extra_blocks: true,
                ..Default::default()
            },
        );
        // Cortado en cualquier punto: error limpio o fin, nunca pánico.
        for cut in 4..bytes.len() {
            let _ = read_all(&bytes[..cut]);
        }
        // Un byte cambiado en cualquier sitio, tampoco.
        for i in 0..bytes.len() {
            let mut b = bytes.clone();
            b[i] ^= 0xff;
            let _ = read_all(&b);
        }
        // Longitud de bloque gigante: error, sin reservar memoria absurda.
        let mut b = bytes.clone();
        let idb_len_at = 28 + 4;
        b[idb_len_at..idb_len_at + 4].copy_from_slice(&0x7fff_fff0u32.to_le_bytes());
        assert!(matches!(
            PcapFileReader::new(b.as_slice()),
            Err(CaptureError::InvalidPcap(_))
        ));
        // Paquete de una interfaz que no existe.
        let mut b = bytes.clone();
        let first_epb = bytes
            .windows(4)
            .position(|w| w == 6u32.to_le_bytes())
            .unwrap();
        b[first_epb + 8..first_epb + 12].copy_from_slice(&7u32.to_le_bytes());
        match read_all(&b) {
            Err(CaptureError::InvalidPcap(m)) => assert!(m.contains("interfaz 7"), "{m}"),
            other => panic!("{other:?}"),
        }
    }
}
