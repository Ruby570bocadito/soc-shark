//! Lector del formato pcapng (PCAP Next Generation, formato de bloques).
//!
//! Soporta: SHB (detección de endianness), IDB (linktype + if_tsresol),
//! EPB (paquetes) y SPB (simple). Los demás bloques (NRB, ISB, custom) se
//! saltan de forma segura.
//!
//! Referencia: <https://pcapng.github.io/pcapng/>

use crate::linktype::LinkType;
use crate::record::PacketRecord;
use crate::source::PacketSource;

const BT_SHB: u32 = 0x0a0d_0d0a;
const BT_IDB: u32 = 0x0000_0001;
const BT_EPB: u32 = 0x0000_0006;
const BT_SPB: u32 = 0x0000_0003;

/// Lector zero-copy de archivos pcapng.
pub struct PcapngFileSource<'a> {
    data: &'a [u8],
    pos: usize,
    last_off: u64,
    big: bool,
    index: u64,
    link: LinkType,
    /// Resolución de timestamp: valor raw * 1_000_000 / resol → μs.
    ts_resol: u64,
    /// Bloque de datos de interfaz visto (para validar EPB).
    done: bool,
}

impl<'a> PcapngFileSource<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 28 {
            return Err("archivo pcapng truncado: no cabe ni un SHB".into());
        }
        let bom_le = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let big = match bom_le {
            0x1a2b_3c4d => false,
            0x4d3c_2b1a => true,
            other => return Err(format!("byte-order magic pcapng inválido: 0x{other:08x}")),
        };
        let t0 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if t0 != BT_SHB {
            // El magic de bloque es simétrico, pero validamos por si acaso.
            let t1 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            if t1 != BT_SHB {
                return Err(format!("tipo de primer bloque pcapng inválido: 0x{t0:08x}"));
            }
        }
        Ok(PcapngFileSource {
            data,
            pos: 0,
            last_off: 0,
            big,
            index: 0,
            link: LinkType::Ethernet,
            ts_resol: 1_000_000, // 10^-6 por defecto
            done: false,
        })
    }

    fn u32(&self, off: usize) -> u32 {
        let b = [
            self.data[off],
            self.data[off + 1],
            self.data[off + 2],
            self.data[off + 3],
        ];
        if self.big {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }
    }

    fn u16(&self, off: usize) -> u16 {
        let b = [self.data[off], self.data[off + 1]];
        if self.big {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        }
    }

    /// Lee opciones IDB buscando `if_tsresol` (código 9).
    ///
    /// `ts_resol` guarda los ticks por segundo (10^6 = microsegundos);
    /// el timestamp se convierte con `ts_us = raw * 1e6 / ts_resol`.
    fn parse_idb_options(&mut self, body_start: usize, block_end: usize) {
        let mut off = body_start + 8; // linktype(2) + reserved(2) + snaplen(4)
        while off + 4 <= block_end {
            let code = self.u16(off);
            let len = self.u16(off + 2) as usize;
            if code == 0 {
                break; // opt_endofopt
            }
            if code == 9 && len >= 1 && off + 4 < block_end {
                let raw = self.data[off + 4];
                let resol = if raw & 0x80 != 0 {
                    // resolución binaria: 2^(raw & 0x7f) ticks/segundo
                    2u128.saturating_pow((raw & 0x7f) as u32)
                } else {
                    // resolución decimal: 10^(raw & 0x7f) ticks/segundo
                    10u128.saturating_pow((raw & 0x7f) as u32)
                };
                if resol > 0 {
                    self.ts_resol = resol as u64;
                }
            }
            off += 4 + len.div_ceil(4) * 4;
        }
    }
}

impl<'a> PacketSource<'a> for PcapngFileSource<'a> {
    fn next_packet(&mut self) -> Option<Result<PacketRecord<'a>, String>> {
        loop {
            if self.done {
                return None;
            }
            if self.pos + 12 > self.data.len() {
                self.done = true;
                return None;
            }
            self.last_off = self.pos as u64;
            let btype = self.u32(self.pos);
            let blen = self.u32(self.pos + 4) as usize;
            if blen < 12 || blen % 4 != 0 || self.pos + blen > self.data.len() {
                self.done = true;
                return Some(Err(format!(
                    "bloque pcapng corrupto en offset {}: len={blen}",
                    self.pos
                )));
            }
            let end = self.pos + blen;
            let body = self.pos + 8;
            let rec = match btype {
                BT_IDB => {
                    self.link = LinkType::from_code(self.u16(body));
                    self.parse_idb_options(body, end - 4);
                    None
                }
                BT_EPB => {
                    if body + 20 > end {
                        self.done = true;
                        return Some(Err("EPB truncado".into()));
                    }
                    let ts_hi = self.u32(body + 4) as u64;
                    let ts_lo = self.u32(body + 8) as u64;
                    let caplen = self.u32(body + 12) as usize;
                    let origlen = self.u32(body + 16);
                    let data_start = body + 20;
                    let padded = caplen.div_ceil(4) * 4;
                    if data_start + padded > end - 4 {
                        self.done = true;
                        return Some(Err(format!(
                            "EPB #{:}: caplen={} excede el bloque",
                            self.index, caplen
                        )));
                    }
                    let data = &self.data[data_start..data_start + caplen];
                    let raw_ts = (ts_hi << 32) | ts_lo;
                    let ts_us = ((raw_ts as u128 * 1_000_000u128) / self.ts_resol as u128) as u64;
                    self.pos = end;
                    let rec = PacketRecord {
                        index: self.index,
                        ts_us,
                        orig_len: origlen,
                        data,
                    };
                    self.index += 1;
                    Some(Ok(rec))
                }
                BT_SPB => {
                    if body + 4 > end {
                        self.done = true;
                        return Some(Err("SPB truncado".into()));
                    }
                    let origlen = self.u32(body) as usize;
                    let data_start = body + 4;
                    let padded = origlen.div_ceil(4) * 4;
                    if data_start + padded > end - 4 {
                        self.done = true;
                        return Some(Err("SPB con longitud mayor que el bloque".into()));
                    }
                    let data = &self.data[data_start..data_start + origlen];
                    self.pos = end;
                    let rec = PacketRecord {
                        index: self.index,
                        ts_us: 0, // SPB no lleva timestamp
                        orig_len: origlen as u32,
                        data,
                    };
                    self.index += 1;
                    Some(Ok(rec))
                }
                _ => None, // NRB, ISB, custom, etc.: se saltan
            };
            self.pos = end;
            if rec.is_some() {
                return rec;
            }
            if self.pos >= self.data.len() {
                self.done = true;
                return None;
            }
        }
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

    /// Construye un pcapng mínimo LE: SHB + IDB(Ethernet) + EPB.
    fn sample_pcapng() -> Vec<u8> {
        let mut v = Vec::new();
        // SHB (28 bytes)
        v.extend_from_slice(&BT_SHB.to_le_bytes());
        v.extend_from_slice(&28u32.to_le_bytes());
        v.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes()); // version major
        v.extend_from_slice(&0u16.to_le_bytes()); // minor
        v.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // section len
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&28u32.to_le_bytes());
        // IDB (20 bytes: 8 hdr + 8 body + 4 trailing)
        v.extend_from_slice(&BT_IDB.to_le_bytes());
        v.extend_from_slice(&20u32.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes()); // linktype Ethernet
        v.extend_from_slice(&0u16.to_le_bytes()); // reserved
        v.extend_from_slice(&65_535u32.to_le_bytes()); // snaplen
        v.extend_from_slice(&20u32.to_le_bytes());
        // EPB (32 + 4 datos + pad 0 = 36+... calculemos: header 8 + body 20 + data 4 + trailing 4 = 36)
        let data = [0xde, 0xad, 0xbe, 0xef];
        let blen = 8u32 + 20 + 4 + 4; // hdr + body + data + trailing
        v.extend_from_slice(&BT_EPB.to_le_bytes());
        v.extend_from_slice(&blen.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // iface
        v.extend_from_slice(&0u32.to_le_bytes()); // ts hi
        v.extend_from_slice(&1_735_689_600u32.to_le_bytes()); // ts lo (us)
        v.extend_from_slice(&4u32.to_le_bytes()); // caplen
        v.extend_from_slice(&4u32.to_le_bytes()); // origlen
        v.extend_from_slice(&data);
        v.extend_from_slice(&0u32.to_le_bytes()); // trailing len
        v
    }

    #[test]
    fn lee_epb_con_ts_resol_por_defecto() {
        let buf = sample_pcapng();
        let mut src = PcapngFileSource::new(&buf).unwrap();
        let rec = src.next_packet().unwrap().unwrap();
        assert_eq!(rec.index, 0);
        assert_eq!(rec.ts_us, 1_735_689_600);
        assert_eq!(rec.data, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(src.link_type(), LinkType::Ethernet);
        assert!(src.next_packet().is_none());
    }

    #[test]
    fn rechaza_bom_invalido() {
        let mut buf = sample_pcapng();
        buf[8..12].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        assert!(PcapngFileSource::new(&buf).is_err());
    }

    #[test]
    fn salta_bloques_desconocidos() {
        // pcapng con un bloque desconocido (custom 0x00000BAD) entre IDB y EPB.
        let mut v = Vec::new();
        // SHB
        v.extend_from_slice(&BT_SHB.to_le_bytes());
        v.extend_from_slice(&28u32.to_le_bytes());
        v.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&28u32.to_le_bytes());
        // Bloque custom (se debe saltar)
        v.extend_from_slice(&0x0000_0badu32.to_le_bytes());
        v.extend_from_slice(&16u32.to_le_bytes());
        v.extend_from_slice(&[0xaa; 4]);
        v.extend_from_slice(&16u32.to_le_bytes());
        // EPB
        let blen = 8u32 + 20 + 4 + 4;
        v.extend_from_slice(&BT_EPB.to_le_bytes());
        v.extend_from_slice(&blen.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&42u32.to_le_bytes());
        v.extend_from_slice(&4u32.to_le_bytes());
        v.extend_from_slice(&4u32.to_le_bytes());
        v.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        v.extend_from_slice(&blen.to_le_bytes());
        let mut src = PcapngFileSource::new(&v).unwrap();
        let rec = src.next_packet().unwrap().unwrap();
        assert_eq!(rec.ts_us, 42);
        assert_eq!(rec.data, &[0x01, 0x02, 0x03, 0x04]);
        assert!(src.next_packet().is_none());
    }

    #[test]
    fn ts_resol_nanosegundos() {
        // IDB con if_tsresol = 9 (10^-9 → nanosegundos).
        let mut v = Vec::new();
        v.extend_from_slice(&BT_SHB.to_le_bytes());
        v.extend_from_slice(&28u32.to_le_bytes());
        v.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&28u32.to_le_bytes());
        // IDB con opción if_tsresol: hdr 8 + body 8 + opt 8 + endofopt 4 + trailing 4 = 32
        v.extend_from_slice(&BT_IDB.to_le_bytes());
        v.extend_from_slice(&32u32.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes()); // Ethernet
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&65_535u32.to_le_bytes());
        v.extend_from_slice(&9u16.to_le_bytes()); // código if_tsresol
        v.extend_from_slice(&1u16.to_le_bytes()); // longitud
        v.extend_from_slice(&[9, 0, 0, 0]); // 10^9
        v.extend_from_slice(&0u16.to_le_bytes()); // opt_endofopt
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&32u32.to_le_bytes());
        // EPB con raw ts = 1_735_689_600_000_000_000 ns = 1_735_689_600 μs
        let blen = 8u32 + 20 + 4 + 4;
        v.extend_from_slice(&BT_EPB.to_le_bytes());
        v.extend_from_slice(&blen.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0x1816_687eu32.to_le_bytes()); // ts hi
        v.extend_from_slice(&0xc057_0000u32.to_le_bytes()); // ts lo
        v.extend_from_slice(&4u32.to_le_bytes());
        v.extend_from_slice(&4u32.to_le_bytes());
        v.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        v.extend_from_slice(&blen.to_le_bytes());
        let mut src = PcapngFileSource::new(&v).unwrap();
        let rec = src.next_packet().unwrap().unwrap();
        assert_eq!(rec.ts_us, 1_735_689_600_000_000, "ns → µs con if_tsresol=9");
    }
}
