//! Dissector TCP: cabecera fija, flags y opciones.

/// Flags TCP decodificados de un byte.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    pub fn from_byte(b: u8) -> Self {
        Self {
            fin: b & 0x01 != 0,
            syn: b & 0x02 != 0,
            rst: b & 0x04 != 0,
            psh: b & 0x08 != 0,
            ack: b & 0x10 != 0,
            urg: b & 0x20 != 0,
            ece: b & 0x40 != 0,
            cwr: b & 0x80 != 0,
        }
    }
}

/// Metadatos de la cabecera TCP.
#[derive(Debug, Clone)]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack_number: u32,
    pub flags: TcpFlags,
    pub window: u16,
    /// Longitud de opciones en bytes (`data_offset * 4 - 20`).
    pub options_len: usize,
}

/// Parsea TCP y devuelve `(info, payload)`.
///
/// El payload de un SYN/SYN-ACK (raro pero posible: TCP Fast Open) se
/// entrega igualmente.
pub fn parse_tcp(data: &[u8]) -> Option<(TcpInfo, &[u8])> {
    if data.len() < 20 {
        return None;
    }
    let data_offset = (data[12] >> 4) as usize * 4;
    if data_offset < 20 || data.len() < data_offset {
        return None;
    }
    let info = TcpInfo {
        src_port: u16::from_be_bytes([data[0], data[1]]),
        dst_port: u16::from_be_bytes([data[2], data[3]]),
        seq: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        ack_number: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        flags: TcpFlags::from_byte(data[13]),
        window: u16::from_be_bytes([data[14], data[15]]),
        options_len: data_offset - 20,
    };
    Some((info, &data[data_offset..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_byte_completo() {
        // 0b10110010 = CWR(0x80) + URG(0x20) + ACK(0x10) + SYN(0x02)
        let f = TcpFlags::from_byte(0b10110010);
        assert!(f.cwr && f.urg && f.ack && f.syn);
        assert!(!f.ece && !f.fin && !f.rst && !f.psh);
    }

    #[test]
    fn segmento_minimo_y_con_opciones() {
        let mut b = vec![0u8; 20];
        b[12] = 0x50; // data_offset = 5 (20 bytes)
        let (info, payload) = parse_tcp(&b).unwrap();
        assert_eq!(info.options_len, 0);
        assert!(payload.is_empty());

        let mut con_opciones = vec![0u8; 24];
        con_opciones[12] = 0x60; // data_offset = 6 (24 bytes)
        let (info2, _) = parse_tcp(&con_opciones).unwrap();
        assert_eq!(info2.options_len, 4);
    }

    #[test]
    fn data_offset_mentiroso_devuelve_none() {
        let mut b = vec![0u8; 20];
        b[12] = 0xf0; // data_offset = 15 → 60 bytes, pero solo hay 20
        assert!(parse_tcp(&b).is_none());
    }
}
