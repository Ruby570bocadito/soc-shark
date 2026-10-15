//! TCP (RFC 9293): segmento con flags y payload zero-copy.

/// Máscara de flags TCP.
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;

/// Segmento TCP diseccionado.
#[derive(Debug)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8, // en words de 4 bytes
    pub flags: u8,
    pub window: u16,
    pub urgent: u16,
    /// Payload de aplicación, prestado.
    pub payload: &'a [u8],
}

impl TcpSegment<'_> {
    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    pub fn is_syn(&self) -> bool {
        self.has(SYN)
    }
    pub fn is_ack(&self) -> bool {
        self.has(ACK)
    }
    pub fn is_fin(&self) -> bool {
        self.has(FIN)
    }
    pub fn is_rst(&self) -> bool {
        self.has(RST)
    }
    pub fn is_psh(&self) -> bool {
        self.has(PSH)
    }

    /// Notación clásica: `SYN,ACK`, `PSH,ACK`, `FIN,ACK`...
    pub fn flags_str(&self) -> String {
        let mut s = Vec::new();
        if self.is_syn() {
            s.push("SYN");
        }
        if self.is_ack() {
            s.push("ACK");
        }
        if self.is_fin() {
            s.push("FIN");
        }
        if self.is_rst() {
            s.push("RST");
        }
        if self.is_psh() {
            s.push("PSH");
        }
        if self.has(URG) {
            s.push("URG");
        }
        if s.is_empty() {
            s.push("NONE");
        }
        s.join(",")
    }
}

/// Parsea TCP; `None` si es malformado. Nunca hace panic.
pub fn parse_tcp(data: &[u8]) -> Option<TcpSegment<'_>> {
    if data.len() < 20 {
        return None;
    }
    let data_offset = (data[12] >> 4) as usize * 4;
    if data_offset < 20 || data_offset > data.len() {
        return None;
    }
    Some(TcpSegment {
        src_port: u16::from_be_bytes([data[0], data[1]]),
        dst_port: u16::from_be_bytes([data[2], data[3]]),
        seq: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        ack: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        data_offset: (data[12] >> 4) as u8,
        flags: data[13],
        window: u16::from_be_bytes([data[14], data[15]]),
        urgent: u16::from_be_bytes([data[16], data[17]]),
        payload: &data[data_offset..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&49_812u16.to_be_bytes());
        v.extend_from_slice(&443u16.to_be_bytes());
        v.extend_from_slice(&1000u32.to_be_bytes());
        v.extend_from_slice(&2000u32.to_be_bytes());
        v.push(0x50); // data_offset = 5
        v.push(flags);
        v.extend_from_slice(&64_000u16.to_be_bytes()); // window
        v.extend_from_slice(&0u16.to_be_bytes()); // checksum
        v.extend_from_slice(&0u16.to_be_bytes()); // urgent
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn flags_y_payload() {
        let buf = sample(SYN | ACK, b"hola");
        let t = parse_tcp(&buf).unwrap();
        assert_eq!(t.src_port, 49_812);
        assert_eq!(t.dst_port, 443);
        assert_eq!(t.flags_str(), "SYN,ACK");
        assert!(t.is_syn() && t.is_ack() && !t.is_rst());
        assert_eq!(t.payload, b"hola");
    }

    #[test]
    fn truncados_sin_panic() {
        let s = sample(0x18, b"0123456789");
        for n in 0..s.len() {
            let _ = parse_tcp(&s[..n]);
        }
        // data_offset inválido
        let mut bad = sample(0x18, b"");
        bad[12] = 0x40; // offset 0
        assert!(parse_tcp(&bad).is_none());
    }
}
