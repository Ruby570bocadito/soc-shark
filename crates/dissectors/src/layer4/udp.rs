//! UDP (RFC 768).

/// Datagrama UDP diseccionado.
#[derive(Debug)]
pub struct UdpDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    /// Longitud declarada (cabecera + datos).
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

/// Parsea UDP; `None` si es malformado. Nunca hace panic.
pub fn parse_udp(data: &[u8]) -> Option<UdpDatagram<'_>> {
    if data.len() < 8 {
        return None;
    }
    let length = u16::from_be_bytes([data[4], data[5]]) as usize;
    let end = if length == 0 {
        data.len()
    } else {
        length.min(data.len())
    };
    if end < 8 {
        return None;
    }
    Some(UdpDatagram {
        src_port: u16::from_be_bytes([data[0], data[1]]),
        dst_port: u16::from_be_bytes([data[2], data[3]]),
        length: end as u16,
        checksum: u16::from_be_bytes([data[6], data[7]]),
        payload: &data[8..end],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&53_530u16.to_be_bytes());
        v.extend_from_slice(&53u16.to_be_bytes());
        v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn parsea_basico() {
        let buf = sample(b"abcd");
        let u = parse_udp(&buf).unwrap();
        assert_eq!(u.src_port, 53_530);
        assert_eq!(u.dst_port, 53);
        assert_eq!(u.length, 12);
        assert_eq!(u.payload, b"abcd");
    }

    #[test]
    fn truncados_sin_panic() {
        let s = sample(b"0123456789");
        for n in 0..s.len() {
            let _ = parse_udp(&s[..n]);
        }
    }
}
