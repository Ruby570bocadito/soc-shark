//! ICMP (echo request/reply y notificaciones básicas).

/// Mensaje ICMP diseccionado.
#[derive(Debug, Clone, Copy)]
pub struct IcmpPacket {
    pub kind: u8,
    pub code: u8,
    /// Identificador de echo (solo tipos 8/0 y 0/0).
    pub echo_id: Option<u16>,
    /// Número de secuencia de echo.
    pub echo_seq: Option<u16>,
}

impl IcmpPacket {
    pub fn summary(&self) -> &'static str {
        match (self.kind, self.code) {
            (8, 0) => "Echo request (ping)",
            (0, 0) => "Echo reply",
            (3, 0) => "Destination unreachable: net",
            (3, 1) => "Destination unreachable: host",
            (3, 3) => "Destination unreachable: port",
            (3, _) => "Destination unreachable",
            (11, 0) => "Time exceeded (TTL)",
            (5, _) => "Redirect",
            _ => "ICMP",
        }
    }
}

/// Parsea ICMP desde el payload IP.
pub fn parse_icmp(data: &[u8]) -> Option<IcmpPacket> {
    if data.len() < 4 {
        return None;
    }
    let kind = data[0];
    let code = data[1];
    let (echo_id, echo_seq) = if matches!((kind, code), (8, 0) | (0, 0)) && data.len() >= 8 {
        (
            Some(u16::from_be_bytes([data[4], data[5]])),
            Some(u16::from_be_bytes([data[6], data[7]])),
        )
    } else {
        (None, None)
    };
    Some(IcmpPacket {
        kind,
        code,
        echo_id,
        echo_seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_ping() {
        let mut v = vec![8, 0, 0, 0];
        v.extend_from_slice(&0x1234u16.to_be_bytes());
        v.extend_from_slice(&7u16.to_be_bytes());
        let p = parse_icmp(&v).unwrap();
        assert_eq!(p.summary(), "Echo request (ping)");
        assert_eq!(p.echo_seq, Some(7));
    }

    #[test]
    fn truncado_sin_panic() {
        assert!(parse_icmp(&[8, 0, 0]).is_none());
    }
}
