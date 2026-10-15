//! ARP (RFC 826): resuelve quién-tiene-qué-IP.

/// Paquete ARP (asumiendo hardware Ethernet y direcciones IPv4, el caso real).
#[derive(Debug, Clone, Copy)]
pub struct ArpPacket {
    /// 1 = request (who-has), 2 = reply (is-at).
    pub oper: u16,
    pub sha: [u8; 6], // sender hardware addr
    pub spa: [u8; 4], // sender protocol addr
    pub tha: [u8; 6], // target hardware addr
    pub tpa: [u8; 4], // target protocol addr
}

impl ArpPacket {
    pub fn is_request(&self) -> bool {
        self.oper == 1
    }

    /// Resumen legible: `Who has 192.168.1.10? Tell 192.168.1.50`.
    pub fn summary(&self) -> String {
        let ip = |b: &[u8]| format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
        if self.is_request() {
            format!("Who has {}? Tell {}", ip(&self.tpa), ip(&self.spa))
        } else {
            format!("{} is-at {}", ip(&self.spa), {
                let m = &self.sha;
                format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                )
            })
        }
    }
}

/// Parsea ARP desde el payload Ethernet (28 bytes mínimos).
pub fn parse_arp(data: &[u8]) -> Option<ArpPacket> {
    if data.len() < 28 {
        return None;
    }
    let htype = u16::from_be_bytes([data[0], data[1]]);
    let ptype = u16::from_be_bytes([data[2], data[3]]);
    if htype != 1 || ptype != 0x0800 {
        return None; // solo Ethernet+IPv4 en fase 1
    }
    let mut p = ArpPacket {
        oper: u16::from_be_bytes([data[6], data[7]]),
        sha: [0; 6],
        spa: [0; 4],
        tha: [0; 6],
        tpa: [0; 4],
    };
    p.sha.copy_from_slice(&data[8..14]);
    p.spa.copy_from_slice(&data[14..18]);
    p.tha.copy_from_slice(&data[18..24]);
    p.tpa.copy_from_slice(&data[24..28]);
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(oper: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&1u16.to_be_bytes()); // htype
        v.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype
        v.push(6); // hlen
        v.push(4); // plen
        v.extend_from_slice(&oper.to_be_bytes());
        v.extend_from_slice(&[0xaa; 6]); // sha
        v.extend_from_slice(&[192, 168, 1, 50]); // spa
        v.extend_from_slice(&[0; 6]); // tha
        v.extend_from_slice(&[192, 168, 1, 1]); // tpa
        v
    }

    #[test]
    fn request_y_reply() {
        let req = parse_arp(&sample(1)).unwrap();
        assert!(req.is_request());
        assert_eq!(req.summary(), "Who has 192.168.1.1? Tell 192.168.1.50");
        let rep = parse_arp(&sample(2)).unwrap();
        assert!(!rep.is_request());
        assert!(rep.summary().starts_with("192.168.1.50 is-at aa:"));
    }

    #[test]
    fn truncado_sin_panic() {
        for n in 0..28 {
            assert!(parse_arp(&sample(1)[..n]).is_none());
        }
    }
}
