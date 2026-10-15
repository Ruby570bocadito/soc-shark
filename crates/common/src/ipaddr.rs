//! Direcciones IP v4/v6 con clasificación y matching CIDR, std-only.
//!
//! Implementación propia en lugar de `std::net::IpAddr` porque necesitamos
//! `Hash + Ord` determinista sobre bytes, `Copy` barato y comparación de
//! prefijos para threat intel (listas de IOCs offline).

use std::fmt;

/// Dirección IP almacenada de forma compacta y copiable.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpAddr {
    /// Parsea una IPv4 punteada (`192.168.1.50`).
    pub fn parse_v4(s: &str) -> Option<IpAddr> {
        let mut out = [0u8; 4];
        let mut parts = s.split('.');
        for o in out.iter_mut() {
            let p = parts.next()?;
            if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            *o = p.parse::<u8>().ok()?;
        }
        if parts.next().is_some() {
            return None;
        }
        Some(IpAddr::V4(out))
    }

    /// Parsea una IPv6 (soporta `::`, prefijos cero y IPv4 embebida).
    pub fn parse_v6(s: &str) -> Option<IpAddr> {
        let s = s.trim_matches(|c| c == '[' || c == ']');
        let (head, tail) = match s.split_once("::") {
            Some((h, t)) => (h, Some(t)),
            None => (s, None),
        };
        if s.matches("::").count() > 1 {
            return None;
        }
        let parse_groups = |part: &str| -> Option<Vec<u16>> {
            if part.is_empty() {
                return Some(Vec::new());
            }
            let mut groups = Vec::new();
            for piece in part.split(':') {
                if piece.contains('.') {
                    // IPv4 embebida al final: 2 grupos
                    let v4 = IpAddr::parse_v4(piece)?;
                    groups.push(((v4.v4_bytes()[0] as u16) << 8) | v4.v4_bytes()[1] as u16);
                    groups.push(((v4.v4_bytes()[2] as u16) << 8) | v4.v4_bytes()[3] as u16);
                } else {
                    if piece.is_empty() || piece.len() > 4 {
                        return None;
                    }
                    groups.push(u16::from_str_radix(piece, 16).ok()?);
                }
            }
            Some(groups)
        };
        let mut head_groups = parse_groups(head)?;
        let tail_groups = match tail {
            Some(t) => parse_groups(t)?,
            None => Vec::new(),
        };
        let total = head_groups.len() + tail_groups.len();
        if tail.is_some() {
            if total > 7 {
                return None;
            }
            let zeros = 8 - total;
            let mut groups = head_groups.clone();
            groups.extend(std::iter::repeat(0u16).take(zeros));
            groups.extend(tail_groups);
            head_groups = groups;
        } else if total != 8 {
            return None;
        }
        let mut out = [0u8; 16];
        for (i, g) in head_groups.iter().enumerate() {
            out[i * 2] = (g >> 8) as u8;
            out[i * 2 + 1] = (g & 0xff) as u8;
        }
        Some(IpAddr::V6(out))
    }

    /// Parsea v4 o v6 según el contenido.
    pub fn parse(s: &str) -> Option<IpAddr> {
        if s.contains(':') {
            Self::parse_v6(s)
        } else {
            Self::parse_v4(s)
        }
    }

    pub fn v4_bytes(&self) -> &[u8; 4] {
        match self {
            IpAddr::V4(b) => b,
            IpAddr::V6(_) => panic!("v4_bytes sobre IPv6"),
        }
    }

    /// Bytes canónicos para claves de ordenación/agrupación.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            IpAddr::V4(b) => b.to_vec(),
            IpAddr::V6(b) => b.to_vec(),
        }
    }

    pub fn is_ipv4(&self) -> bool {
        matches!(self, IpAddr::V4(_))
    }

    pub fn is_multicast(&self) -> bool {
        match self {
            IpAddr::V4(b) => b[0] & 0xf0 == 0xe0,
            IpAddr::V6(b) => b[0] == 0xff,
        }
    }

    pub fn is_broadcast(&self) -> bool {
        matches!(self, IpAddr::V4([255, 255, 255, 255]))
    }

    /// Direcciones de enlace local, loopback, privadas (RFC1918/ULA) y
    /// no especificadas: no se consideran "externas" para las alertas.
    pub fn is_local_or_reserved(&self) -> bool {
        match self {
            IpAddr::V4(b) => {
                b[0] == 10
                    || (b[0] == 172 && b[1] & 0xf0 == 16)
                    || (b[0] == 192 && b[1] == 168)
                    || b[0] == 127
                    || (b[0] == 169 && b[1] == 254)
                    || b[0] == 0
                    || b[0] >= 224 // multicast + reservado + broadcast
            }
            IpAddr::V6(b) => {
                b[0] == 0x00 && b[..15].iter().all(|&x| x == 0) && (b[15] == 0 || b[15] == 1) // :: y ::1
                    || b[0] & 0xfe == 0xfc // ULA fc00::/7
                    || b[0] == 0xfe && b[1] & 0xc0 == 0x80 // link-local fe80::/10
                    || b[0] == 0xff
            }
        }
    }

    /// ¿Es una IP global alcanzable (candidata a destino externo)?
    pub fn is_global_candidate(&self) -> bool {
        !self.is_local_or_reserved() && !self.is_multicast() && !self.is_broadcast()
    }

    /// Comprueba si la IP cae dentro de un CIDR `a.b.c.d/n` o `x::y/n`.
    pub fn in_cidr(&self, cidr: &str) -> bool {
        let Some((addr, plen)) = cidr
            .split_once('/')
            .and_then(|(a, p)| p.parse::<u32>().ok().map(|n| (a, n)))
        else {
            // Sin prefijo: igualdad exacta
            return match IpAddr::parse(cidr) {
                Some(o) => self == &o,
                None => false,
            };
        };
        let other = match IpAddr::parse(addr) {
            Some(o) => o,
            None => return false,
        };
        match (self, other) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let plen = plen.min(32);
                let na = u32::from_be_bytes(*a) >> (32 - plen);
                let nb = u32::from_be_bytes(b) >> (32 - plen);
                na == nb
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let plen = plen.min(128);
                prefix_eq(a, &b, plen)
            }
            _ => false,
        }
    }
}

fn prefix_eq(a: &[u8; 16], b: &[u8; 16], plen: u32) -> bool {
    let full = plen / 8;
    if a[..full as usize] != b[..full as usize] {
        return false;
    }
    let rem = plen % 8;
    if rem == 0 {
        true
    } else {
        let mask = 0xffu8 << (8 - rem);
        a[full as usize] & mask == b[full as usize] & mask
    }
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddr::V4(b) => write!(f, "{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
            IpAddr::V6(b) => {
                // RFC 5952 simplificado: comprime la run de ceros más larga (≥2).
                let groups: Vec<u16> = (0..8)
                    .map(|i| ((b[i * 2] as u16) << 8) | b[i * 2 + 1] as u16)
                    .collect();
                let (mut best_start, mut best_len) = (usize::MAX, 0usize);
                let (mut cur_start, mut cur_len) = (0usize, 0usize);
                for (i, g) in groups.iter().enumerate() {
                    if *g == 0 {
                        if cur_len == 0 {
                            cur_start = i;
                        }
                        cur_len += 1;
                        if cur_len > best_len {
                            best_len = cur_len;
                            best_start = cur_start;
                        }
                    } else {
                        cur_len = 0;
                    }
                }
                let hex = |g: &u16| format!("{g:x}");
                if best_len < 2 {
                    let parts: Vec<String> = groups.iter().map(hex).collect();
                    return f.write_str(&parts.join(":"));
                }
                let head: Vec<String> = groups[..best_start].iter().map(hex).collect();
                let tail: Vec<String> = groups[best_start + best_len..].iter().map(hex).collect();
                let mut s = head.join(":");
                s.push_str("::");
                s.push_str(&tail.join(":"));
                f.write_str(&s)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parseo_v4() {
        assert!(IpAddr::parse("192.168.1.50").is_some());
        assert!(IpAddr::parse("256.1.1.1").is_none());
        assert!(IpAddr::parse("1.2.3").is_none());
        assert!(IpAddr::parse("1.2.3.4.5").is_none());
        assert_eq!(
            format!("{}", IpAddr::parse("10.0.0.1").unwrap()),
            "10.0.0.1"
        );
    }

    #[test]
    fn parseo_v6() {
        assert_eq!(format!("{}", IpAddr::parse("::1").unwrap()), "::1");
        assert_eq!(
            format!(
                "{}",
                IpAddr::parse("2001:0db8:0000:0000:0000:0000:0000:0001").unwrap()
            ),
            "2001:db8::1"
        );
        assert_eq!(format!("{}", IpAddr::parse("fe80::1").unwrap()), "fe80::1");
        assert_eq!(
            format!("{}", IpAddr::parse("::ffff:192.168.1.1").unwrap()),
            "::ffff:c0a8:101"
        );
        assert!(IpAddr::parse("2001::1::2").is_none());
    }

    #[test]
    fn clasificacion() {
        let t = IpAddr::parse("185.22.1.9").unwrap();
        let lan = IpAddr::parse("192.168.1.50").unwrap();
        let mc = IpAddr::parse("239.255.255.250").unwrap();
        assert!(t.is_global_candidate());
        assert!(!lan.is_global_candidate());
        assert!(mc.is_multicast());
        assert!(IpAddr::parse("255.255.255.255").unwrap().is_broadcast());
    }

    #[test]
    fn cidr_matching() {
        let t = IpAddr::parse("185.220.101.4").unwrap();
        assert!(t.in_cidr("185.220.101.0/24"));
        assert!(!t.in_cidr("185.220.102.0/24"));
        assert!(t.in_cidr("185.220.0.0/16"));
        assert!(IpAddr::parse("fe80::1").unwrap().in_cidr("fe80::/10"));
        assert!(IpAddr::parse("2001:db8::5")
            .unwrap()
            .in_cidr("2001:db8::/32"));
    }
}
