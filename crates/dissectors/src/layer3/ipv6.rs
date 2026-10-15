//! IPv6 (RFC 8200) con salto de extension headers básicos.

use socshark_common::ipaddr::IpAddr;

/// Extension headers que se saltan para llegar al L4.
fn is_extension_header(nh: u8) -> bool {
    matches!(nh, 0 | 43 | 44 | 51 | 60 | 135)
}

/// Paquete IPv6 diseccionado.
#[derive(Debug)]
pub struct Ipv6Packet<'a> {
    pub traffic_class: u8,
    pub flow_label: u32,
    /// Protocolo L4 real (tras saltar extension headers).
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub payload: &'a [u8],
    /// Número de extension headers saltados.
    pub ext_headers: u8,
    /// ¿Fragmento que no empieza en 0?
    pub non_first_fragment: bool,
}

/// Parsea IPv6; `None` si es malformado. Nunca hace panic.
pub fn parse_ipv6(data: &[u8]) -> Option<Ipv6Packet<'_>> {
    if data.len() < 40 {
        return None;
    }
    let ver_tc_fl = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if ver_tc_fl >> 28 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let mut next_header = data[6];
    let hop_limit = data[7];
    let mut s16 = [0u8; 16];
    s16.copy_from_slice(&data[8..24]);
    let src = IpAddr::V6(s16);
    s16.copy_from_slice(&data[24..40]);
    let dst = IpAddr::V6(s16);

    // Salta extension headers (límite de seguridad).
    let mut off = 40usize;
    let mut ext = 0u8;
    let mut non_first_frag = false;
    while is_extension_header(next_header) && off < data.len() {
        if next_header == 44 {
            // Fragment header: longitud fija 8; offset en bytes 2-3.
            if off + 8 > data.len() {
                return None;
            }
            let fo = u16::from_be_bytes([data[off + 2], data[off + 3]]);
            if fo & 0x1fff != 0 {
                non_first_frag = true;
            }
            next_header = data[off];
            off += 8;
        } else {
            if off + 2 > data.len() {
                return None;
            }
            next_header = data[off];
            let ext_len = (data[off + 1] as usize + 1) * 8;
            off += ext_len;
        }
        ext += 1;
        if ext > 8 {
            return None; // cadena de extensiones anómala
        }
    }
    let end = if payload_len == 0 {
        data.len()
    } else {
        (40 + payload_len).min(data.len())
    };
    let start = off.min(end);
    Some(Ipv6Packet {
        traffic_class: ((ver_tc_fl >> 20) & 0xff) as u8,
        flow_label: ver_tc_fl & 0x000f_ffff,
        next_header,
        hop_limit,
        src,
        dst,
        payload: &data[start..end],
        ext_headers: ext,
        non_first_fragment: non_first_frag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(nh: u8) -> Vec<u8> {
        let mut v = vec![0x60u8, 0x00, 0x00, 0x00, 0x00, 0x04, nh, 0x40];
        v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        v.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        v
    }

    #[test]
    fn parsea_basico() {
        let buf = sample(6);
        let p = parse_ipv6(&buf).unwrap();
        assert_eq!(p.next_header, 6);
        assert_eq!(p.src.to_string(), "2001:db8::1");
        assert_eq!(p.dst.to_string(), "2001:db8::2");
        assert_eq!(p.payload, &[0xca, 0xfe, 0xba, 0xbe]);
        assert_eq!(p.ext_headers, 0);
    }

    #[test]
    fn salta_hop_by_hop() {
        // Añade un hop-by-hop (len=0 → 8 bytes) antes del TCP.
        let mut v = sample(0);
        // nh hop-by-hop en cabecera fija; ext: nh=6, len=0
        v[4..6].copy_from_slice(&12u16.to_be_bytes()); // payload_len
        let mut ext = vec![6u8, 0, 0, 0, 0, 0, 0, 0];
        ext.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        v.truncate(40);
        v.extend_from_slice(&ext);
        let p = parse_ipv6(&v).unwrap();
        assert_eq!(p.next_header, 6);
        assert_eq!(p.ext_headers, 1);
        assert_eq!(p.payload, &[0xca, 0xfe, 0xba, 0xbe]);
    }

    #[test]
    fn truncados_sin_panic() {
        let s = sample(17);
        for n in 0..s.len() {
            let _ = parse_ipv6(&s[..n]);
        }
    }
}
