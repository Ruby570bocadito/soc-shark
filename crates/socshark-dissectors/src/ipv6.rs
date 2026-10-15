//! Dissector IPv6 (Fase 2): cabecera fija de 40 bytes y recorrido de
//! cabeceras de extensión.
//!
//! Extensiones soportadas: Hop-by-Hop (0), Routing (43), Destinos (60),
//! Fragment (44, solo el primer fragmento produce L4) y AH (51). ESP y
//! cualquier otra extensión terminalizan el recorrido con
//! `next_header` sin interpretar, igual que haría un parser honesto.

use std::net::Ipv6Addr;

/// Metadatos de la cabecera IPv6 (post-recorrido de extensiones).
#[derive(Debug, Clone)]
pub struct Ipv6Info {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    /// Protocolo L4 efectivo (6=TCP, 17=UDP, 58=ICMPv6, ...) tras las
    /// cabeceras de extensión.
    pub next_header: u8,
    pub hop_limit: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    /// Tipos de cabecera de extensión recorridos, en orden.
    pub extensions: Vec<u8>,
}

/// Parsea IPv6 y devuelve `(info, payload_l4)`.
///
/// Devuelve `None` si la trama es demasiado corta, la versión no es 6 o el
/// paquete es un fragmento no inicial (sin L4 interpretable).
pub fn parse_ipv6(data: &[u8]) -> Option<(Ipv6Info, &[u8])> {
    if data.len() < 40 || data[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let mut info = Ipv6Info {
        src: Ipv6Addr::new(
            u16::from_be_bytes([data[8], data[9]]),
            u16::from_be_bytes([data[10], data[11]]),
            u16::from_be_bytes([data[12], data[13]]),
            u16::from_be_bytes([data[14], data[15]]),
            u16::from_be_bytes([data[16], data[17]]),
            u16::from_be_bytes([data[18], data[19]]),
            u16::from_be_bytes([data[20], data[21]]),
            u16::from_be_bytes([data[22], data[23]]),
        ),
        dst: Ipv6Addr::new(
            u16::from_be_bytes([data[24], data[25]]),
            u16::from_be_bytes([data[26], data[27]]),
            u16::from_be_bytes([data[28], data[29]]),
            u16::from_be_bytes([data[30], data[31]]),
            u16::from_be_bytes([data[32], data[33]]),
            u16::from_be_bytes([data[34], data[35]]),
            u16::from_be_bytes([data[36], data[37]]),
            u16::from_be_bytes([data[38], data[39]]),
        ),
        next_header: data[6],
        hop_limit: data[7],
        traffic_class: ((data[0] & 0x0f) << 4) | (data[1] >> 4),
        flow_label: (((data[1] & 0x0f) as u32) << 16)
            | u32::from_be_bytes([data[2], data[3], 0, 0]) >> 8,
        extensions: Vec::new(),
    };

    let end = (40usize)
        .checked_add(payload_len)
        .map(|e| e.min(data.len()))
        .unwrap_or(data.len());
    let mut off = 40usize;
    let mut nh = info.next_header;

    // Recorrido de cabeceras de extensión (máx. 8: no hay cadena legítima
    // tan larga y acota bucles maliciosos).
    for _ in 0..8 {
        match nh {
            0 | 43 | 60 => {
                // NextHeader(1) + HdrExtLen(1) + cuerpo: len = (ext+1)*8.
                if off + 2 > end {
                    return None;
                }
                let ext_len = (data[off + 1] as usize + 1) * 8;
                if off + ext_len > end {
                    return None;
                }
                info.extensions.push(nh);
                nh = data[off];
                off += ext_len;
            }
            44 => {
                // Fragment: NextHeader(1) + Res(1) + FragmentOffset/Flags(2) + ID(4).
                if off + 8 > end {
                    return None;
                }
                let frag_offset = u16::from_be_bytes([data[off + 2], data[off + 3]]) & 0xfff8;
                info.extensions.push(44);
                nh = data[off];
                off += 8;
                if frag_offset != 0 {
                    // Fragmento no inicial: L4 no interpretable sin reensamblado.
                    return None;
                }
            }
            51 => {
                // AH: NextHeader(1) + PayloadLen(1); longitud = (len+2)*4.
                if off + 2 > end {
                    return None;
                }
                let ah_len = (data[off + 1] as usize + 2) * 4;
                if off + ah_len > end {
                    return None;
                }
                info.extensions.push(51);
                nh = data[off];
                off += ah_len;
            }
            _ => break,
        }
    }

    info.next_header = nh;
    if off > end {
        return None;
    }
    Some((info, &data[off..end]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_testgen as tg;

    #[test]
    fn header_minimo_udp() {
        let qmsg = tg::dns_query(1, "v6.example", 28);
        let frame = tg::frame_ipv6_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A6,
            tg::DNS6,
            53001,
            53,
            &qmsg,
        );
        let (info, l4) = parse_ipv6(&frame[14..]).unwrap();
        assert_eq!(info.src, tg::HOST_A6);
        assert_eq!(info.dst, tg::DNS6);
        assert_eq!(info.next_header, 17);
        assert!(info.extensions.is_empty());
        // Puerto origen 53001 = 0xcf 0x29 al inicio del datagrama UDP.
        assert_eq!(&l4[..2], &53001u16.to_be_bytes());
        assert_eq!(l4.len(), 8 + qmsg.len());
    }

    #[test]
    fn cadena_de_extensiones_hop_by_hop_y_routing() {
        // IPv6 + HBH(8B) + Routing(8B) + UDP(8B vacío).
        let mut ip = Vec::new();
        ip.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // ver/tc/fl
        let payload_len = 8 + 8 + 8;
        ip.extend_from_slice(&(payload_len as u16).to_be_bytes());
        ip.push(0); // next = HBH
        ip.push(64); // hop limit
        ip.extend_from_slice(&tg::HOST_A6.octets());
        ip.extend_from_slice(&tg::DNS6.octets());
        // HBH: next=43 (Routing), ext_len=0 → 8 bytes
        ip.extend_from_slice(&[43, 0, 0, 0, 0, 0, 0, 0]);
        // Routing: next=17 (UDP), ext_len=0 → 8 bytes
        ip.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
        // UDP mínimo
        ip.extend_from_slice(&tg::udp(1000, 2000, &[]));

        let (info, l4) = parse_ipv6(&ip).unwrap();
        assert_eq!(info.extensions, vec![0, 43]);
        assert_eq!(info.next_header, 17);
        assert_eq!(l4.len(), 8);
    }

    #[test]
    fn fragmento_no_inicial_devuelve_none() {
        let mut ip = vec![0u8; 40 + 8];
        ip[0] = 0x60;
        ip[6] = 44; // fragment
        ip[40] = 17; // next = udp
        ip[42] = 0x00;
        ip[43] = 0x08; // offset = 8 → no es el primer fragmento
        assert!(parse_ipv6(&ip).is_none());
    }

    #[test]
    fn truncado_no_panics() {
        let frame = tg::frame_ipv6_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A6,
            tg::DNS6,
            53001,
            53,
            &tg::dns_query(1, "v6.example", 28),
        );
        let total = frame.len();
        for cut in 0..=total.min(80) {
            let start = 14.min(cut);
            let _ = parse_ipv6(&frame[start..cut]);
        }
    }
}
