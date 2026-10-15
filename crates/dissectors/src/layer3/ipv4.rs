//! IPv4 (RFC 791): cabecera fija + opciones, con detección de fragmentos.

use socshark_common::ipaddr::IpAddr;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// Paquete IPv4 diseccionado.
#[derive(Debug)]
pub struct Ipv4Packet<'a> {
    pub ihl: u8,
    pub dscp: u8,
    pub total_len: u16,
    pub id: u16,
    /// Bits de flags (R/DF/MF en los 3 bits altos).
    pub flags: u8,
    /// Offset de fragmento en unidades de 8 bytes.
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Payload (L4), truncado a `total_len` si el snaplen cortó.
    pub payload: &'a [u8],
}

impl Ipv4Packet<'_> {
    /// ¿Más fragmentos o desplazamiento no nulo? (no es el primer segmento o
    /// hay más detrás — el reensamblado llega en fase 4).
    pub fn is_fragmented(&self) -> bool {
        self.frag_off != 0 || self.flags & 0x1 != 0
    }

    /// ¿Es un fragmento que no empieza en 0 (no dissecable a L4)?
    pub fn is_non_first_fragment(&self) -> bool {
        self.frag_off != 0
    }

    /// Verificación del checksum de cabecera (para calidad de datos).
    pub fn checksum_ok(&self, raw: &[u8]) -> bool {
        if raw.len() < 20 {
            return false;
        }
        let ihl = (raw[0] & 0x0f) as usize * 4;
        if ihl < 20 || ihl > raw.len() {
            return false;
        }
        let mut sum = 0u32;
        let mut i = 0;
        while i < ihl {
            let w = u16::from_be_bytes([raw[i], raw[i + 1]]);
            sum += w as u32;
            i += 2;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !sum as u16 == 0
    }
}

/// Parsea IPv4; `None` si es malformado. Nunca hace panic.
pub fn parse_ipv4(data: &[u8]) -> Option<Ipv4Packet<'_>> {
    if data.len() < 20 {
        return None;
    }
    let version = data[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl_words = data[0] & 0x0f;
    if ihl_words < 5 {
        return None; // IHL mínimo = 20 bytes
    }
    let ihl = ihl_words as usize * 4;
    if ihl > data.len() {
        return None;
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if total_len < ihl {
        return None;
    }
    // El snaplen puede haber truncado el paquete: acota al disponible.
    let end = total_len.min(data.len());
    let flags_frag = u16::from_be_bytes([data[6], data[7]]);
    let mut s4 = [0u8; 4];
    s4.copy_from_slice(&data[12..16]);
    let src = IpAddr::V4(s4);
    s4.copy_from_slice(&data[16..20]);
    let dst = IpAddr::V4(s4);
    Some(Ipv4Packet {
        ihl: ihl_words,
        dscp: data[1] >> 2,
        total_len: total_len as u16,
        id: u16::from_be_bytes([data[4], data[5]]),
        flags: (flags_frag >> 13) as u8,
        frag_off: flags_frag & 0x1fff,
        ttl: data[8],
        protocol: data[9],
        checksum: u16::from_be_bytes([data[10], data[11]]),
        src,
        dst,
        payload: &data[ihl..end],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cabecera IPv4 válida con checksum correcto.
    fn sample(proto: u8) -> Vec<u8> {
        let mut v = vec![
            0x45u8, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00, 0x40, proto, 0, 0,
        ];
        v.extend_from_slice(&[192, 168, 1, 50]);
        v.extend_from_slice(&[93, 184, 216, 34]);
        v.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload
                                                        // checksum: suma de words en 0..20 (con checksum=0)
        let mut sum = 0u32;
        for w in v[0..20].chunks(2) {
            sum += u16::from_be_bytes([w[0], w[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let ck = !(sum as u16);
        v[10..12].copy_from_slice(&ck.to_be_bytes());
        v
    }

    #[test]
    fn parsea_y_verifica_checksum() {
        let buf = sample(PROTO_TCP);
        let p = parse_ipv4(&buf).unwrap();
        assert_eq!(p.protocol, PROTO_TCP);
        assert_eq!(p.src.to_string(), "192.168.1.50");
        assert_eq!(p.dst.to_string(), "93.184.216.34");
        assert_eq!(p.payload, &[0xde, 0xad, 0xbe, 0xef]);
        assert!(!p.is_fragmented());
        assert!(p.checksum_ok(&sample(PROTO_TCP)));
    }

    #[test]
    fn detecta_fragmentos() {
        let mut v = sample(PROTO_UDP);
        v[6..8].copy_from_slice(&0x2005u16.to_be_bytes()); // MF + offset 5
        let p = parse_ipv4(&v).unwrap();
        assert!(p.is_fragmented());
        assert!(p.is_non_first_fragment());
    }

    #[test]
    fn truncados_sin_panic() {
        let s = sample(PROTO_TCP);
        for n in 0..s.len() {
            let r = parse_ipv4(&s[..n]);
            if let Some(p) = r {
                let _ = p.payload.len();
            }
        }
        // versión incorrecta
        let mut bad = sample(PROTO_TCP);
        bad[0] = 0x65;
        assert!(parse_ipv4(&bad).is_none());
        // IHL inválido
        let mut bad2 = sample(PROTO_TCP);
        bad2[0] = 0x43;
        assert!(parse_ipv4(&bad2).is_none());
    }
}
