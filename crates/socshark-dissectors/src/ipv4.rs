//! Dissector IPv4 con verificación de checksum.
//!
//! Los fragmentos IP (MF=1 u offset > 0) se entregan al L4 tal cual: el
//! reensamblado de datagramas fragmentados es trabajo del Stream Reassembler
//! (Fase 2+, ver `docs/pipeline.md`).

use std::net::Ipv4Addr;

/// Metadatos de la cabecera IPv4.
#[derive(Debug, Clone)]
pub struct Ipv4Info {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    /// Número de protocolo IP (6=TCP, 17=UDP, 1=ICMP, ...).
    pub protocol: u8,
    pub ttl: u8,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    /// Offset de fragmento en unidades de 8 bytes.
    pub fragment_offset: u16,
    /// Resultado de validar el checksum de cabecera.
    pub checksum_ok: bool,
}

/// Parsea IPv4 y devuelve `(info, payload_l4)`.
///
/// El payload se recorta según `total_len` cuando es consistente; si el
/// paquete trae relleno Ethernet (padding) o `total_len` mentiroso, se usa
/// el límite seguro disponible.
pub fn parse_ipv4(data: &[u8]) -> Option<(Ipv4Info, &[u8])> {
    if data.len() < 20 {
        return None;
    }
    let ver_ihl = data[0];
    if ver_ihl >> 4 != 4 {
        return None;
    }
    let ihl = (ver_ihl & 0x0f) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let end = total_len.clamp(ihl, data.len());
    let flags_frag = u16::from_be_bytes([data[6], data[7]]);

    let info = Ipv4Info {
        src: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
        dst: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        protocol: data[9],
        ttl: data[8],
        identification: u16::from_be_bytes([data[4], data[5]]),
        dont_fragment: flags_frag & 0x4000 != 0,
        more_fragments: flags_frag & 0x2000 != 0,
        fragment_offset: flags_frag & 0x1fff,
        checksum_ok: header_checksum_ok(&data[..ihl]),
    };
    Some((info, &data[ihl..end]))
}

/// Suma de complemento a uno sobre palabras de 16 bits big-endian.
fn ones_complement_sum(bytes: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    // Si queda un byte suelto (longitud impar), se cuenta como palabra alta.
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    sum
}

/// Verifica el checksum de cabecera IPv4: la suma de toda la cabecera
/// (checksum correcto incluido) debe plegarse a 0xffff.
fn header_checksum_ok(header: &[u8]) -> bool {
    let mut s = ones_complement_sum(header);
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16 == 0xffff
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_testgen as tg;

    #[test]
    fn checksum_valido_y_corrupto() {
        let frame = tg::frame_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::DNS_EXT,
            53001,
            53,
            &[1, 2, 3],
        );
        // Cabecera IPv4: a partir del byte 14 de la trama Ethernet.
        let ip = &frame[14..34];
        assert!(header_checksum_ok(ip));

        let mut corrompida = ip.to_vec();
        corrompida[8] ^= 0xff; // rompe el TTL
        assert!(!header_checksum_ok(&corrompida));
    }

    #[test]
    fn opciones_ihl_se_respetan() {
        // Cabecera con IHL=6 (24 bytes): construida a mano con opciones.
        let mut ip = vec![0u8; 24];
        ip[0] = 0x46; // versión 4, IHL 6
        ip[2..4].copy_from_slice(&24u16.to_be_bytes());
        ip[8] = 64; // ttl
        ip[9] = 17; // udp
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let ck = tests_support::checksum16(&ip);
        ip[10..12].copy_from_slice(&ck.to_be_bytes());

        let (info, payload) = parse_ipv4(&ip).unwrap();
        assert_eq!(info.src, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(payload.len(), 0);
    }
}

/// Soporte de tests interno (checksum reutilizable).
#[cfg(test)]
pub(crate) mod tests_support {
    pub fn checksum16(bytes: &[u8]) -> u16 {
        let mut s = 0u32;
        let mut i = 0;
        while i + 1 < bytes.len() {
            s += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
            i += 2;
        }
        if i < bytes.len() {
            s += (bytes[i] as u32) << 8;
        }
        while s >> 16 != 0 {
            s = (s & 0xffff) + (s >> 16);
        }
        !(s as u16)
    }
}
