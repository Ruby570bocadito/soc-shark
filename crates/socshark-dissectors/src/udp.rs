//! Dissector UDP.

/// Metadatos de la cabecera UDP.
#[derive(Debug, Clone, Copy)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    /// Campo length de la cabecera (cabecera + payload).
    pub length: u16,
}

/// Parsea UDP y devuelve `(info, payload)`.
///
/// El payload se recorta con el campo `length` si es consistente; si el
/// valor es mentiroso (paquetes crafted), se usa el límite físico disponible
/// para no perder bytes ni leer fuera de rango.
pub fn parse_udp(data: &[u8]) -> Option<(UdpInfo, &[u8])> {
    if data.len() < 8 {
        return None;
    }
    let length = u16::from_be_bytes([data[4], data[5]]);
    let end = (length as usize).clamp(8, data.len());
    let info = UdpInfo {
        src_port: u16::from_be_bytes([data[0], data[1]]),
        dst_port: u16::from_be_bytes([data[2], data[3]]),
        length,
    };
    Some((info, &data[8..end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagrama_basico() {
        let mut b = Vec::new();
        b.extend_from_slice(&8080u16.to_be_bytes());
        b.extend_from_slice(&53u16.to_be_bytes());
        b.extend_from_slice(&12u16.to_be_bytes()); // 8 cabecera + 4 payload
        b.extend_from_slice(&[0, 0]); // checksum 0 (no verificado en IPv4)
        b.extend_from_slice(&[1, 2, 3, 4]);
        b.extend_from_slice(&[0xde, 0xad]); // relleno que debe recortarse

        let (info, payload) = parse_udp(&b).unwrap();
        assert_eq!(info.src_port, 8080);
        assert_eq!(info.dst_port, 53);
        assert_eq!(payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn length_mentiroso_no_expone_bytes_de_mas() {
        let mut b = vec![0u8; 8];
        b[4..6].copy_from_slice(&1000u16.to_be_bytes()); // length imposible
        b.extend_from_slice(&[1, 2]);
        let (_, payload) = parse_udp(&b).unwrap();
        assert_eq!(payload.len(), 2); // clamped al tamaño real
    }
}
