//! Dissector Ethernet (incluye VLAN 802.1Q y QinQ 802.1ad, hasta 2 etiquetas).

/// Metadatos de la cabecera Ethernet.
#[derive(Debug, Clone)]
pub struct EthernetInfo {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    /// Ethertype del payload (0x0800 IPv4, 0x0806 ARP, 0x86DD IPv6, ...).
    /// En tramas VLAN contiene el ethertype interior tras las etiquetas
    /// 802.1Q/802.1ad.
    pub ethertype: u16,
}

impl EthernetInfo {
    pub fn src_mac_str(&self) -> String {
        crate::fmt_mac(&self.src_mac)
    }

    pub fn dst_mac_str(&self) -> String {
        crate::fmt_mac(&self.dst_mac)
    }
}

/// TPIDs de etiqueta VLAN reconocidos: 802.1Q (0x8100), 802.1ad/QinQ
/// (0x88a8) y el 0x9100 histórico de algunos conmutadores.
const VLAN_TPIDS: [u16; 3] = [0x8100, 0x88a8, 0x9100];
/// Etiquetas VLAN apiladas que se recorren como mucho (QinQ = 2).
const MAX_VLAN_TAGS: usize = 2;

/// Parsea la cabecera Ethernet y devuelve `(info, payload_l3)`.
///
/// Devuelve `None` si la trama es demasiado corta. Recorre hasta
/// [`MAX_VLAN_TAGS`] etiquetas VLAN (802.1Q y QinQ 802.1ad); si quedan más,
/// `ethertype` conserva el TPID sin resolver y el pipeline no lo trata como IP.
pub fn parse_ethernet(data: &[u8]) -> Option<(EthernetInfo, &[u8])> {
    if data.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut l3_off = 14;

    for _ in 0..MAX_VLAN_TAGS {
        if !VLAN_TPIDS.contains(&ethertype) {
            break;
        }
        // TPID(2) + TCI(2); el siguiente ethertype viene después del TCI.
        let next = data.get(l3_off + 2..l3_off + 4)?;
        ethertype = u16::from_be_bytes([next[0], next[1]]);
        l3_off += 4;
    }

    Some((
        EthernetInfo {
            dst_mac: data[0..6].try_into().ok()?,
            src_mac: data[6..12].try_into().ok()?,
            ethertype,
        },
        &data[l3_off..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trama(tags: &[(u16, u16)], ethertype: u16) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        for (tpid, tci) in tags {
            f.extend_from_slice(&tpid.to_be_bytes());
            f.extend_from_slice(&tci.to_be_bytes());
        }
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(&[0x45, 0, 0, 20]);
        f
    }

    #[test]
    fn qinq_dos_etiquetas_resuelve_el_ethertype_interior() {
        let f = trama(&[(0x88a8, 10), (0x8100, 20)], 0x0800);
        let (info, l3) = parse_ethernet(&f).unwrap();
        assert_eq!(info.ethertype, 0x0800);
        assert_eq!(l3[0], 0x45);
        // 802.1Q doble (0x8100 apilado) también.
        let f = trama(&[(0x8100, 10), (0x8100, 20)], 0x86dd);
        assert_eq!(parse_ethernet(&f).unwrap().0.ethertype, 0x86dd);
    }

    #[test]
    fn mas_de_dos_etiquetas_no_se_resuelven_y_truncada_da_none() {
        let f = trama(&[(0x8100, 1), (0x8100, 2), (0x8100, 3)], 0x0800);
        assert_eq!(parse_ethernet(&f).unwrap().0.ethertype, 0x8100);
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&0x88a8u16.to_be_bytes());
        f.extend_from_slice(&[0, 1]);
        assert!(parse_ethernet(&f).is_none());
    }
}
