//! Dissector Ethernet (incluye VLAN 802.1Q de una etiqueta).

/// Metadatos de la cabecera Ethernet.
#[derive(Debug, Clone)]
pub struct EthernetInfo {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    /// Ethertype del payload (0x0800 IPv4, 0x0806 ARP, 0x86DD IPv6, ...).
    /// En tramas VLAN contiene el ethertype interior tras el tag 802.1Q.
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

/// Parsea la cabecera Ethernet y devuelve `(info, payload_l3)`.
///
/// Devuelve `None` si la trama es demasiado corta. Soporta una etiqueta
/// VLAN 802.1Q (TPID 0x8100); QinQ múltiple queda fuera de alcance en Fase 1.
pub fn parse_ethernet(data: &[u8]) -> Option<(EthernetInfo, &[u8])> {
    if data.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut l3_off = 14;

    if ethertype == 0x8100 {
        // 802.1Q: TPID(2) + TCI(2); el ethertype real viene después.
        if data.len() < 18 {
            return None;
        }
        ethertype = u16::from_be_bytes([data[16], data[17]]);
        l3_off = 18;
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
