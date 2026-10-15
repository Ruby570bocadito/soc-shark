//! Ethernet II con manejo de etiquetas VLAN 802.1Q (0x8100) y QinQ (0x88a8).

use crate::mac::MacAddr;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const ETHERTYPE_QINQ: u16 = 0x88a8;

/// Trama Ethernet diseccionada. `ethertype` es el tipo interno tras las VLAN.
#[derive(Debug)]
pub struct EthernetFrame<'a> {
    pub dst: MacAddr,
    pub src: MacAddr,
    /// Ethertype efectivo (después de desempaquetar VLANs).
    pub ethertype: u16,
    /// VLAN IDs vistos (0, 1 o 2 en QinQ).
    pub vlan_ids: Vec<u16>,
    /// Payload (L3 o superior), prestado sin copiar.
    pub payload: &'a [u8],
}

/// Parsea una trama Ethernet; devuelve `None` si es demasiado corta o
/// malformada. Nunca hace panic.
pub fn parse_ethernet(data: &[u8]) -> Option<EthernetFrame<'_>> {
    if data.len() < 14 {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&data[0..6]);
    let dst = MacAddr(mac);
    mac.copy_from_slice(&data[6..12]);
    let src = MacAddr(mac);
    let mut etype = u16::from_be_bytes([data[12], data[13]]);
    let mut off = 14usize;
    let mut vlans = Vec::new();
    // Desempaqueta hasta 2 etiquetas VLAN (QinQ).
    for _ in 0..2 {
        if etype == ETHERTYPE_VLAN || etype == ETHERTYPE_QINQ {
            if data.len() < off + 4 {
                return None;
            }
            let tci = u16::from_be_bytes([data[off], data[off + 1]]);
            vlans.push(tci & 0x0fff);
            etype = u16::from_be_bytes([data[off + 2], data[off + 3]]);
            off += 4;
        } else {
            break;
        }
    }
    Some(EthernetFrame {
        dst,
        src,
        ethertype: etype,
        vlan_ids: vlans,
        payload: &data[off..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut v = vec![0xff; 6]; // dst broadcast
        v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src
        v.extend_from_slice(&0x8100u16.to_be_bytes());
        v.extend_from_slice(&0x0064u16.to_be_bytes()); // VLAN 100
        v.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        v.extend_from_slice(&[0x45, 0x00]); // inicio de IP
        v
    }

    #[test]
    fn parsea_vlan() {
        let buf = sample();
        let f = parse_ethernet(&buf).unwrap();
        assert_eq!(f.vlan_ids, vec![100]);
        assert_eq!(f.ethertype, ETHERTYPE_IPV4);
        assert_eq!(f.payload, &[0x45, 0x00]);
        assert!(f.dst.is_broadcast());
        assert_eq!(f.src.to_string(), "00:11:22:33:44:55");
    }

    #[test]
    fn tramas_cortas_sin_panic() {
        for n in 0..14 {
            assert!(parse_ethernet(&sample()[..n]).is_none());
        }
        // VLAN truncada
        assert!(parse_ethernet(&sample()[..16]).is_none());
    }
}
