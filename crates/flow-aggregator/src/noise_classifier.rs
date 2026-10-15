//! Clasificador de ruido de fondo (Smart Noise Dimming).
//!
//! El tráfico benigno y repetitivo (ARP, mDNS, SSDP, NTP, DHCP, STP, IGMP)
//! no debe competir por la atención del analista: se agrupa o se pinta en
//! gris tenue. Esta función decide qué es ruido y por qué.

use socshark_common::ipaddr::IpAddr;
use socshark_dissectors::view::DissectedPacket;

/// Razón por la que un paquete/flujo es ruido de fondo.
pub fn noise_reason(dp: &DissectedPacket) -> Option<&'static str> {
    // ARP: siempre ruido de fondo (broadcast/mantenimiento L2).
    if matches!(dp.net, Some(socshark_dissectors::view::NetInfo::Arp(_))) {
        return Some("ARP");
    }
    // MACs de control: STP (01:80:c2:00:00:00), IPv6 multicast 33:33.
    if let Some(mac) = dp.dst_mac {
        if mac.0 == [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00] {
            return Some("STP");
        }
        if mac.0[0] == 0x01 && mac.0[1] == 0x00 && mac.0[2] == 0x5e {
            return Some("multicast-IPv4");
        }
        if mac.0[0] == 0x33 && mac.0[1] == 0x33 {
            return Some("multicast-IPv6");
        }
    }
    let Some(dst) = dp.dst_ip() else {
        return None;
    };
    // SSDP / mDNS / LLMNR / NetBIOS: descubrimiento local repetitivo.
    if let Some(reason) = discovery_noise(&dst, dp) {
        return Some(reason);
    }
    // NTP: sincronización horaria periódica.
    if dp.dst_port() == Some(123) || dp.src_port() == Some(123) {
        return Some("NTP");
    }
    // DHCP.
    if matches!(
        (dp.src_port(), dp.dst_port()),
        (Some(67), Some(68)) | (Some(68), Some(67))
    ) {
        return Some("DHCP");
    }
    // IGMP (proto 2).
    if let Some(socshark_dissectors::view::NetInfo::V4(ip)) = &dp.net {
        if ip.protocol == 2 {
            return Some("IGMP");
        }
    }
    None
}

fn discovery_noise(dst: &IpAddr, dp: &DissectedPacket) -> Option<&'static str> {
    let (sp, dp_) = (dp.src_port(), dp.dst_port());
    // mDNS: 224.0.0.251 / ff02::fb : 5353
    if (sp == Some(5353) || dp_ == Some(5353)) && dst.is_multicast() {
        return Some("mDNS");
    }
    // SSDP: 239.255.255.250:1900
    if (sp == Some(1900) || dp_ == Some(1900)) && dst.to_string() == "239.255.255.250" {
        return Some("SSDP");
    }
    // LLMNR: 224.0.0.252:5355
    if (sp == Some(5355) || dp_ == Some(5355)) && dst.to_string() == "224.0.0.252" {
        return Some("LLMNR");
    }
    // NetBIOS name service broadcast.
    if (sp == Some(137) || dp_ == Some(137)) && dst.is_broadcast() {
        return Some("NetBIOS");
    }
    None
}

/// Clasifica un paquete como ruido de fondo.
pub fn is_noise(dp: &DissectedPacket) -> bool {
    noise_reason(dp).is_some()
}

/// Clasificación a nivel de **flujo** (usada en el enriquecimiento final,
/// cuando ya no hay paquetes sino conversaciones agregadas).
pub fn flow_is_background_noise(key: &crate::model::FlowKey) -> bool {
    use socshark_common::ipaddr::IpAddr as IP;
    // mDNS / LLMNR: multicast en puertos de descubrimiento.
    if (key.dport == 5353 || key.sport == 5353) && key.dst.is_multicast() {
        return true;
    }
    if (key.dport == 5355 || key.sport == 5355) && key.dst.to_string() == "224.0.0.252" {
        return true;
    }
    // SSDP.
    if (key.dport == 1900 || key.sport == 1900) && key.dst.to_string() == "239.255.255.250" {
        return true;
    }
    // NTP: sincronización horaria periódica y benigna.
    if key.proto == 17 && (key.dport == 123 || key.sport == 123) {
        return true;
    }
    // DHCP.
    if key.proto == 17 && matches!((key.sport, key.dport), (67, 68) | (68, 67)) {
        return true;
    }
    // NetBIOS broadcast.
    if key.proto == 17 && (key.dport == 137 || key.sport == 137) && key.dst.is_broadcast() {
        return true;
    }
    let _ = IP::parse("0.0.0.0");
    false
}
