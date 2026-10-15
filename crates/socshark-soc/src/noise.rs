//! Clasificación de "ruido de fondo": tráfico legítimo de mantenimiento que
//! no aporta valor analítico y debe atenuarse en la interfaz (Smart Noise
//! Dimming del diseño SOC). Nunca se borra: se marca y se puede mostrar con
//! `--show-noise`.

use socshark_core::{EnrichedFlow, Transport};

/// Puertos UDP considerados ruido de fondo en Fase 1.
const NOISE_UDP_PORTS: &[u16] = &[
    123,  // NTP
    5353, // mDNS
    5355, // LLMNR
    1900, // SSDP / UPnP discovery
    137,  // NetBIOS Name Service
    138,  // NetBIOS Datagram
    67,   // DHCP (servidor)
    68,   // DHCP (cliente)
    111,  // rpcbind/portmap
    161,  // SNMP
    514,  // syslog clásico
];

/// Determina si un flujo es ruido de fondo.
///
/// Criterios Fase 1 (ver `docs/soc-features.md`):
/// - UDP hacia/desde puertos de mantenimiento (NTP, mDNS, LLMNR, SSDP, ...).
///   Se comprueban ambos puertos porque los clientes de NTP/mDNS suelen
///   fijar su puerto origen igual al destino.
/// - TCP: todavía nada marcado como ruido; en Fase 2 se añadirán sondeos de
///   broadcast/multicast (ARP cuando exista dissector propio).
pub fn is_background_noise(flow: &EnrichedFlow) -> bool {
    match flow.transport {
        Transport::Udp => [flow.src_port, flow.dst_port]
            .iter()
            .any(|p| NOISE_UDP_PORTS.contains(p)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::flujo_basico;

    #[test]
    fn udp_de_mantenimiento_es_ruido() {
        let ntp = flujo_basico(17, 123, 123);
        assert!(is_background_noise(&ntp));

        let mdns = flujo_basico(17, 5353, 5353);
        assert!(is_background_noise(&mdns));
    }

    #[test]
    fn dns_y_tcp_nunca_son_ruido_en_fase_1() {
        let dns = flujo_basico(17, 53001, 53);
        assert!(!is_background_noise(&dns));

        let tcp = flujo_basico(6, 52000, 443);
        assert!(!is_background_noise(&tcp));
    }
}
