//! Clasificación de "ruido de fondo": tráfico legítimo de mantenimiento que
//! no aporta valor analítico y debe atenuarse en la interfaz (Smart Noise
//! Dimming del diseño SOC). Nunca se borra: se marca y se puede mostrar con
//! `--show-noise`.

use socshark_core::{EnrichedFlow, L7Protocol, Transport};

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
/// - UDP hacia puertos de mantenimiento (NTP, mDNS, LLMNR, SSDP, ...): manda
///   el puerto del lado servidor (destino). Los clientes de NTP/mDNS suelen
///   fijar el origen igual al destino, así que eso sigue cubierto. Un puerto
///   de la lista solo en el **origen** no basta: un implante puede salir
///   desde el 123 hacia un C2 y esquivar así la detección de beaconing.
///   Solo cuenta si el dissector confirmó el protocolo (NTP/DHCP).
/// - TCP: todavía nada marcado como ruido; en Fase 2 se añadirán sondeos de
///   broadcast/multicast (ARP cuando exista dissector propio).
pub fn is_background_noise(flow: &EnrichedFlow) -> bool {
    match flow.transport {
        Transport::Udp => {
            NOISE_UDP_PORTS.contains(&flow.dst_port)
                || (NOISE_UDP_PORTS.contains(&flow.src_port)
                    && matches!(flow.l7_protocol, L7Protocol::Ntp | L7Protocol::Dhcp))
        }
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

    #[test]
    fn puerto_de_ruido_solo_en_origen_no_basta() {
        // Regresión: un beacon que sale desde el 123 hacia un puerto alto
        // quedaba marcado como ruido y R5 lo ignoraba.
        let c2 = flujo_basico(17, 123, 4444);
        assert!(!is_background_noise(&c2));
        // Con NTP confirmado por el dissector (respuesta vista al revés) sí.
        let mut ntp = flujo_basico(17, 123, 40000);
        ntp.l7_protocol = L7Protocol::Ntp;
        assert!(is_background_noise(&ntp));
        // Cliente NTP desde puerto efímero hacia el 123: ruido.
        assert!(is_background_noise(&flujo_basico(17, 40000, 123)));
    }
}
