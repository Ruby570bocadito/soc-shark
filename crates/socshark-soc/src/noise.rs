//! Clasificación de "ruido de fondo": tráfico legítimo de mantenimiento que
//! no aporta valor analítico y debe atenuarse en la interfaz (Smart Noise
//! Dimming del diseño SOC). Nunca se borra: se marca y se puede mostrar con
//! `--show-noise`.

use std::net::IpAddr;

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

/// Optimización de distribución de Windows (Delivery Optimization): los
/// equipos de la red se pasan trozos de actualizaciones por TCP/7680 y se
/// buscan entre sí cada ~40 s, con una regularidad que la regla de beaconing
/// tomaba por un C2 (falso positivo medio real del corpus: capturas de
/// laboratorio Windows de Active Countermeasures, hasta 118 flujos por
/// hora).
const DELIVERY_OPTIMIZATION_PORT: u16 = 7680;

/// Dirección unicast de la red local: privada, de enlace local o ULA. Los
/// pares de Delivery Optimization son equipos, nunca multicast.
fn lan_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            (s0 & 0xfe00) == 0xfc00 || (s0 & 0xffc0) == 0xfe80
        }
    }
}

/// Determina si un flujo es ruido de fondo.
///
/// Criterios Fase 1 (ver `docs/soc-features.md`):
/// - UDP hacia puertos de mantenimiento (NTP, mDNS, LLMNR, SSDP, ...): manda
///   el puerto del lado servidor (destino). Los clientes de NTP/mDNS suelen
///   fijar el origen igual al destino, así que eso sigue cubierto. Un puerto
///   de la lista solo en el **origen** no basta: un implante puede salir
///   desde el 123 hacia un C2 y esquivar así la detección de beaconing.
///   Solo cuenta si el dissector confirmó el protocolo (NTP/DHCP).
/// - TCP: solo Delivery Optimization (7680) **entre dos equipos de la red
///   local**, en cualquiera de los dos extremos (la captura pudo empezar
///   con un paquete del que escucha). Un equipo de Internet en el 7680 sigue
///   analizándose como cualquier otro: un C2 no se esconde usando el puerto.
pub fn is_background_noise(flow: &EnrichedFlow) -> bool {
    match flow.transport {
        Transport::Udp => {
            NOISE_UDP_PORTS.contains(&flow.dst_port)
                || (NOISE_UDP_PORTS.contains(&flow.src_port)
                    && matches!(flow.l7_protocol, L7Protocol::Ntp | L7Protocol::Dhcp))
        }
        Transport::Tcp => {
            (flow.dst_port == DELIVERY_OPTIMIZATION_PORT
                || flow.src_port == DELIVERY_OPTIMIZATION_PORT)
                && lan_unicast(flow.src_ip)
                && lan_unicast(flow.dst_ip)
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
    fn dns_y_tcp_normal_no_son_ruido() {
        let dns = flujo_basico(17, 53001, 53);
        assert!(!is_background_noise(&dns));

        let tcp = flujo_basico(6, 52000, 443);
        assert!(!is_background_noise(&tcp));
    }

    #[test]
    fn delivery_optimization_solo_entre_equipos_de_la_red() {
        // 10.0.0.5 → 10.0.0.99:7680, como en las capturas reales.
        assert!(is_background_noise(&flujo_basico(6, 52000, 7680)));
        // Captura empezada a mitad: el primer paquete es del que escucha.
        assert!(is_background_noise(&flujo_basico(6, 7680, 52000)));
        // Un equipo de Internet en el 7680 no es ruido (un C2 no se esconde así).
        let mut fuera = flujo_basico(6, 52000, 7680);
        fuera.dst_ip = "203.0.113.9".parse().unwrap();
        assert!(!is_background_noise(&fuera));
        // Solo TCP.
        assert!(!is_background_noise(&flujo_basico(17, 52000, 7680)));
        // IPv6 de enlace local también es la red local.
        let mut v6 = flujo_basico(6, 52000, 7680);
        v6.src_ip = "fe80::1".parse().unwrap();
        v6.dst_ip = "fe80::2".parse().unwrap();
        assert!(is_background_noise(&v6));
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
