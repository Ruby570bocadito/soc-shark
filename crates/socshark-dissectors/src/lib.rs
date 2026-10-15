//! socshark-dissectors: parsers de protocolos y pipeline de disección.
//!
//! Principios de diseño:
//! - **Sin panics**: todo acceso a bytes está acotado (`get`, `try_into`,
//!   comprobaciones de longitud); un paquete malformado produce `None`,
//!   nunca un crash. Esto es crítico porque los parsers procesan datos
//!   controlables por un atacante.
//! - **Zero-copy del payload**: los parsers devuelven slices prestados
//!   ([`DissectedPacket::payload`]); solo se copian los metadatos pequeños
//!   y las cadenas DNS necesarias para el enriquecimiento.
//! - **Funciones puras**: `&[u8] -> Option<(Info, &[u8])>`, fáciles de
//!   testear y de portar al pool concurrente de Fase 2.
//!
//! Fase 2 añadirá: IPv6, el pool de workers concurrentes y dissectors
//! registrables (incluidos plugins WASM, ver `docs/wasm-plugins.md`).

pub mod dns;
pub mod ethernet;
pub mod ipv4;
pub mod tcp;
pub mod udp;

use socshark_core::{L7Protocol, LinkType, RawPacket, Transport};

pub use dns::{parse_dns, DnsInfo, DnsQuestion, DnsRecord};
pub use ethernet::{parse_ethernet, EthernetInfo};
pub use ipv4::{parse_ipv4, Ipv4Info};
pub use tcp::{parse_tcp, TcpFlags, TcpInfo};
pub use udp::{parse_udp, UdpInfo};

/// Formatea una MAC como `aa:bb:cc:dd:ee:ff`.
pub fn fmt_mac(mac: &[u8; 6]) -> String {
    let octets = mac.iter().map(|b| format!("{b:02x}"));
    octets.collect::<Vec<_>>().join(":")
}

/// Resultado de diseccionar un paquete: metadatos por capa + payload L4 prestado.
#[derive(Debug)]
pub struct DissectedPacket<'a> {
    pub eth: Option<EthernetInfo>,
    pub ipv4: Option<Ipv4Info>,
    pub tcp: Option<TcpInfo>,
    pub udp: Option<UdpInfo>,
    /// Presente si el paquete es DNS (puertos 53/5353/5355 o DNS sobre TCP).
    pub dns: Option<DnsInfo>,
    /// Protocolo de aplicación detectado (dissector DNS o heurística L7).
    pub l7: L7Protocol,
    /// Payload de nivel 4 (post TCP/UDP), sin copiar.
    pub payload: &'a [u8],
}

/// Pipeline de dissectors de la Fase 1: Ethernet → IPv4 → TCP/UDP → DNS/L7.
///
/// En Fase 2 esta estructura se convertirá en el registro del pool de
/// dissectors; la firma de [`DissectorPipeline::dissect`] se mantiene estable
/// para que el cambio sea transparente para el agregador.
#[derive(Debug, Clone, Default)]
pub struct DissectorPipeline;

impl DissectorPipeline {
    pub fn new() -> Self {
        Self
    }

    /// Diseca un paquete crudo. Devuelve `None` si no se puede interpretar:
    /// Ethernet truncado, ethertype no-IPv4, L4 truncado, etc.
    pub fn dissect<'a>(&self, raw: &'a RawPacket, link: LinkType) -> Option<DissectedPacket<'a>> {
        let (eth, l3) = match link {
            LinkType::Ethernet => {
                let (info, rest) = parse_ethernet(&raw.data)?;
                (Some(info), rest)
            }
            LinkType::RawIp => (None, &raw.data[..]),
            // SLL, loopback, etc.: fuera de alcance en Fase 1 (documentado).
            LinkType::Unknown(_) => return None,
        };

        let (ip, l4) = parse_ipv4(l3)?;
        let transport = Transport::from_ip_proto(ip.protocol);

        let mut pkt = DissectedPacket {
            eth,
            ipv4: Some(ip),
            tcp: None,
            udp: None,
            dns: None,
            l7: L7Protocol::Unknown,
            payload: &[],
        };

        let (sport, dport, payload) = match transport {
            Transport::Tcp => {
                let (info, payload) = parse_tcp(l4)?;
                let (s, d) = (info.src_port, info.dst_port);
                pkt.tcp = Some(info);
                (s, d, payload)
            }
            Transport::Udp => {
                let (info, payload) = parse_udp(l4)?;
                let (s, d) = (info.src_port, info.dst_port);
                pkt.udp = Some(info);
                (s, d, payload)
            }
            // ICMP y otros: sin parser L4 en Fase 1; el flujo se registra
            // con puertos 0 y queda visible en la tabla.
            _ => (0u16, 0u16, l4),
        };
        pkt.payload = payload;

        pkt.dns = self.try_dns(transport, sport, dport, payload);
        pkt.l7 = if pkt.dns.is_some() {
            L7Protocol::Dns
        } else {
            detect_l7(transport, sport, dport, payload)
        };
        Some(pkt)
    }

    /// Intenta disección DNS si el puerto lo sugiere (UDP 53/5353/5355 o
    /// TCP 53 con prefijo de longitud de 2 bytes).
    fn try_dns(
        &self,
        transport: Transport,
        sport: u16,
        dport: u16,
        payload: &[u8],
    ) -> Option<DnsInfo> {
        match transport {
            Transport::Udp
                if [53, 5353, 5355].contains(&sport) || [53, 5353, 5355].contains(&dport) =>
            {
                parse_dns(payload)
            }
            Transport::Tcp if sport == 53 || dport == 53 => payload.get(2..).and_then(parse_dns),
            _ => None,
        }
    }
}

/// Heurísticas de identificación L7: reglas de puerto + inspección ligera
/// de payload (independiente del puerto para TLS/HTTP/SSH).
pub fn detect_l7(transport: Transport, sport: u16, dport: u16, payload: &[u8]) -> L7Protocol {
    match transport {
        Transport::Udp => match (sport, dport) {
            (67, _) | (_, 68) => return L7Protocol::Dhcp,
            (123, _) | (_, 123) => return L7Protocol::Ntp,
            _ => {}
        },
        Transport::Tcp if sport == 443 || dport == 443 => return L7Protocol::Tls,
        _ => {}
    }

    // Sniffing independiente del puerto (solo TCP con payload).
    if transport == Transport::Tcp && !payload.is_empty() {
        const METHODS: [&[u8]; 6] = [
            b"GET ",
            b"POST ",
            b"HEAD ",
            b"PUT ",
            b"DELETE ",
            b"OPTIONS ",
        ];
        if payload.starts_with(b"SSH-") {
            return L7Protocol::Ssh;
        }
        if METHODS.iter().any(|m| payload.starts_with(m)) {
            return L7Protocol::Http;
        }
        // Registro TLS: content type 0x16 (handshake) con versión >= 3.0.
        if payload.len() >= 3 && payload[0] == 0x16 && payload[1] == 0x03 {
            return L7Protocol::Tls;
        }
    }
    L7Protocol::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_testgen as tg;

    fn dissect(pkt: Vec<u8>) -> DissectedPacket<'static> {
        // Leaky + Box para satisfacer el lifetime en tests: los paquetes
        // viven hasta el final del proceso de test.
        let raw: &'static RawPacket = Box::leak(Box::new(RawPacket {
            ts_micros: 0,
            orig_len: pkt.len() as u32,
            data: pkt,
        }));
        DissectorPipeline::new()
            .dissect(raw, LinkType::Ethernet)
            .expect("la trama del testgen debe diseccionarse")
    }

    #[test]
    fn diseca_flujo_tls_por_puerto() {
        let pkt = tg::frame_tcp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::WEB,
            52000,
            443,
            1,
            0,
            tg::flags::SYN,
            &[],
        );
        let dp = dissect(pkt);
        let tcp = dp.tcp.unwrap();
        assert!(tcp.flags.syn && !tcp.flags.ack);
        assert_eq!(dp.l7, L7Protocol::Tls);
        assert!(dp.ipv4.unwrap().checksum_ok);
    }

    #[test]
    fn diseca_consulta_y_respuesta_dns_con_compresion() {
        let q = dissect(tg::frame_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::DNS_EXT,
            53001,
            53,
            &tg::dns_query(0x1234, "example.com", 1),
        ));
        let qinfo = q.dns.unwrap();
        assert!(!qinfo.is_response);
        assert_eq!(qinfo.queries[0].name, "example.com");
        assert_eq!(qinfo.queries[0].qtype, 1);

        let r = dissect(tg::frame_udp(
            tg::MAC_ROUTER,
            tg::MAC_HOST_A,
            tg::DNS_EXT,
            tg::HOST_A,
            53,
            53001,
            &tg::dns_response(0x1234, "example.com", 1, tg::WEB),
        ));
        let rinfo = r.dns.unwrap();
        assert!(rinfo.is_response);
        assert_eq!(rinfo.rcode, Some(0));
        let ans = &rinfo.answers[0];
        // El nombre viene comprimido (puntero 0xc00c): debe resolverse.
        assert_eq!(ans.name, "example.com");
        assert_eq!(ans.address, Some(std::net::IpAddr::V4(tg::WEB)));
    }

    #[test]
    fn sniffing_ssh_http_sin_puerto_estandar() {
        let ssh = dissect(tg::frame_tcp(
            tg::MAC_HOST_B,
            tg::MAC_ROUTER,
            tg::HOST_B,
            tg::GATEWAY,
            40110,
            2222,
            7,
            9,
            tg::flags::PSH_ACK,
            b"SSH-2.0-OpenSSH_8.9p1\r\n",
        ));
        assert_eq!(ssh.l7, L7Protocol::Ssh);

        let http = dissect(tg::frame_tcp(
            tg::MAC_HOST_B,
            tg::MAC_ROUTER,
            tg::HOST_B,
            tg::WEB,
            40111,
            8080,
            11,
            13,
            tg::flags::PSH_ACK,
            b"GET /index.html HTTP/1.1\r\nHost: ejemplo.local\r\n\r\n",
        ));
        assert_eq!(http.l7, L7Protocol::Http);
    }

    #[test]
    fn ntp_por_puerto() {
        let ntp = dissect(tg::frame_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::NTP,
            123,
            123,
            &[0u8; 48],
        ));
        assert_eq!(ntp.l7, L7Protocol::Ntp);
        assert!(ntp.dns.is_none());
    }

    #[test]
    fn dns_sobre_tcp_descarta_prefijo_de_longitud() {
        let q = tg::dns_query(0x4242, "tcp.example.com", 1);
        let mut payload = Vec::new();
        payload.extend_from_slice(&(q.len() as u16).to_be_bytes());
        payload.extend_from_slice(&q);
        let dp = dissect(tg::frame_tcp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::DNS_EXT,
            53002,
            53,
            1,
            1,
            tg::flags::PSH_ACK,
            &payload,
        ));
        let dinfo = dp.dns.expect("DNS sobre TCP debe diseccionarse");
        assert_eq!(dinfo.queries[0].name, "tcp.example.com");
    }

    #[test]
    fn trama_truncada_devuelve_none_y_no_panics() {
        let full = tg::frame_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::DNS_EXT,
            53001,
            53,
            &tg::dns_query(1, "a.b", 1),
        );
        for cut in [0usize, 5, 13, 14, 20, 34, 40] {
            let raw = RawPacket {
                ts_micros: 0,
                orig_len: full.len() as u32,
                data: full[..cut.min(full.len())].to_vec(),
            };
            let _ = DissectorPipeline::new().dissect(&raw, LinkType::Ethernet);
        }
    }

    #[test]
    fn ethernet_vlan_8021q() {
        // dst(6) src(6) TPID 0x8100(2) TCI(2) ethertype 0x0800(2) + IPv4 mínimo.
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0; 12]);
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&100u16.to_be_bytes()); // VLAN id
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[0x45, 0x00, 0x00, 0x14]); // versión/ihl, tos, total_len=20
        frame.extend_from_slice(&[0; 16]);

        let (info, payload) = parse_ethernet(&frame).unwrap();
        assert_eq!(info.ethertype, 0x0800);
        assert_eq!(payload.len(), 20);
    }
}
