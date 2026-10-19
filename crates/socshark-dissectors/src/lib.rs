//! socshark-dissectors: parsers de protocolos y pipeline de disección.
//!
//! Principios de diseño:
//! - **Sin panics**: todo acceso a bytes está acotado (`get`, `try_into`,
//!   comprobaciones de longitud); un paquete malformado produce `None`,
//!   nunca un crash. Esto es crítico porque los parsers procesan datos
//!   controlables por un atacante.
//! - **Zero-copy del payload por defecto**: los parsers devuelven slices
//!   prestados ([`DissectedPacket::payload`], `Cow::Borrowed`); solo se
//!   copian los metadatos pequeños y las cadenas DNS necesarias para el
//!   enriquecimiento. El pool concurrente ([`pool`]) es la única etapa que
//!   copia el payload (`Cow::Owned`), y solo cuando se le pide paralelismo.
//! - **Funciones puras**: `&[u8] -> Option<(Info, &[u8])>`, fáciles de
//!   testear y de portar al pool concurrente.
//!
//! Fase 2 añade IPv6 completo (con cabeceras de extensión) y el pool de
//! workers concurrentes. Queda para fases posteriores: dissectors
//! registrables (incluidos plugins WASM, ver `docs/wasm-plugins.md`).

pub mod discovery;
pub mod dns;
pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod pool;
pub mod tcp;
pub mod tls;
pub mod udp;

pub use pool::DissectionPool;

use std::borrow::Cow;
use std::net::IpAddr;

use socshark_core::{L7Protocol, LinkType, RawPacket, Transport};

pub use discovery::{clean_name, parse_dhcp, parse_nbns, DhcpInfo, NbnsName};
pub use dns::{parse_dns, DnsInfo, DnsQuestion, DnsRecord};
pub use ethernet::{parse_ethernet, EthernetInfo};
pub use ipv4::{parse_ipv4, Ipv4Info};
pub use ipv6::{parse_ipv6, Ipv6Info};
pub use tcp::{parse_tcp, TcpFlags, TcpInfo};
pub use tls::{parse_client_hello, ClientHello, ClientHelloCapture};
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
    /// Presente si el paquete es IPv6 (Fase 2).
    pub ipv6: Option<Ipv6Info>,
    /// Versión IP (4 o 6); 0 si el paquete no llegó a interpretarse como IP.
    pub ip_version: u8,
    /// Transporte efectivo, ya resuelto desde el protocolo IP.
    pub transport: Transport,
    pub tcp: Option<TcpInfo>,
    pub udp: Option<UdpInfo>,
    /// Presente si el paquete es DNS (puertos 53/5353/5355 o DNS sobre TCP).
    pub dns: Option<DnsInfo>,
    /// Protocolo de aplicación detectado (dissector DNS o heurística L7).
    pub l7: L7Protocol,
    /// Payload de nivel 4 (post TCP/UDP). En el camino secuencial es
    /// `Cow::Borrowed` (zero-copy); el pool concurrente entrega
    /// `Cow::Owned` para poder cruzar hilos.
    pub payload: Cow<'a, [u8]>,
}

impl<'a> DissectedPacket<'a> {
    /// IP de origen (v4 o v6) si el paquete es IP.
    pub fn src_ip(&self) -> Option<IpAddr> {
        if let Some(i) = self.ipv4.as_ref() {
            Some(IpAddr::V4(i.src))
        } else {
            self.ipv6.as_ref().map(|i| IpAddr::V6(i.src))
        }
    }

    /// IP de destino (v4 o v6) si el paquete es IP.
    pub fn dst_ip(&self) -> Option<IpAddr> {
        if let Some(i) = self.ipv4.as_ref() {
            Some(IpAddr::V4(i.dst))
        } else {
            self.ipv6.as_ref().map(|i| IpAddr::V6(i.dst))
        }
    }

    /// Convierte el paquete diseccionado en propietario (`'static`) para
    /// poder enviarlo entre hilos: copia el payload y clona los metadatos.
    /// Es la operación que hace posible el pool concurrente ([`pool`]).
    pub fn into_owned(self) -> DissectedPacket<'static> {
        DissectedPacket {
            eth: self.eth,
            ipv4: self.ipv4,
            ipv6: self.ipv6,
            ip_version: self.ip_version,
            transport: self.transport,
            tcp: self.tcp,
            udp: self.udp,
            dns: self.dns,
            l7: self.l7,
            payload: Cow::Owned(self.payload.into_owned()),
        }
    }
}

/// Pipeline de dissectors: Ethernet → IPv4/IPv6 → TCP/UDP → DNS/L7.
///
/// En Fase 2+ esta estructura se convertirá en el registro del pool de
/// dissectors; la firma de [`DissectorPipeline::dissect`] se mantiene
/// estable para que el cambio sea transparente para el agregador.
#[derive(Debug, Clone, Default)]
pub struct DissectorPipeline;

impl DissectorPipeline {
    pub fn new() -> Self {
        Self
    }

    /// Diseca un paquete crudo. Devuelve `None` si no se puede interpretar:
    /// Ethernet truncado, ethertype no-IP, L3/L4 truncado, fragmento IPv6
    /// no inicial, etc.
    pub fn dissect<'a>(&self, raw: &'a RawPacket, link: LinkType) -> Option<DissectedPacket<'a>> {
        let (eth, l3) = match link {
            LinkType::Ethernet => {
                let (info, rest) = parse_ethernet(&raw.data)?;
                (Some(info), rest)
            }
            LinkType::RawIp => (None, &raw.data[..]),
            // SLL, loopback, etc.: fuera de alcance (documentado).
            LinkType::Unknown(_) => return None,
        };

        // ¿IPv4 o IPv6? En Ethernet lo dice el ethertype; en IP crudo, el
        // nibble de versión. Otros ethertypes (ARP, ...) se descartan por ahora.
        let is_v6 = match &eth {
            Some(e) => e.ethertype == 0x86dd,
            None => l3.first().is_some_and(|b| b >> 4 == 6),
        };
        let (ipv4, ipv6, transport, l4) = if is_v6 {
            let (i6, l4) = parse_ipv6(l3)?;
            let t = Transport::from_ip_proto(i6.next_header);
            (None, Some(i6), t, l4)
        } else {
            let (i4, l4) = parse_ipv4(l3)?;
            let t = Transport::from_ip_proto(i4.protocol);
            (Some(i4), None, t, l4)
        };

        let mut pkt = DissectedPacket {
            eth,
            ip_version: if ipv6.is_some() { 6 } else { 4 },
            ipv4,
            ipv6,
            transport,
            tcp: None,
            udp: None,
            dns: None,
            l7: L7Protocol::Unknown,
            payload: Cow::Borrowed(&[]),
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
            // ICMP y otros: sin parser L4; el flujo se registra con puertos 0
            // y queda visible en la tabla.
            _ => (0u16, 0u16, l4),
        };
        pkt.payload = Cow::Borrowed(payload);

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
            // Petición (68→67, a menudo a difusión) y respuesta (67→68).
            (67 | 68, 67 | 68) => return L7Protocol::Dhcp,
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
        assert_eq!(dp.ip_version, 4);
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

    // -------------------------------------------------- Fase 2: IPv6

    #[test]
    fn dns_ipv6_query_y_respuesta_aaaa() {
        let q = dissect(tg::frame_ipv6_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A6,
            tg::DNS6,
            53010,
            53,
            &tg::dns_query(0x0606, "v6.example.com", 28),
        ));
        assert_eq!(q.ip_version, 6);
        assert_eq!(q.src_ip(), Some(IpAddr::V6(tg::HOST_A6)));
        assert_eq!(q.dst_ip(), Some(IpAddr::V6(tg::DNS6)));
        assert_eq!(q.transport, Transport::Udp);
        assert_eq!(q.dns.as_ref().unwrap().queries[0].name, "v6.example.com");

        let r = dissect(tg::frame_ipv6_udp(
            tg::MAC_ROUTER,
            tg::MAC_HOST_A,
            tg::DNS6,
            tg::HOST_A6,
            53,
            53010,
            &tg::dns_response_aaaa(0x0606, "v6.example.com", tg::WEB6),
        ));
        let ans = &r.dns.unwrap().answers[0];
        assert_eq!(ans.address, Some(IpAddr::V6(tg::WEB6)));
    }

    #[test]
    fn tcp_ipv6_con_sniffing_ssh() {
        let dp = dissect(tg::frame_ipv6_tcp(
            tg::MAC_HOST_B,
            tg::MAC_ROUTER,
            tg::HOST_A6,
            tg::WEB6,
            40010,
            2222,
            7,
            9,
            tg::flags::PSH_ACK,
            b"SSH-2.0-OpenSSH_9.6\r\n",
        ));
        assert_eq!(dp.ip_version, 6);
        assert_eq!(dp.transport, Transport::Tcp);
        assert_eq!(dp.l7, L7Protocol::Ssh);
        assert_eq!(dp.tcp.unwrap().dst_port, 2222);
    }

    #[test]
    fn ethertype_arp_se_descarta() {
        // ARP: ethertype 0x0806, no IP.
        let arp = {
            let mut f = Vec::new();
            f.extend_from_slice(&tg::MAC_HOST_A);
            f.extend_from_slice(&tg::MAC_ROUTER);
            f.extend_from_slice(&0x0806u16.to_be_bytes());
            f.extend_from_slice(&[0u8; 28]);
            f
        };
        let raw = RawPacket {
            ts_micros: 0,
            orig_len: arp.len() as u32,
            data: arp,
        };
        assert!(DissectorPipeline::new()
            .dissect(&raw, LinkType::Ethernet)
            .is_none());
    }

    #[test]
    fn ip_crudo_detecta_version() {
        let frame = tg::frame_ipv6_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A6,
            tg::DNS6,
            53010,
            53,
            &tg::dns_query(2, "raw.example", 1),
        );
        let raw = RawPacket {
            ts_micros: 0,
            orig_len: frame.len() as u32,
            data: frame[14..].to_vec(), // sin cabecera Ethernet
        };
        let dp = DissectorPipeline::new()
            .dissect(&raw, LinkType::RawIp)
            .expect("IPv6 crudo debe diseccionarse");
        assert_eq!(dp.ip_version, 6);
        assert!(dp.eth.is_none());
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
        // Y también el camino IPv6.
        let full6 = tg::frame_ipv6_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A6,
            tg::DNS6,
            53010,
            53,
            &tg::dns_query(1, "a.b.example", 1),
        );
        for cut in [0usize, 14, 40, 54, 62] {
            let raw = RawPacket {
                ts_micros: 0,
                orig_len: full6.len() as u32,
                data: full6[..cut.min(full6.len())].to_vec(),
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
