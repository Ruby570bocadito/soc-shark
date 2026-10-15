//! Vista normalizada de un paquete diseccionado.
//!
//! [`dissect`] encadena L2 → L3 → L4 → L7 y produce un único struct con la
//! tupla de 5, la capa de aplicación detectada (por puerto + sniffing) y el
//! payload útil. Todo prestado del buffer original: cero copias.

use crate::layer2::arp::ArpPacket;
use crate::layer2::ethernet::{parse_ethernet, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6};
use crate::layer2::sll::parse_sll;
use crate::layer3::ipv4::{parse_ipv4, Ipv4Packet, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use crate::layer3::ipv6::{parse_ipv6, Ipv6Packet};
use crate::layer4::icmp as icmp_mod;
use crate::layer4::icmp::IcmpPacket;
use crate::layer4::tcp::{parse_tcp, TcpSegment};
use crate::layer4::udp::{parse_udp, UdpDatagram};
use crate::layer7::dns;
use crate::layer7::dns::DnsPacket;
use crate::layer7::http::{HttpMessage, HttpRequest, HttpResponse};
use crate::layer7::tls::{looks_like_tls, TlsRecord};
use crate::mac::MacAddr;
use socshark_capture_core::{LinkType, PacketRecord};
use socshark_common::ipaddr::IpAddr;

/// Capa de red.
#[derive(Debug)]
pub enum NetInfo<'a> {
    V4(Ipv4Packet<'a>),
    V6(Ipv6Packet<'a>),
    Arp(ArpPacket),
}

/// Capa de transporte.
#[derive(Debug)]
pub enum TransInfo<'a> {
    Tcp(TcpSegment<'a>),
    Udp(UdpDatagram<'a>),
    Icmp(IcmpPacket),
    Other { proto: u8 },
}

/// Capa de aplicación detectada.
#[derive(Debug)]
pub enum AppInfo<'a> {
    Dns(DnsPacket),
    Http(HttpMessage<'a>),
    Tls(TlsRecord<'a>),
}

/// Tupla de 5 canónica direccional (cliente → servidor tal como se vio).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src: IpAddr,
    pub src_port: u16,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
}

/// Paquete diseccionado: la unidad que fluye por el pipeline.
#[derive(Debug)]
pub struct DissectedPacket<'a> {
    pub index: u64,
    pub ts_us: u64,
    pub cap_len: usize,
    pub orig_len: u32,
    pub src_mac: Option<MacAddr>,
    pub dst_mac: Option<MacAddr>,
    pub vlan_ids: Vec<u16>,
    pub net: Option<NetInfo<'a>>,
    pub trans: Option<TransInfo<'a>>,
    pub app: Option<AppInfo<'a>>,
    /// Protocolo L7 identificado: DNS, HTTP, TLS, QUIC, TCP, UDP, ICMP, ARP...
    pub l7_proto: &'static str,
    pub five_tuple: Option<FiveTuple>,
    /// Payload de aplicación (después de TCP/UDP), para carving y entropía.
    pub app_payload: Option<&'a [u8]>,
    pub ip_fragmented: bool,
}

impl DissectedPacket<'_> {
    pub fn src_ip(&self) -> Option<IpAddr> {
        self.five_tuple.as_ref().map(|t| t.src)
    }

    pub fn dst_ip(&self) -> Option<IpAddr> {
        self.five_tuple.as_ref().map(|t| t.dst)
    }

    pub fn src_port(&self) -> Option<u16> {
        self.five_tuple.as_ref().map(|t| t.src_port)
    }

    pub fn dst_port(&self) -> Option<u16> {
        self.five_tuple.as_ref().map(|t| t.dst_port)
    }

    pub fn tcp_flags(&self) -> Option<u8> {
        match &self.trans {
            Some(TransInfo::Tcp(t)) => Some(t.flags),
            _ => None,
        }
    }
}

/// Punto de entrada: disecciona un paquete según su encapsulamiento de enlace.
pub fn dissect<'a>(rec: &PacketRecord<'a>, link: LinkType) -> DissectedPacket<'a> {
    let mut dp = DissectedPacket {
        index: rec.index,
        ts_us: rec.ts_us,
        cap_len: rec.data.len(),
        orig_len: rec.orig_len,
        src_mac: None,
        dst_mac: None,
        vlan_ids: Vec::new(),
        net: None,
        trans: None,
        app: None,
        l7_proto: "",
        five_tuple: None,
        app_payload: None,
        ip_fragmented: false,
    };
    match link {
        LinkType::Ethernet => {
            if let Some(eth) = parse_ethernet(rec.data) {
                dp.src_mac = Some(eth.src);
                dp.dst_mac = Some(eth.dst);
                dp.vlan_ids = eth.vlan_ids;
                handle_ethertype(&mut dp, eth.ethertype, eth.payload);
            }
        }
        LinkType::RawIp => {
            handle_ip(&mut dp, rec.data);
        }
        LinkType::Null => {
            // 4 bytes de AF family (host order): 2=IPv4, 24/30=IPv6.
            if rec.data.len() > 4 {
                handle_ip(&mut dp, &rec.data[4..]);
            }
        }
        LinkType::LinuxSll => {
            if let Some(sll) = parse_sll(rec.data) {
                handle_ethertype(&mut dp, sll.protocol, sll.payload);
            }
        }
        LinkType::Unknown(_) => {}
    }
    if dp.l7_proto.is_empty() {
        dp.l7_proto = match dp.trans {
            Some(TransInfo::Tcp(_)) => "TCP",
            Some(TransInfo::Udp(_)) => "UDP",
            Some(TransInfo::Icmp(_)) => "ICMP",
            Some(TransInfo::Other { .. }) => "IP",
            None => match dp.net {
                Some(NetInfo::Arp(_)) => "ARP",
                _ => "UNKNOWN",
            },
        };
    }
    dp
}

fn handle_ethertype<'a>(dp: &mut DissectedPacket<'a>, ethertype: u16, payload: &'a [u8]) {
    match ethertype {
        ETHERTYPE_IPV4 => handle_ip(dp, payload),
        ETHERTYPE_IPV6 => handle_ip(dp, payload),
        ETHERTYPE_ARP => {
            if let Some(arp) = crate::layer2::arp::parse_arp(payload) {
                dp.net = Some(NetInfo::Arp(arp));
            }
        }
        _ => {}
    }
}

fn handle_ip<'a>(dp: &mut DissectedPacket<'a>, data: &'a [u8]) {
    if data.is_empty() {
        return;
    }
    let version = data[0] >> 4;
    match version {
        4 => handle_ipv4(dp, data),
        6 => handle_ipv6(dp, data),
        _ => {}
    }
}

fn handle_ipv4<'a>(dp: &mut DissectedPacket<'a>, data: &'a [u8]) {
    let Some(ip) = parse_ipv4(data) else {
        return;
    };
    dp.ip_fragmented = ip.is_fragmented();
    let frag_skip = ip.is_non_first_fragment();
    let (proto, payload) = (ip.protocol, ip.payload);
    dp.net = Some(NetInfo::V4(ip));
    if frag_skip {
        return;
    }
    handle_transport(dp, proto, payload);
}

fn handle_ipv6<'a>(dp: &mut DissectedPacket<'a>, data: &'a [u8]) {
    let Some(ip) = parse_ipv6(data) else {
        return;
    };
    dp.ip_fragmented = ip.non_first_fragment;
    let (proto, payload) = (ip.next_header, ip.payload);
    dp.net = Some(NetInfo::V6(ip));
    if dp.ip_fragmented {
        return;
    }
    handle_transport(dp, proto, payload);
}

fn handle_transport<'a>(dp: &mut DissectedPacket<'a>, proto: u8, payload: &'a [u8]) {
    match proto {
        PROTO_TCP => {
            let Some(tcp) = parse_tcp(payload) else {
                dp.trans = Some(TransInfo::Other { proto });
                return;
            };
            let (sp, dp_, app_payload) = (tcp.src_port, tcp.dst_port, tcp.payload);
            dp.trans = Some(TransInfo::Tcp(tcp));
            dp.app_payload = Some(app_payload);
            set_five_tuple(dp, sp, dp_, PROTO_TCP);
            detect_l7(dp, sp, dp_, app_payload, true);
        }
        PROTO_UDP => {
            let Some(udp) = parse_udp(payload) else {
                dp.trans = Some(TransInfo::Other { proto });
                return;
            };
            let (sp, dp_, app_payload) = (udp.src_port, udp.dst_port, udp.payload);
            dp.trans = Some(TransInfo::Udp(udp));
            dp.app_payload = Some(app_payload);
            set_five_tuple(dp, sp, dp_, PROTO_UDP);
            detect_l7(dp, sp, dp_, app_payload, false);
        }
        PROTO_ICMP => {
            if let Some(icmp) = icmp_mod::parse_icmp(payload) {
                dp.trans = Some(TransInfo::Icmp(icmp));
            } else {
                dp.trans = Some(TransInfo::Other { proto });
            }
        }
        other => dp.trans = Some(TransInfo::Other { proto: other }),
    }
}

fn set_five_tuple(dp: &mut DissectedPacket, sp: u16, dport: u16, proto: u8) {
    let (src, dst) = match &dp.net {
        Some(NetInfo::V4(ip)) => (ip.src, ip.dst),
        Some(NetInfo::V6(ip)) => (ip.src, ip.dst),
        _ => return,
    };
    dp.five_tuple = Some(FiveTuple {
        src,
        src_port: sp,
        dst,
        dst_port: dport,
        proto,
    });
}

/// Detección L7: primero por puerto (DNS/mDNS), luego sniffing TLS y HTTP.
fn detect_l7<'a>(
    dp: &mut DissectedPacket<'a>,
    sport: u16,
    dport: u16,
    payload: &'a [u8],
    is_tcp: bool,
) {
    if payload.is_empty() {
        return;
    }
    // DNS sobre UDP 53/5353 o TCP 53 (con prefijo de 2 bytes).
    if (sport == 53 || dport == 53 || dport == 5353 || sport == 5353) && !payload.is_empty() {
        if let Some(d) = dns::parse_dns(payload, is_tcp) {
            dp.app = Some(AppInfo::Dns(d));
            dp.l7_proto = "DNS";
            return;
        }
    }
    // QUIC: primer nibble largo header (0xC0-0xCF) sobre UDP.
    if !is_tcp && payload[0] & 0xc0 == 0xc0 {
        dp.l7_proto = "QUIC";
        return;
    }
    // TLS: sniffing por estructura (permite detectar TLS en puertos raros).
    if looks_like_tls(payload) {
        if let Some(t) = crate::layer7::tls::parse_tls(payload) {
            dp.app = Some(AppInfo::Tls(t));
            dp.l7_proto = "TLS";
            return;
        }
    }
    // HTTP/1.x: sniffing por método/versión en cualquier puerto.
    if let Some(h) = crate::layer7::http::parse_http(payload) {
        dp.app = Some(AppInfo::Http(h));
        dp.l7_proto = "HTTP";
    }
}

// Helpers públicos para extraer vistas HTTP sin exponer el enum interno.
impl<'a> AppInfo<'a> {
    pub fn as_http_request(&self) -> Option<&HttpRequest<'a>> {
        match self {
            AppInfo::Http(HttpMessage::Request(r)) => Some(r),
            _ => None,
        }
    }

    pub fn as_http_response(&self) -> Option<&HttpResponse<'a>> {
        match self {
            AppInfo::Http(HttpMessage::Response(r)) => Some(r),
            _ => None,
        }
    }

    pub fn as_dns(&self) -> Option<&DnsPacket> {
        match self {
            AppInfo::Dns(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_tls(&self) -> Option<&TlsRecord<'a>> {
        match self {
            AppInfo::Tls(t) => Some(t),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer2::ethernet::ETHERTYPE_IPV4;

    /// Construye Ethernet+IPv4+TCP+payload con checksum IP válido.
    fn frame(proto: u8, sport: u16, dport: u16, l4: &[u8]) -> Vec<u8> {
        let mut eth = vec![0u8; 14];
        eth[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let tcp_or_udp = {
            let mut v = Vec::new();
            if proto == 6 {
                v.extend_from_slice(&sport.to_be_bytes());
                v.extend_from_slice(&dport.to_be_bytes());
                v.extend_from_slice(&1u32.to_be_bytes());
                v.extend_from_slice(&2u32.to_be_bytes());
                v.push(0x50);
                v.push(0x18); // PSH,ACK
                v.extend_from_slice(&64_000u16.to_be_bytes()); // window
                v.extend_from_slice(&0u16.to_be_bytes()); // checksum
                v.extend_from_slice(&0u16.to_be_bytes()); // urgent
                v.extend_from_slice(l4);
            } else {
                v.extend_from_slice(&sport.to_be_bytes());
                v.extend_from_slice(&dport.to_be_bytes());
                v.extend_from_slice(&((8 + l4.len()) as u16).to_be_bytes());
                v.extend_from_slice(&0u16.to_be_bytes());
                v.extend_from_slice(l4);
            }
            v
        };
        let total = 20 + tcp_or_udp.len();
        let mut ip = vec![
            0x45u8,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            1,
            0x40,
            0,
            64,
            proto,
            0,
            0,
        ];
        ip.extend_from_slice(&[192, 168, 1, 50]);
        ip.extend_from_slice(&[185, 22, 1, 9]);
        ip.extend_from_slice(&tcp_or_udp);
        let mut sum = 0u32;
        for w in ip[0..20].chunks(2) {
            sum += u16::from_be_bytes([w[0], w[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        ip[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        let mut f = eth;
        f.extend_from_slice(&ip);
        f
    }

    #[test]
    fn disecta_tcp_http_en_puerto_raro() {
        let payload = b"POST /gate.php HTTP/1.1\r\nHost: c2.evil.ru\r\n\r\n";
        let f = frame(6, 49_812, 4444, payload);
        let rec = PacketRecord {
            index: 0,
            ts_us: 0,
            orig_len: f.len() as u32,
            data: &f,
        };
        let dp = dissect(&rec, LinkType::Ethernet);
        assert_eq!(dp.l7_proto, "HTTP");
        let ft = dp.five_tuple.unwrap();
        assert_eq!(ft.dst_port, 4444);
        assert_eq!(ft.proto, 6);
        assert!(dp.app.as_ref().unwrap().as_http_request().is_some());
        assert_eq!(dp.app_payload, Some(&payload[..]));
    }

    #[test]
    fn disecta_dns() {
        // DNS query mínima: header + qname "a.b" + type/class
        let mut dnsq = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        dnsq.push(1);
        dnsq.extend_from_slice(b"a");
        dnsq.push(1);
        dnsq.extend_from_slice(b"b");
        dnsq.push(0);
        dnsq.extend_from_slice(&1u16.to_be_bytes());
        dnsq.extend_from_slice(&1u16.to_be_bytes());
        let f = frame(17, 53_530, 53, &dnsq);
        let rec = PacketRecord {
            index: 1,
            ts_us: 0,
            orig_len: f.len() as u32,
            data: &f,
        };
        let dp = dissect(&rec, LinkType::Ethernet);
        assert_eq!(dp.l7_proto, "DNS");
        let d = dp.app.as_ref().unwrap().as_dns().unwrap();
        assert_eq!(d.qname(), Some("a.b"));
    }

    #[test]
    fn nunca_panico_con_entrada_aleatoria() {
        // PRNG LCG determinista: bytes aleatorios nunca deben tumbar el disector.
        let mut x: u64 = 0x1234_5678_9abc_def0;
        for _ in 0..2_000 {
            let n = (x >> 33) as usize % 120;
            let buf: Vec<u8> = (0..n)
                .map(|_| {
                    x = x
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    (x >> 33) as u8
                })
                .collect();
            let rec = PacketRecord {
                index: 0,
                ts_us: 0,
                orig_len: n as u32,
                data: &buf,
            };
            let _ = dissect(&rec, LinkType::Ethernet);
            let _ = dissect(&rec, LinkType::RawIp);
        }
    }
}
