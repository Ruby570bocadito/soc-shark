//! Escenario «casa»: una red doméstica donde los equipos se presentan solos.
//!
//! Sirve para probar y enseñar el «quién es quién» (nombres por DHCP, mDNS,
//! LLMNR y NetBIOS, fabricante por MAC, el router). Los prefijos de MAC son
//! reales del registro del IEEE: Arcadyan (router de operadora), HP
//! (impresora), Intel (PC), Google (Chromecast); el móvil usa una MAC
//! aleatoria, como hacen iPhone y Android modernos en cada Wi-Fi.

use std::net::Ipv4Addr;

use crate::{client_hello, dns_query, dns_response, encode_dns_name, flags, frame_tcp, frame_udp};

pub const HOME_ROUTER_IP: &str = "192.168.1.1";
pub const HOME_PHONE_IP: &str = "192.168.1.30";
pub const HOME_PRINTER_IP: &str = "192.168.1.40";
pub const HOME_PC_IP: &str = "192.168.1.50";
pub const HOME_TV_IP: &str = "192.168.1.60";

const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
const PHONE: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 30);
const PRINTER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 40);
const PC: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
const TV: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 60);
const BROADCAST: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);
const LAN_BROADCAST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 255);
const MDNS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const DNS_GOOGLE: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const INSTAGRAM: Ipv4Addr = Ipv4Addr::new(157, 240, 5, 174);
const OUTLOOK: Ipv4Addr = Ipv4Addr::new(52, 97, 146, 162);

pub const MAC_HOME_ROUTER: [u8; 6] = [0x00, 0x12, 0xbf, 0x11, 0x22, 0x33];
pub const MAC_HOME_PHONE: [u8; 6] = [0xda, 0xa1, 0x19, 0x4e, 0x5f, 0x60];
pub const MAC_HOME_PRINTER: [u8; 6] = [0x00, 0x01, 0xe6, 0x44, 0x55, 0x66];
pub const MAC_HOME_PC: [u8; 6] = [0x00, 0x02, 0xb3, 0x77, 0x88, 0x99];
pub const MAC_HOME_TV: [u8; 6] = [0x00, 0x1a, 0x11, 0xaa, 0xbb, 0xcc];
const MAC_BROADCAST: [u8; 6] = [0xff; 6];
const MAC_MDNS: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb];

/// Mensaje DHCP/BOOTP con opciones `(código, valor)`.
pub fn dhcp_message(
    op: u8,
    mac: [u8; 6],
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    options: &[(u8, &[u8])],
) -> Vec<u8> {
    let mut p = vec![0u8; 240];
    p[0] = op;
    p[1] = 1; // Ethernet
    p[2] = 6;
    p[4..8].copy_from_slice(&0x3903_f326u32.to_be_bytes());
    p[12..16].copy_from_slice(&ciaddr.octets());
    p[16..20].copy_from_slice(&yiaddr.octets());
    p[28..34].copy_from_slice(&mac);
    p[236..240].copy_from_slice(&[99, 130, 83, 99]);
    for (code, value) in options {
        p.push(*code);
        p.push(value.len() as u8);
        p.extend_from_slice(value);
    }
    p.push(255);
    p
}

/// Registro NetBIOS de un nombre de equipo (sufijo 0x00), como el que
/// difunde Windows al arrancar.
pub fn nbns_registration(name: &str, ip: Ipv4Addr) -> Vec<u8> {
    let mut p = vec![0x80, 0x01, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 1];
    let mut raw = [b' '; 16];
    raw[..name.len().min(15)].copy_from_slice(&name.as_bytes()[..name.len().min(15)]);
    raw[15] = 0x00;
    p.push(32);
    for b in raw {
        p.push(b'A' + (b >> 4));
        p.push(b'A' + (b & 0xf));
    }
    p.push(0);
    p.extend_from_slice(&[0, 0x20, 0, 1]); // NB, IN
    p.extend_from_slice(&[0xc0, 0x0c, 0, 0x20, 0, 1, 0, 0x04, 0x93, 0xe0, 0, 6, 0, 0]);
    p.extend_from_slice(&ip.octets());
    p
}

/// Registro de una respuesta mDNS.
pub enum MdnsRecord<'a> {
    /// Servicio anunciado: `_ipp._tcp.local` → `«instancia»._ipp._tcp.local`.
    Ptr { service: &'a str, instance: &'a str },
    /// Nombre de equipo: `HP-OfficeJet.local` → IP.
    A { name: &'a str, ip: Ipv4Addr },
}

/// Respuesta mDNS (o LLMNR, mismo formato) con los registros dados.
pub fn mdns_response(records: &[MdnsRecord]) -> Vec<u8> {
    let mut m = vec![0, 0, 0x84, 0x00, 0, 0];
    m.extend_from_slice(&(records.len() as u16).to_be_bytes());
    m.extend_from_slice(&[0, 0, 0, 0]);
    for r in records {
        match r {
            MdnsRecord::Ptr { service, instance } => {
                let target = encode_dns_name(&format!("{instance}.{service}"));
                m.extend_from_slice(&encode_dns_name(service));
                m.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0x11, 0x94]);
                m.extend_from_slice(&(target.len() as u16).to_be_bytes());
                m.extend_from_slice(&target);
            }
            MdnsRecord::A { name, ip } => {
                m.extend_from_slice(&encode_dns_name(name));
                m.extend_from_slice(&[0, 1, 0x80, 1, 0, 0, 0, 0x78, 0, 4]);
                m.extend_from_slice(&ip.octets());
            }
        }
    }
    m
}

/// Apretón de manos TCP + un mensaje del cliente + cierre.
#[allow(clippy::too_many_arguments)]
fn tcp_session(
    p: &mut Vec<(u64, Vec<u8>)>,
    t: u64,
    (cmac, smac): ([u8; 6], [u8; 6]),
    (cip, sip): (Ipv4Addr, Ipv4Addr),
    (cport, sport): (u16, u16),
    request: &[u8],
    response: &[u8],
) {
    use flags::*;
    let (c, s) = (1000u32, 5000u32);
    let req = request.len() as u32;
    let resp = response.len() as u32;
    p.push((
        t,
        frame_tcp(cmac, smac, cip, sip, cport, sport, c, 0, SYN, &[]),
    ));
    p.push((
        t + 20_000,
        frame_tcp(smac, cmac, sip, cip, sport, cport, s, c + 1, SYN_ACK, &[]),
    ));
    p.push((
        t + 21_000,
        frame_tcp(cmac, smac, cip, sip, cport, sport, c + 1, s + 1, ACK, &[]),
    ));
    p.push((
        t + 22_000,
        frame_tcp(
            cmac,
            smac,
            cip,
            sip,
            cport,
            sport,
            c + 1,
            s + 1,
            PSH_ACK,
            request,
        ),
    ));
    if !response.is_empty() {
        p.push((
            t + 60_000,
            frame_tcp(
                smac,
                cmac,
                sip,
                cip,
                sport,
                cport,
                s + 1,
                c + 1 + req,
                PSH_ACK,
                response,
            ),
        ));
    }
    p.push((
        t + 90_000,
        frame_tcp(
            cmac,
            smac,
            cip,
            sip,
            cport,
            sport,
            c + 1 + req,
            s + 1 + resp,
            FIN_ACK,
            &[],
        ),
    ));
    p.push((
        t + 110_000,
        frame_tcp(
            smac,
            cmac,
            sip,
            cip,
            sport,
            cport,
            s + 1 + resp,
            c + 2 + req,
            FIN_ACK,
            &[],
        ),
    ));
}

/// La red de casa, con marcas de tiempo, lista para [`crate::write_pcap`].
pub fn home_pcap_packets() -> Vec<(u64, Vec<u8>)> {
    let t0 = 1_760_000_000_000_000u64; // 2025-10-09T08:53:20Z
    let s = 1_000_000u64;
    let mut p: Vec<(u64, Vec<u8>)> = Vec::new();
    let unspecified = Ipv4Addr::UNSPECIFIED;

    // 1) El móvil llega a casa y pide dirección: se presenta como «iPhone-de-Ana».
    p.push((
        t0,
        frame_udp(
            MAC_HOME_PHONE,
            MAC_BROADCAST,
            unspecified,
            BROADCAST,
            68,
            67,
            &dhcp_message(
                1,
                MAC_HOME_PHONE,
                unspecified,
                unspecified,
                &[(53, &[3]), (50, &PHONE.octets()), (12, b"iPhone-de-Ana")],
            ),
        ),
    ));
    p.push((
        t0 + 3_000,
        frame_udp(
            MAC_HOME_ROUTER,
            MAC_HOME_PHONE,
            ROUTER,
            PHONE,
            67,
            68,
            &dhcp_message(
                2,
                MAC_HOME_PHONE,
                unspecified,
                PHONE,
                &[
                    (53, &[5]),
                    (54, &ROUTER.octets()),
                    (1, &[255, 255, 255, 0]),
                    (3, &ROUTER.octets()),
                    (6, &ROUTER.octets()),
                ],
            ),
        ),
    ));

    // 2) El PC renueva su dirección (Windows: «MSFT 5.0») y se anuncia por NetBIOS.
    p.push((
        t0 + s,
        frame_udp(
            MAC_HOME_PC,
            MAC_HOME_ROUTER,
            PC,
            ROUTER,
            68,
            67,
            &dhcp_message(
                1,
                MAC_HOME_PC,
                PC,
                unspecified,
                &[(53, &[3]), (12, b"DESKTOP-AB12"), (60, b"MSFT 5.0")],
            ),
        ),
    ));
    p.push((
        t0 + s + 2_000,
        frame_udp(
            MAC_HOME_ROUTER,
            MAC_HOME_PC,
            ROUTER,
            PC,
            67,
            68,
            &dhcp_message(
                2,
                MAC_HOME_PC,
                PC,
                PC,
                &[(53, &[5]), (54, &ROUTER.octets()), (3, &ROUTER.octets())],
            ),
        ),
    ));
    p.push((
        t0 + 2 * s,
        frame_udp(
            MAC_HOME_PC,
            MAC_BROADCAST,
            PC,
            LAN_BROADCAST,
            137,
            137,
            &nbns_registration("DESKTOP-AB12", PC),
        ),
    ));

    // 3) La impresora y la tele se anuncian por mDNS.
    p.push((
        t0 + 3 * s,
        frame_udp(
            MAC_HOME_PRINTER,
            MAC_MDNS,
            PRINTER,
            MDNS,
            5353,
            5353,
            &mdns_response(&[
                MdnsRecord::Ptr {
                    service: "_ipp._tcp.local",
                    instance: "HP OfficeJet Pro 8020",
                },
                MdnsRecord::A {
                    name: "HP-OfficeJet.local",
                    ip: PRINTER,
                },
            ]),
        ),
    ));
    p.push((
        t0 + 4 * s,
        frame_udp(
            MAC_HOME_TV,
            MAC_MDNS,
            TV,
            MDNS,
            5353,
            5353,
            &mdns_response(&[MdnsRecord::Ptr {
                service: "_googlecast._tcp.local",
                instance: "Salón",
            }]),
        ),
    ));

    // 4) El móvil abre Instagram (DNS por el router + conexión cifrada).
    p.push((
        t0 + 5 * s,
        frame_udp(
            MAC_HOME_PHONE,
            MAC_HOME_ROUTER,
            PHONE,
            DNS_GOOGLE,
            51000,
            53,
            &dns_query(7, "www.instagram.com", 1),
        ),
    ));
    p.push((
        t0 + 5 * s + 15_000,
        frame_udp(
            MAC_HOME_ROUTER,
            MAC_HOME_PHONE,
            DNS_GOOGLE,
            PHONE,
            53,
            51000,
            &dns_response(7, "www.instagram.com", 1, INSTAGRAM),
        ),
    ));
    tcp_session(
        &mut p,
        t0 + 6 * s,
        (MAC_HOME_PHONE, MAC_HOME_ROUTER),
        (PHONE, INSTAGRAM),
        (52344, 443),
        &client_hello("www.instagram.com", b"h2"),
        &[0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00],
    );

    // 5) El PC abre el correo (a través del DNS del router).
    p.push((
        t0 + 8 * s,
        frame_udp(
            MAC_HOME_PC,
            MAC_HOME_ROUTER,
            PC,
            ROUTER,
            50123,
            53,
            &dns_query(9, "outlook.office365.com", 1),
        ),
    ));
    p.push((
        t0 + 8 * s + 4_000,
        frame_udp(
            MAC_HOME_ROUTER,
            MAC_HOME_PC,
            ROUTER,
            PC,
            53,
            50123,
            &dns_response(9, "outlook.office365.com", 1, OUTLOOK),
        ),
    ));
    tcp_session(
        &mut p,
        t0 + 9 * s,
        (MAC_HOME_PC, MAC_HOME_ROUTER),
        (PC, OUTLOOK),
        (50124, 443),
        &client_hello("outlook.office365.com", b"h2"),
        &[0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00],
    );

    // 6) El PC imprime (puerto 9100 de la impresora).
    tcp_session(
        &mut p,
        t0 + 12 * s,
        (MAC_HOME_PC, MAC_HOME_PRINTER),
        (PC, PRINTER),
        (50200, 9100),
        b"\x1b%-12345X@PJL JOB NAME=\"lista-compra\"\r\n",
        &[],
    );

    // 7) Alguien entra al router por Telnet (sin cifrar): algo que revisar.
    tcp_session(
        &mut p,
        t0 + 20 * s,
        (MAC_HOME_PC, MAC_HOME_ROUTER),
        (PC, ROUTER),
        (50300, 23),
        b"admin\r\n",
        b"Password: ",
    );
    p.sort_by_key(|(t, _)| *t);
    p
}

/// Solo las tramas del escenario «casa» (para tests que no miran el tiempo).
pub fn home_network_frames() -> Vec<Vec<u8>> {
    home_pcap_packets().into_iter().map(|(_, f)| f).collect()
}
