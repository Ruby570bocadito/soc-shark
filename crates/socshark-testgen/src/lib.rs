//! socshark-testgen: constructores de tramas y capturas de prueba.
//!
//! Usado por los tests unitarios/de integración de todo el workspace y por
//! el comando `socshark dev sample-pcap`. Genera tramas Ethernet+IPv4+TCP/UDP
//! y mensajes DNS con checksums correctos (IPv4 y TCP con pseudo-cabecera)
//! para que los parsers trabajen con datos realistas.
//!
//! Al ser una crate de utilidad no depende de ningún otro crate del
//! workspace: nada del "código bajo test" puede colarse en los fixtures.

use std::io::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub mod fuzz;

// ---------------------------------------------------------------- checksums

fn ones_sum(bytes: &[u8]) -> u64 {
    let mut sum = 0u64;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u64;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u64) << 8;
    }
    sum
}

fn checksum16(bytes: &[u8]) -> u16 {
    // Acumulador u64: los pseudo-cabeceras de segmentos grandes (hasta 1 MiB
    // en los fixtures de reensamblado) desbordarían un u32 antes de plegar.
    let mut s = ones_sum(bytes);
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

// ------------------------------------------------------------ constructores

/// Trama Ethernet completa: eth + ipv4 + l4 (con checksum IP correcto).
pub fn frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ttl: u8,
    l4: &[u8],
    proto: u8,
) -> Vec<u8> {
    let total_len = (20 + l4.len()) as u16;
    let mut ip = Vec::with_capacity(20 + l4.len());
    ip.extend_from_slice(&[0x45, 0x00]); // versión 4, IHL 5, DSCP 0
    ip.extend_from_slice(&total_len.to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x01]); // id
    ip.extend_from_slice(&[0x40, 0x00]); // flags DF, offset 0
    ip.push(ttl);
    ip.push(proto);
    ip.extend_from_slice(&[0, 0]); // checksum provisional
    ip.extend_from_slice(&src_ip.octets());
    ip.extend_from_slice(&dst_ip.octets());
    let ck = checksum16(&ip);
    ip[10..12].copy_from_slice(&ck.to_be_bytes());

    let mut out = Vec::with_capacity(14 + ip.len());
    out.extend_from_slice(&dst_mac);
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&0x0800u16.to_be_bytes());
    out.extend_from_slice(&ip);
    out.extend_from_slice(l4);
    out
}

/// Segmento TCP con checksum (pseudo-cabecera incluida, RFC 9293).
#[allow(clippy::too_many_arguments)]
pub fn tcp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut seg = tcp_segment(src_port, dst_port, seq, ack, flags, payload);
    let mut pseudo = Vec::with_capacity(12 + seg.len());
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.extend_from_slice(&[0, 6]); // protocolo TCP
    pseudo.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&seg);
    let ck = checksum16(&pseudo);
    seg[16..18].copy_from_slice(&ck.to_be_bytes());
    seg
}

/// Segmento TCP sin checksum (lo rellena cada variante de IP).
#[allow(clippy::too_many_arguments)]
fn tcp_segment(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut seg = Vec::with_capacity(20 + payload.len());
    seg.extend_from_slice(&src_port.to_be_bytes());
    seg.extend_from_slice(&dst_port.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(&ack.to_be_bytes());
    seg.extend_from_slice(&[0x50, flags]); // data offset 5 (20 bytes)
    seg.extend_from_slice(&8192u16.to_be_bytes()); // window
    seg.extend_from_slice(&[0, 0]); // checksum provisional
    seg.extend_from_slice(&[0, 0]); // urgent pointer
    seg.extend_from_slice(payload);
    seg
}

/// Datagrama UDP (checksum 0 = no verificado, válido en IPv4).
pub fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut seg = Vec::with_capacity(8 + payload.len());
    seg.extend_from_slice(&src_port.to_be_bytes());
    seg.extend_from_slice(&dst_port.to_be_bytes());
    seg.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    seg.extend_from_slice(&[0, 0]);
    seg.extend_from_slice(payload);
    seg
}

/// Atajo: trama UDP completa (eth + ip + udp + payload).
pub fn frame_udp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let l4 = udp(sport, dport, payload);
    frame(src_mac, dst_mac, src_ip, dst_ip, 64, &l4, 17)
}

/// Atajo: trama TCP completa.
#[allow(clippy::too_many_arguments)]
pub fn frame_tcp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let l4 = tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, payload);
    frame(src_mac, dst_mac, src_ip, dst_ip, 64, &l4, 6)
}

// ------------------------------------------------------------ IPv6 (Fase 2)

/// Cabecera IPv6 fija (40 bytes, sin extensiones).
fn ipv6_header(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload_len: usize) -> Vec<u8> {
    let mut ip = Vec::with_capacity(40);
    ip.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // versión 6, TC 0, FL 0
    ip.extend_from_slice(&(payload_len as u16).to_be_bytes());
    ip.push(next_header);
    ip.push(64); // hop limit
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    ip
}

/// Checksum L4 con pseudo-cabecera común a IPv4 e IPv6 (RFC 1071/2460).
fn l4_checksum(seg: &[u8], src: &[u8], dst: &[u8], proto: u8) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + seg.len());
    pseudo.extend_from_slice(src);
    pseudo.extend_from_slice(dst);
    pseudo.extend_from_slice(&(seg.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0]); // reservado
    pseudo.push(proto);
    pseudo.extend_from_slice(seg);
    checksum16(&pseudo)
}

/// Segmento TCP sobre IPv6 con checksum (pseudo-cabecera v6).
#[allow(clippy::too_many_arguments)]
pub fn ipv6_tcp(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let seg = tcp_segment(src_port, dst_port, seq, ack, flags, payload);
    let mut seg = seg;
    let ck = l4_checksum(&seg, &src.octets(), &dst.octets(), 6);
    seg[16..18].copy_from_slice(&ck.to_be_bytes());
    seg
}

/// Datagrama UDP sobre IPv6 con checksum (obligatorio en IPv6, RFC 2460).
pub fn ipv6_udp(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut seg = Vec::with_capacity(8 + payload.len());
    seg.extend_from_slice(&src_port.to_be_bytes());
    seg.extend_from_slice(&dst_port.to_be_bytes());
    seg.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    seg.extend_from_slice(&[0, 0]); // checksum provisional
    seg.extend_from_slice(payload);
    let ck = l4_checksum(&seg, &src.octets(), &dst.octets(), 17);
    seg[6..8].copy_from_slice(&ck.to_be_bytes());
    seg
}

/// Atajo: trama Ethernet + IPv6 + UDP completa.
pub fn frame_ipv6_udp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let l4 = ipv6_udp(src, dst, sport, dport, payload);
    let mut out = Vec::with_capacity(14 + 40 + l4.len());
    out.extend_from_slice(&dst_mac);
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&0x86ddu16.to_be_bytes());
    out.extend_from_slice(&ipv6_header(src, dst, 17, l4.len()));
    out.extend_from_slice(&l4);
    out
}

/// Atajo: trama Ethernet + IPv6 + TCP completa.
#[allow(clippy::too_many_arguments)]
pub fn frame_ipv6_tcp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let l4 = ipv6_tcp(src, dst, sport, dport, seq, ack, flags, payload);
    let mut out = Vec::with_capacity(14 + 40 + l4.len());
    out.extend_from_slice(&dst_mac);
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&0x86ddu16.to_be_bytes());
    out.extend_from_slice(&ipv6_header(src, dst, 6, l4.len()));
    out.extend_from_slice(&l4);
    out
}

// --------------------------------------------------------------------- DNS

/// Codifica un nombre en formato DNS (etiquetas length-prefixed + raíz).
pub fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// Mensaje DNS de consulta (una pregunta, RD=1).
pub fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    m.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar = 0
    m.extend_from_slice(&encode_dns_name(name));
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes()); // clase IN
    m
}

/// Mensaje DNS de respuesta (A con nombre comprimido por puntero 0xc00c).
///
/// Genera el patrón de compresión real de los resolvers: el nombre de la
/// respuesta apunta al nombre de la pregunta (offset 12).
pub fn dns_response(id: u16, name: &str, qtype: u16, addr: Ipv4Addr) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&0x8180u16.to_be_bytes()); // QR + RD + RA
    m.extend_from_slice(&1u16.to_be_bytes()); // qd
    m.extend_from_slice(&1u16.to_be_bytes()); // an
    m.extend_from_slice(&[0, 0, 0, 0]);
    m.extend_from_slice(&encode_dns_name(name));
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    // answer: puntero al nombre de la pregunta (offset 12)
    m.extend_from_slice(&0xc00cu16.to_be_bytes());
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&300u32.to_be_bytes()); // TTL
    m.extend_from_slice(&4u16.to_be_bytes()); // rdlength
    m.extend_from_slice(&addr.octets()); // rdata
    m
}

/// Respuesta DNS AAAA (dirección IPv6 de 16 bytes en rdata).
pub fn dns_response_aaaa(id: u16, name: &str, addr: Ipv6Addr) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&0x8180u16.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&[0, 0, 0, 0]);
    m.extend_from_slice(&encode_dns_name(name));
    m.extend_from_slice(&28u16.to_be_bytes()); // AAAA
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&0xc00cu16.to_be_bytes());
    m.extend_from_slice(&28u16.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&300u32.to_be_bytes());
    m.extend_from_slice(&16u16.to_be_bytes()); // rdlength
    m.extend_from_slice(&addr.octets());
    m
}

/// Flags TCP útiles para los constructores.
pub mod flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const SYN_ACK: u8 = SYN | ACK;
    pub const FIN_ACK: u8 = FIN | ACK;
    pub const PSH_ACK: u8 = PSH | ACK;
}

// ------------------------------------------------------ escritura de pcaps

/// Escribe un pcap clásico little-endian en microsegundos.
///
/// `link_type` es el código LINKTYPE (1 = Ethernet).
pub fn write_pcap(
    path: impl AsRef<Path>,
    link_type: u32,
    packets: &[(u64, Vec<u8>)],
) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes()); // versión 2.4
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    buf.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    buf.extend_from_slice(&link_type.to_le_bytes());
    for (ts_micros, data) in packets {
        let ts_sec = (ts_micros / 1_000_000) as u32;
        let ts_frac = (ts_micros % 1_000_000) as u32;
        buf.extend_from_slice(&ts_sec.to_le_bytes());
        buf.extend_from_slice(&ts_frac.to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
    }
    f.write_all(&buf)
}

// ---------------------------------------------------------- escenario demo

/// MACs e IPs ficticias del escenario (publics para que los tests las usen).
pub const MAC_ROUTER: [u8; 6] = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
pub const MAC_HOST_A: [u8; 6] = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01];
pub const MAC_HOST_B: [u8; 6] = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02];
pub const MAC_HOST_C: [u8; 6] = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x03];

pub const HOST_A: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
pub const HOST_B: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);
pub const HOST_C: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 30);
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
pub const DNS_EXT: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
pub const WEB: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
pub const NTP: Ipv4Addr = Ipv4Addr::new(17, 253, 0, 1);
pub const MDNS_MCAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

// Extremos IPv6 del escenario (Fase 2).
pub const HOST_A6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x10);
pub const DNS6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
pub const WEB6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0, 0, 0, 0x248);

/// qname de alta entropía del túnel DNS demo (60 caracteres, 30 símbolos
/// distintos repetidos dos veces → entropía ≈ log2(30) ≈ 4.91 bits).
pub const TUNNEL_QNAME: &str =
    "az3k9t2wq7xm5vb8n4rj6yp1chfdgsaz3k9t2wq7xm5vb8n4rj6yp1chfdgs.tun.evil.example";

/// Servidor C2 simulado del beacon (TEST-NET-2, doc RFC 5737).
pub const C2: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 23);

/// Registro TLS con un ClientHello completo y realista (Fase 3).
///
/// TLS 1.3 (supported_versions sobre legacy 1.2), SNI, ALPN, signature
/// algorithms, key share y grupos. Es lo que un cliente moderno envía y
/// produce una huella JA4 estable para el escenario demo.
pub fn client_hello(sni: &str, alpn: &[u8]) -> Vec<u8> {
    // Extensiones (formato: tipo u16 + longitud u16 + datos).
    let name = sni.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0); // host_name
    sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(name);

    let mut alpn_ext = Vec::new();
    alpn_ext.extend_from_slice(&((alpn.len() + 1) as u16).to_be_bytes());
    alpn_ext.push(alpn.len() as u8);
    alpn_ext.extend_from_slice(alpn);

    let sig: [u8; 16] = [
        0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06,
        0x01,
    ];
    let mut sig_ext = (sig.len() as u16).to_be_bytes().to_vec();
    sig_ext.extend_from_slice(&sig);

    let sv_ext: Vec<u8> = vec![4, 0x03, 0x04, 0x03, 0x03]; // TLS 1.3 y 1.2
    let groups_ext: Vec<u8> = vec![4, 0x00, 0x1d, 0x00, 0x17]; // x25519, secp256r1
    let mut ks_ext: Vec<u8> = vec![64, 0x00, 0x1d, 0x00, 0x20]; // cabecera del key_share
                                                                // `repeat_n` es de Rust 1.82; el MSRV del workspace es 1.75 (ADR-001).
    #[allow(clippy::manual_repeat_n)]
    ks_ext.extend(std::iter::repeat(0x11).take(32));

    let exts: [(u16, Vec<u8>); 8] = [
        (0x0000, sni_ext),
        (0x0010, alpn_ext),
        (0x000d, sig_ext),
        (0x002b, sv_ext),
        (0x000a, groups_ext),
        (0x0033, ks_ext),
        (0x002d, vec![1]), // psk_key_exchange_modes
        (0x0017, vec![]),  // extended_master_secret
    ];
    let mut ext_blob = Vec::new();
    for (t, d) in &exts {
        ext_blob.extend_from_slice(&t.to_be_bytes());
        ext_blob.extend_from_slice(&(d.len() as u16).to_be_bytes());
        ext_blob.extend_from_slice(d);
    }

    // Cuerpo del handshake: version + random + sid + ciphers + compression + exts.
    let mut body = vec![0x03, 0x03]; // legacy_version TLS 1.2
    body.extend_from_slice(&[0xaa; 32]); // random (fijo para reproducibilidad)
    body.push(0x00); // session_id vacío
    let ciphers: [u8; 4] = [0x13, 0x01, 0xc0, 0x2b]; // AES128GCM-SHA256, ECDHE-ECDSA-AES128
    body.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
    body.extend_from_slice(&ciphers);
    body.push(0x01); // 1 método de compresión
    body.push(0x00); // null
    body.extend_from_slice(&(ext_blob.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_blob);

    // Mensaje handshake + registro TLS. Convención TLS real: la longitud del
    // mensaje handshake NO incluye su propia cabecera de 4 bytes; la del
    // registro SÍ incluye esa cabecera.
    let mut out = vec![0x16, 0x03, 0x01];
    let rec_len = body.len() + 4;
    out.extend_from_slice(&(rec_len as u16).to_be_bytes());
    out.push(0x01); // ClientHello
    let hs = (body.len() as u32).to_be_bytes();
    out.extend_from_slice(&hs[1..4]);
    out.extend_from_slice(&body);
    out
}

/// Escenario demo completo: tráfico variado con eventos SOC interesantes.
///
/// Devuelve `(timestamp_micros, trama)` lista para [`write_pcap`]. Contiene:
/// 1. Resolución DNS legítima de `example.com` + sesión TLS con ClientHello
///    realista (produce huella JA4 y SNI desde la Fase 3).
/// 2. Ruido de fondo: NTP y mDNS.
/// 3. Posible túnel DNS (qname largo de alta entropía, TXT al resolver).
/// 4. Escaneo SYN hacia el gateway (5 SYNs, puertos origen distintos).
/// 5. Banner SSH y petición HTTP en texto claro.
/// 6. DNS sobre IPv6 (Fase 2).
/// 7. Beacon UDP cada 30 s hacia un C2 simulado (Fase 3: alerta BEACONING
///    por regularidad de intervalos, MITRE T1071).
pub fn sample_pcap_packets() -> Vec<(u64, Vec<u8>)> {
    let t0 = 1_700_000_000_000_000u64; // 2023-11-14T22:13:20Z
    let mut p: Vec<(u64, Vec<u8>)> = Vec::new();

    // 1) DNS legítimo: example.com → 93.184.216.34.
    p.push((
        t0,
        frame_udp(
            MAC_HOST_A,
            MAC_ROUTER,
            HOST_A,
            DNS_EXT,
            53001,
            53,
            &dns_query(0x1234, "example.com", 1),
        ),
    ));
    p.push((
        t0 + 10_000,
        frame_udp(
            MAC_ROUTER,
            MAC_HOST_A,
            DNS_EXT,
            HOST_A,
            53,
            53001,
            &dns_response(0x1234, "example.com", 1, WEB),
        ),
    ));

    // 2) Sesión TLS: handshake con ClientHello realista (JA4/SNI, Fase 3)
    //    + cierre limpio (FIN/FIN-ACK).
    let (sp, seq0) = (52000u16, 1000u32);
    let client_hello = client_hello("store.ejemplo-corporativo.com", b"h2");
    let server_hello: &[u8] = &[
        0x16, 0x03, 0x03, 0x00, 0x31, 0x02, 0x00, 0x00, 0x2d, 0x03, 0x03, 0xdd, 0xee, 0xff,
    ];
    let ch_end = seq0 + 1 + client_hello.len() as u32;
    let sh_end = 5001 + server_hello.len() as u32;
    p.push((
        t0 + 500_000,
        frame_tcp(
            MAC_HOST_A,
            MAC_ROUTER,
            HOST_A,
            WEB,
            sp,
            443,
            seq0,
            0,
            flags::SYN,
            &[],
        ),
    ));
    p.push((
        t0 + 501_000,
        frame_tcp(
            MAC_ROUTER,
            MAC_HOST_A,
            WEB,
            HOST_A,
            443,
            sp,
            5000,
            seq0 + 1,
            flags::SYN_ACK,
            &[],
        ),
    ));
    p.push((
        t0 + 502_000,
        frame_tcp(
            MAC_HOST_A,
            MAC_ROUTER,
            HOST_A,
            WEB,
            sp,
            443,
            seq0 + 1,
            5001,
            flags::ACK,
            &[],
        ),
    ));
    p.push((
        t0 + 503_000,
        frame_tcp(
            MAC_HOST_A,
            MAC_ROUTER,
            HOST_A,
            WEB,
            sp,
            443,
            seq0 + 1,
            5001,
            flags::PSH_ACK,
            &client_hello,
        ),
    ));
    p.push((
        t0 + 504_000,
        frame_tcp(
            MAC_ROUTER,
            MAC_HOST_A,
            WEB,
            HOST_A,
            443,
            sp,
            5001,
            ch_end,
            flags::PSH_ACK,
            server_hello,
        ),
    ));
    p.push((
        t0 + 900_000,
        frame_tcp(
            MAC_HOST_A,
            MAC_ROUTER,
            HOST_A,
            WEB,
            sp,
            443,
            ch_end,
            sh_end,
            flags::FIN_ACK,
            &[],
        ),
    ));
    p.push((
        t0 + 950_000,
        frame_tcp(
            MAC_ROUTER,
            MAC_HOST_A,
            WEB,
            HOST_A,
            443,
            sp,
            sh_end,
            ch_end + 1,
            flags::FIN_ACK,
            &[],
        ),
    ));

    // 3) Ruido de fondo: NTP y mDNS.
    p.push((
        t0 + 1_000_000,
        frame_udp(MAC_HOST_A, MAC_ROUTER, HOST_A, NTP, 123, 123, &[0u8; 48]),
    ));
    p.push((
        t0 + 1_100_000,
        frame_udp(
            MAC_HOST_B,
            MAC_ROUTER,
            HOST_B,
            MDNS_MCAST,
            5353,
            5353,
            &dns_query(0, "_services._dns-sd._udp.local", 12),
        ),
    ));

    // 4) Posible túnel DNS: qname largo de alta entropía (TXT) al resolver.
    p.push((
        t0 + 2_000_000,
        frame_udp(
            MAC_HOST_C,
            MAC_ROUTER,
            HOST_C,
            DNS_EXT,
            53002,
            53,
            &dns_query(0xbeef, TUNNEL_QNAME, 16),
        ),
    ));

    // 5) Escaneo SYN: 5 conexiones de un solo SYN al 22 del gateway.
    for i in 0..5u16 {
        p.push((
            t0 + 3_000_000 + i as u64 * 100_000,
            frame_tcp(
                MAC_HOST_C,
                MAC_ROUTER,
                HOST_C,
                GATEWAY,
                40001 + i,
                22,
                1,
                0,
                flags::SYN,
                &[],
            ),
        ));
    }

    // 6) Banner SSH.
    p.push((
        t0 + 5_000_000,
        frame_tcp(
            MAC_HOST_B,
            MAC_ROUTER,
            HOST_B,
            GATEWAY,
            40110,
            22,
            7,
            9,
            flags::PSH_ACK,
            b"SSH-2.0-OpenSSH_8.9p1\r\n",
        ),
    ));

    // 7) Petición HTTP en texto claro (hacia la IP que resolvió example.com).
    p.push((
        t0 + 5_200_000,
        frame_tcp(
            MAC_HOST_B,
            MAC_ROUTER,
            HOST_B,
            WEB,
            40111,
            80,
            11,
            13,
            flags::PSH_ACK,
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ),
    ));

    // 8) DNS sobre IPv6 (Fase 2): consulta AAAA + respuesta.
    p.push((
        t0 + 6_000_000,
        frame_ipv6_udp(
            MAC_HOST_A,
            MAC_ROUTER,
            HOST_A6,
            DNS6,
            53010,
            53,
            &dns_query(0x0606, "v6.example.com", 28),
        ),
    ));
    p.push((
        t0 + 6_010_000,
        frame_ipv6_udp(
            MAC_ROUTER,
            MAC_HOST_A,
            DNS6,
            HOST_A6,
            53,
            53010,
            &dns_response_aaaa(0x0606, "v6.example.com", WEB6),
        ),
    ));

    // 9) Beacon UDP (Fase 3): el equipo comprometido (HOST_C, el mismo del
    //    túnel DNS y el escaneo) "llama a casa" cada 30 s al C2 simulado.
    //    8 datagramas = 7 intervalos de 30 s exactos → alerta BEACONING
    //    (T1071) con periodo estimado 30.0 s. Sin handshake: sesión larga
    //    preestablecida, como hacen los beacons reales.
    let beacon_payload: Vec<u8> = (0..64u8).collect();
    for i in 0..8u16 {
        p.push((
            t0 + 10_000_000 + i as u64 * 30_000_000,
            frame_udp(
                MAC_HOST_C,
                MAC_ROUTER,
                HOST_C,
                C2,
                53100,
                8080,
                &beacon_payload,
            ),
        ));
    }

    p
}

/// Valida los fixtures en tiempo de test (smoke test de los builders).
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn escenario_demo_genera_paquetes_validos() {
        let pkts = sample_pcap_packets();
        // 2 DNS + 7 TLS + 2 ruido + 1 túnel + 5 escaneo + 1 SSH + 1 HTTP
        // + 2 DNS-IPv6 + 8 beacon = 29.
        assert_eq!(pkts.len(), 29);
        // Todas las tramas deben ser >= 34 bytes (eth + ip mínimo).
        assert!(pkts.iter().all(|(_, d)| d.len() >= 34));
    }

    #[test]
    fn client_hello_del_demo_parsea_completo() {
        let hello = client_hello("demo.example", b"h2");
        // Cabecera de registro de 5 bytes: tipo handshake 0x16 y longitud coherente.
        assert_eq!(hello[0], 0x16);
        let rec_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(hello.len(), 5 + rec_len);
        // El mensaje declara su longitud completa: el parser del dissector
        // debe poder cerrar la captura con un único segmento.
        let hs_len = ((hello[6] as usize) << 16) | ((hello[7] as usize) << 8) | hello[8] as usize;
        assert_eq!(hello.len(), 9 + hs_len);
    }

    #[test]
    fn checksum_ipv6_udp_es_valido() {
        // Recalcula el checksum sobre la pseudo-cabecera v6 y debe dar 0xffff
        // tras plegar (el campo checksum incluido).
        let frame = frame_ipv6_udp(
            MAC_HOST_A,
            MAC_ROUTER,
            HOST_A6,
            DNS6,
            53010,
            53,
            &dns_query(1, "ck.example", 1),
        );
        let ip = &frame[14..];
        let payload_len = u16::from_be_bytes([ip[4], ip[5]]) as usize;
        let l4 = &ip[40..40 + payload_len];
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&HOST_A6.octets());
        pseudo.extend_from_slice(&DNS6.octets());
        pseudo.extend_from_slice(&(l4.len() as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
        pseudo.extend_from_slice(l4);
        let mut s = ones_sum(&pseudo);
        while s >> 16 != 0 {
            s = (s & 0xffff) + (s >> 16);
        }
        assert_eq!(s as u16, 0xffff);
    }

    #[test]
    fn ip_literal_dns_ext() {
        assert_eq!(DNS_EXT, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(IpAddr::V4(WEB).to_string(), "93.184.216.34");
    }

    #[test]
    fn nombre_dns_codificado_roundtrip_manual() {
        let enc = encode_dns_name("a.b");
        assert_eq!(enc, vec![1, b'a', 1, b'b', 0]);
    }
}
