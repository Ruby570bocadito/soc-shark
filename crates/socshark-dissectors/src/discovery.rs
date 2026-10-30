//! Pistas de identidad de los equipos de la red local.
//!
//! Los equipos anuncian solos cómo se llaman: al pedir dirección por DHCP
//! («iPhone-de-Ana», «DESKTOP-AB12»), en NetBIOS (nombre de Windows) y en
//! mDNS/LLMNR (estos dos usan el formato DNS y los decodifica `dns`). Aquí
//! solo se extrae lo necesario para ponerles nombre: nada se interpreta
//! como orden ni se confía en ello para decidir alertas.
//!
//! Seguridad: todo acceso a bytes está acotado y los nombres se limpian
//! (solo caracteres imprimibles, longitud máxima) antes de salir de aquí.

use std::net::Ipv4Addr;

/// Longitud máxima de un nombre anunciado que se conserva.
const MAX_NAME: usize = 63;
/// Opciones DHCP recorridas como mucho (anti bucles con opciones basura).
const MAX_OPTIONS: usize = 128;
const DHCP_MAGIC: [u8; 4] = [99, 130, 83, 99];

/// Lo que interesa de un mensaje DHCP/BOOTP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DhcpInfo {
    /// 1 = del cliente, 2 = del servidor.
    pub op: u8,
    /// Opción 53: 1 DISCOVER, 2 OFFER, 3 REQUEST, 5 ACK, 8 INFORM…
    pub message_type: Option<u8>,
    /// Dirección física del cliente (`chaddr`, solo Ethernet).
    pub client_mac: Option<[u8; 6]>,
    /// `ciaddr`: la IP que ya usa el cliente.
    pub client_ip: Option<Ipv4Addr>,
    /// `yiaddr`: la IP que el servidor le asigna.
    pub your_ip: Option<Ipv4Addr>,
    /// Opción 50: la IP que el cliente pide.
    pub requested_ip: Option<Ipv4Addr>,
    /// Opción 12: el nombre que el equipo se pone.
    pub hostname: Option<String>,
    /// Opción 60: identifica el sistema («MSFT 5.0», «android-dhcp-13»).
    pub vendor_class: Option<String>,
    /// Opción 54: el servidor DHCP (casi siempre el router).
    pub server_id: Option<Ipv4Addr>,
    /// Opción 3: puerta de enlace (el router).
    pub router: Option<Ipv4Addr>,
}

impl DhcpInfo {
    /// La IP que el cliente tiene o va a tener, si se sabe.
    pub fn client_address(&self) -> Option<Ipv4Addr> {
        self.client_ip.or(self.your_ip).or(self.requested_ip)
    }
}

fn ipv4_at(data: &[u8], off: usize) -> Option<Ipv4Addr> {
    let b: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
    let ip = Ipv4Addr::from(b);
    (!ip.is_unspecified()).then_some(ip)
}

/// Caracteres de formato invisibles que alteran cómo se *ve* un texto sin
/// verse ellos: marcas y aislamientos bidi (U+202A–U+202E, U+2066–U+2069,
/// U+200E/U+200F, U+061C), ancho cero (U+200B–U+200D, U+2060) y BOM
/// (U+FEFF). Un nombre anunciado con ellos puede hacerse pasar por otro en
/// la UI («Trojan Source»), así que nunca se muestran tal cual.
pub(crate) fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2069}'
            | '\u{061c}'
            | '\u{feff}'
    )
}

/// Texto anunciado por la red, limpio: imprimible (sin control ni formato
/// invisible), sin espacios sobrantes y acotado. `None` si no queda nada.
pub fn clean_name(raw: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_control() && *c != '\u{fffd}' && !is_invisible_format(*c))
        .take(MAX_NAME)
        .collect();
    let trimmed = cleaned.trim().trim_end_matches('.').trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Parsea un mensaje DHCP (payload UDP de los puertos 67/68).
pub fn parse_dhcp(data: &[u8]) -> Option<DhcpInfo> {
    if data.len() < 240 || data[236..240] != DHCP_MAGIC {
        return None;
    }
    let op = data[0];
    if op != 1 && op != 2 {
        return None;
    }
    let mut info = DhcpInfo {
        op,
        client_ip: ipv4_at(data, 12),
        your_ip: ipv4_at(data, 16),
        ..DhcpInfo::default()
    };
    // htype 1 (Ethernet) con hlen 6: chaddr es una MAC.
    if data[1] == 1 && data[2] == 6 {
        let mac: [u8; 6] = data[28..34].try_into().ok()?;
        if mac != [0; 6] {
            info.client_mac = Some(mac);
        }
    }
    let mut i = 240;
    for _ in 0..MAX_OPTIONS {
        let Some(&code) = data.get(i) else { break };
        match code {
            0 => {
                i += 1;
                continue;
            }
            255 => break,
            _ => {}
        }
        let Some(&len) = data.get(i + 1) else { break };
        let Some(value) = data.get(i + 2..i + 2 + len as usize) else {
            break;
        };
        match code {
            53 if len == 1 => info.message_type = Some(value[0]),
            50 if len == 4 => info.requested_ip = ipv4_at(value, 0),
            54 if len == 4 => info.server_id = ipv4_at(value, 0),
            3 if len >= 4 => info.router = ipv4_at(value, 0),
            12 => info.hostname = clean_name(value),
            60 => info.vendor_class = clean_name(value),
            _ => {}
        }
        i += 2 + len as usize;
    }
    Some(info)
}

/// Un nombre NetBIOS asociado a una IP (registro o respuesta).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NbnsName {
    /// Nombre del equipo (hasta 15 caracteres, como lo escribe Windows).
    pub name: String,
    /// Sufijo: 0x00 estación de trabajo, 0x20 servidor de archivos.
    pub suffix: u8,
    /// IP dueña del nombre.
    pub address: Ipv4Addr,
}

/// Decodifica un nombre NetBIOS de primer nivel (32 letras A–P) en el
/// desplazamiento `off`. Devuelve `(nombre, sufijo, siguiente_offset)`.
fn nb_name(data: &[u8], off: usize) -> Option<(String, u8, usize)> {
    if *data.get(off)? != 32 {
        return None;
    }
    let enc = data.get(off + 1..off + 33)?;
    let mut raw = [0u8; 16];
    for (k, out) in raw.iter_mut().enumerate() {
        let (hi, lo) = (
            enc[2 * k].wrapping_sub(b'A'),
            enc[2 * k + 1].wrapping_sub(b'A'),
        );
        if hi > 15 || lo > 15 {
            return None;
        }
        *out = (hi << 4) | lo;
    }
    // Sin ámbito (scope): la etiqueta siguiente es la final.
    if *data.get(off + 33)? != 0 {
        return None;
    }
    let suffix = raw[15];
    let name = raw[..15]
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect::<String>();
    let name = name.trim_end().to_string();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return None;
    }
    Some((name, suffix, off + 34))
}

/// Parsea NetBIOS Name Service (UDP 137) y devuelve el nombre de equipo
/// que el mensaje asocia a una IP: registros/refrescos (los anuncia su
/// dueño) y respuestas positivas. Las preguntas no dicen de quién es nada.
pub fn parse_nbns(data: &[u8]) -> Option<NbnsName> {
    if data.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = ((flags >> 11) & 0xf) as u8;
    let qd = u16::from_be_bytes([data[4], data[5]]);
    let an = u16::from_be_bytes([data[6], data[7]]);
    let ar = u16::from_be_bytes([data[10], data[11]]);
    // Registro (5), refresco (8/9) con un registro adicional, o respuesta
    // positiva a una consulta (opcode 0) con una respuesta.
    let registration = !is_response && matches!(opcode, 5 | 8 | 9) && qd == 1 && ar >= 1;
    let answer = is_response && opcode == 0 && an >= 1 && flags & 0xf == 0;
    if !registration && !answer {
        return None;
    }
    let (name, suffix, mut off) = nb_name(data, 12)?;
    if registration {
        off += 4; // tipo y clase de la pregunta
                  // El registro adicional repite el nombre (normalmente con puntero).
        off = match data.get(off)? {
            b if b & 0xc0 == 0xc0 => off + 2,
            _ => nb_name(data, off)?.2,
        };
    }
    // tipo (NB = 0x20), clase, TTL, longitud y datos (flags + IPv4).
    let rtype = u16::from_be_bytes(data.get(off..off + 2)?.try_into().ok()?);
    let rdlen = u16::from_be_bytes(data.get(off + 8..off + 10)?.try_into().ok()?);
    if rtype != 0x20 || rdlen < 6 {
        return None;
    }
    let nb_flags = u16::from_be_bytes(data.get(off + 10..off + 12)?.try_into().ok()?);
    // Los nombres de grupo (WORKGROUP…) no son de un equipo.
    if nb_flags & 0x8000 != 0 || !matches!(suffix, 0x00 | 0x20) {
        return None;
    }
    let address = ipv4_at(data, off + 12)?;
    Some(NbnsName {
        name,
        suffix,
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_name_quita_bidi_y_ancho_cero() {
        let raw = "PC-\u{202e}gpj.exe\u{200b}\u{feff}-Ana\u{2066}x\u{2069}".as_bytes();
        assert_eq!(clean_name(raw).as_deref(), Some("PC-gpj.exe-Anax"));
        assert_eq!(clean_name("\u{200f}\u{202a}".as_bytes()), None);
    }

    fn dhcp(op: u8, mac: [u8; 6], options: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 240];
        p[0] = op;
        p[1] = 1;
        p[2] = 6;
        p[28..34].copy_from_slice(&mac);
        p[236..240].copy_from_slice(&DHCP_MAGIC);
        p.extend_from_slice(options);
        p.push(255);
        p
    }

    #[test]
    fn dhcp_request_con_nombre_y_sistema() {
        let mac = [0xa4, 0x83, 0xe7, 1, 2, 3];
        let mut opts = vec![53, 1, 3, 50, 4, 192, 168, 1, 30];
        opts.extend_from_slice(&[12, 13]);
        opts.extend_from_slice(b"iPhone-de-Ana");
        opts.extend_from_slice(&[60, 15]);
        opts.extend_from_slice(b"android-dhcp-1");
        opts.push(b'3');
        let info = parse_dhcp(&dhcp(1, mac, &opts)).unwrap();
        assert_eq!(info.message_type, Some(3));
        assert_eq!(info.client_mac, Some(mac));
        assert_eq!(info.hostname.as_deref(), Some("iPhone-de-Ana"));
        assert_eq!(info.vendor_class.as_deref(), Some("android-dhcp-13"));
        assert_eq!(info.client_address(), Some(Ipv4Addr::new(192, 168, 1, 30)));
    }

    #[test]
    fn dhcp_ack_del_router() {
        let mut p = dhcp(
            2,
            [1, 2, 3, 4, 5, 6],
            &[53, 1, 5, 54, 4, 192, 168, 1, 1, 3, 4, 192, 168, 1, 1],
        );
        p[16..20].copy_from_slice(&[192, 168, 1, 30]);
        let info = parse_dhcp(&p).unwrap();
        assert_eq!(info.your_ip, Some(Ipv4Addr::new(192, 168, 1, 30)));
        assert_eq!(info.router, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(info.server_id, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn dhcp_malformado_no_explota() {
        assert!(parse_dhcp(&[]).is_none());
        assert!(parse_dhcp(&[0u8; 300]).is_none(), "sin cookie mágica");
        // Opción que dice medir más de lo que queda: se para sin panic.
        let p = dhcp(1, [0; 6], &[12, 200, b'x']);
        let info = parse_dhcp(&p).unwrap();
        assert_eq!(info.hostname, None);
        // Nombre con controles y basura: se limpia.
        let p = dhcp(1, [0; 6], &[12, 6, b'a', 0, b'b', 0x1b, b'c', b'.']);
        assert_eq!(parse_dhcp(&p).unwrap().hostname.as_deref(), Some("abc"));
        for cut in 0..p.len() {
            let _ = parse_dhcp(&p[..cut]);
        }
    }

    fn encode_nb(name: &str, suffix: u8) -> Vec<u8> {
        let mut raw = [b' '; 16];
        raw[..name.len()].copy_from_slice(name.as_bytes());
        raw[15] = suffix;
        let mut out = vec![32];
        for b in raw {
            out.push(b'A' + (b >> 4));
            out.push(b'A' + (b & 0xf));
        }
        out.push(0);
        out
    }

    fn nbns_registration(name: &str, suffix: u8, group: bool, ip: [u8; 4]) -> Vec<u8> {
        // id, flags (opcode 5, RD), qd=1, an=0, ns=0, ar=1
        let mut p = vec![0x12, 0x34, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 1];
        p.extend(encode_nb(name, suffix));
        p.extend_from_slice(&[0, 0x20, 0, 1]); // NB, IN
        p.extend_from_slice(&[0xc0, 0x0c, 0, 0x20, 0, 1, 0, 0, 0x93, 0xe0, 0, 6]);
        p.extend_from_slice(&[if group { 0x80 } else { 0 }, 0]);
        p.extend_from_slice(&ip);
        p
    }

    #[test]
    fn netbios_registro_de_equipo() {
        let p = nbns_registration("DESKTOP-AB12", 0x00, false, [192, 168, 1, 40]);
        let n = parse_nbns(&p).unwrap();
        assert_eq!(n.name, "DESKTOP-AB12");
        assert_eq!(n.address, Ipv4Addr::new(192, 168, 1, 40));
        // Los grupos (WORKGROUP) no son nombres de equipo.
        assert!(parse_nbns(&nbns_registration(
            "WORKGROUP",
            0x00,
            true,
            [192, 168, 1, 40]
        ))
        .is_none());
        // Una consulta no dice de quién es el nombre.
        let mut q = p.clone();
        q[2] = 0x01;
        q[3] = 0x10;
        assert!(parse_nbns(&q).is_none());
        for cut in 0..p.len() {
            let _ = parse_nbns(&p[..cut]);
        }
    }
}
