//! Traductor a lenguaje humano: la capa que convierte un [`EnrichedFlow`]
//! en algo que entiende cualquier persona, no solo un analista.
//!
//! Wireshark responde con campos (`40001 → 22 [SYN] Seq=0 Win=1024`); aquí
//! se responde con frases: quién, con quién, qué hizo y si es normal. Cada
//! flujo recibe un **semáforo** ([`Level`]), un titular, una explicación y,
//! por cada alerta, qué significa y **qué hacer**. Además, [`stories`]
//! agrupa las alertas en historias: un escaneo de 12 puertos es *una*
//! historia, no 12 líneas.
//!
//! Las frases existen en español (el de referencia) y en inglés: las
//! funciones `*_in` reciben el [`Lang`]; las de siempre son las españolas.
//!
//! Todo el texto es plano (nunca HTML): los nombres de dominio, rutas y
//! archivos vienen de la captura y los controla quien genera el tráfico,
//! así que la interfaz que lo muestre debe tratarlo como texto.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Serialize;
use socshark_core::{EnrichedFlow, L7Protocol, Severity, Transport};

use crate::hosts::HostDirectory;
use crate::is_failed_connect;
use crate::risk::{alert_detail_in, alert_name_in};
use crate::summarize::fmt_bytes;
use crate::{tr, Lang};

/// Semáforo de un flujo o una historia. Ordenable: `Ok < Raro < Peligro`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Tráfico normal.
    Ok,
    /// Algo inusual que conviene mirar.
    Raro,
    /// Señal clara de riesgo.
    Peligro,
}

impl Level {
    pub fn from_severity(s: Severity) -> Self {
        match s {
            Severity::Info => Level::Ok,
            Severity::Low | Severity::Medium => Level::Raro,
            Severity::High | Severity::Critical => Level::Peligro,
        }
    }
}

/// Una alerta contada para personas.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AlertExplanation {
    pub id: String,
    pub level: Level,
    pub title: String,
    /// Qué ha pasado y por qué importa.
    pub story: String,
    /// Qué hacer.
    pub action: String,
    pub mitre: Option<String>,
}

/// Un flujo contado para personas.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Explanation {
    pub level: Level,
    /// Lo primero que hay que leer: la alerta más grave o, sin alertas, el título.
    pub headline: String,
    /// Qué pasó, en una frase.
    pub title: String,
    /// Contexto: cómo funciona y si es normal.
    pub story: String,
    /// Alertas explicadas, de la más grave a la menos.
    pub alerts: Vec<AlertExplanation>,
}

/// Varias alertas relacionadas contadas como una sola historia.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Story {
    pub level: Level,
    pub alert_id: String,
    pub title: String,
    pub story: String,
    pub action: String,
    pub mitre: Option<String>,
    /// Índices, en el slice de entrada de [`stories`], de los flujos implicados.
    pub flows: Vec<usize>,
    /// Primer avistamiento (µs epoch) de cualquiera de sus flujos.
    pub first_seen_micros: u64,
}

// ------------------------------------------------------------ nombres

/// Servicios conocidos por puerto y transporte: (nombre corto, descripción
/// para personas). UDP tiene su propia tabla: el 8080/udp no es web.
pub fn service_by_port(port: u16, transport: Transport) -> Option<(&'static str, &'static str)> {
    service_by_port_in(port, transport, Lang::Es)
}

/// Como [`service_by_port`], en el idioma dado.
pub fn service_by_port_in(
    port: u16,
    transport: Transport,
    lang: Lang,
) -> Option<(&'static str, &'static str)> {
    let l = |es: &'static str, en: &'static str| lang.pick(es, en);
    if transport == Transport::Udp {
        return Some(match port {
            53 => ("DNS", "DNS"),
            67 | 68 => (
                "DHCP",
                l("reparto de direcciones (DHCP)", "address assignment (DHCP)"),
            ),
            123 => ("NTP", l("hora (NTP)", "time (NTP)")),
            137 | 138 => (
                "NetBIOS",
                l("red de Windows (NetBIOS)", "Windows networking (NetBIOS)"),
            ),
            161 | 162 => (
                "SNMP",
                l(
                    "gestión de equipos de red (SNMP)",
                    "network device management (SNMP)",
                ),
            ),
            443 => (
                "QUIC",
                l("web segura (QUIC/HTTP3)", "secure web (QUIC/HTTP3)"),
            ),
            500 | 4500 => ("IPsec", "VPN (IPsec)"),
            514 => (
                "Syslog",
                l("registro de eventos (syslog)", "event logging (syslog)"),
            ),
            1900 => (
                "SSDP",
                l(
                    "descubrimiento de dispositivos (SSDP)",
                    "device discovery (SSDP)",
                ),
            ),
            5353 => (
                "mDNS",
                l(
                    "anuncios de la red local (mDNS)",
                    "local network announcements (mDNS)",
                ),
            ),
            _ => return None,
        });
    }
    Some(match port {
        20 | 21 => (
            "FTP",
            l("transferencia de archivos (FTP)", "file transfer (FTP)"),
        ),
        22 => (
            "SSH",
            l("acceso remoto seguro (SSH)", "secure remote access (SSH)"),
        ),
        23 => (
            "Telnet",
            l(
                "acceso remoto sin cifrar (Telnet)",
                "unencrypted remote access (Telnet)",
            ),
        ),
        25 | 465 | 587 => ("SMTP", l("envío de correo (SMTP)", "sending email (SMTP)")),
        53 => ("DNS", "DNS"),
        67 | 68 => (
            "DHCP",
            l("reparto de direcciones (DHCP)", "address assignment (DHCP)"),
        ),
        80 | 8080 => ("HTTP", l("web sin cifrar (HTTP)", "unencrypted web (HTTP)")),
        110 | 995 => (
            "POP3",
            l("recogida de correo (POP3)", "fetching email (POP3)"),
        ),
        123 => ("NTP", l("hora (NTP)", "time (NTP)")),
        135 => (
            "RPC",
            l(
                "servicios internos de Windows (RPC)",
                "internal Windows services (RPC)",
            ),
        ),
        137..=139 => (
            "NetBIOS",
            l("red de Windows (NetBIOS)", "Windows networking (NetBIOS)"),
        ),
        143 | 993 => ("IMAP", l("correo (IMAP)", "email (IMAP)")),
        443 | 8443 => ("HTTPS", l("web segura (HTTPS)", "secure web (HTTPS)")),
        445 => (
            "SMB",
            l(
                "carpetas compartidas de Windows (SMB)",
                "Windows shared folders (SMB)",
            ),
        ),
        1433 => (
            "SQL Server",
            l("la base de datos SQL Server", "the SQL Server database"),
        ),
        3306 => ("MySQL", l("la base de datos MySQL", "the MySQL database")),
        3389 => ("RDP", l("escritorio remoto (RDP)", "remote desktop (RDP)")),
        5353 => (
            "mDNS",
            l(
                "anuncios de la red local (mDNS)",
                "local network announcements (mDNS)",
            ),
        ),
        5432 => (
            "PostgreSQL",
            l("la base de datos PostgreSQL", "the PostgreSQL database"),
        ),
        5900 => ("VNC", l("escritorio remoto (VNC)", "remote desktop (VNC)")),
        515 => (
            "LPD",
            l("el protocolo de impresión LPD", "the LPD printing protocol"),
        ),
        631 => (
            "IPP",
            l("el protocolo de impresión IPP", "the IPP printing protocol"),
        ),
        9100 => (
            l("impresión", "printing"),
            l(
                "el canal de impresión directa (JetDirect)",
                "the direct printing channel (JetDirect)",
            ),
        ),
        6379 => ("Redis", l("la base de datos Redis", "the Redis database")),
        27017 => (
            "MongoDB",
            l("la base de datos MongoDB", "the MongoDB database"),
        ),
        _ => return None,
    })
}

/// `22 (SSH)`, o el número solo si el puerto no es conocido.
pub fn port_label(port: u16, transport: Transport) -> String {
    port_label_in(port, transport, Lang::Es)
}

/// Como [`port_label`], en el idioma dado.
pub fn port_label_in(port: u16, transport: Transport, lang: Lang) -> String {
    match service_by_port_in(port, transport, lang) {
        Some((short, _)) => format!("{port} ({short})"),
        None => port.to_string(),
    }
}

/// Servicio del flujo en palabras: por protocolo detectado y, si no, por puerto.
pub fn service_name(flow: &EnrichedFlow) -> String {
    service_name_in(flow, Lang::Es)
}

/// Como [`service_name`], en el idioma dado.
pub fn service_name_in(flow: &EnrichedFlow, lang: Lang) -> String {
    let l = |es: &'static str, en: &'static str| lang.pick(es, en);
    let by_l7 = match flow.l7_protocol {
        L7Protocol::Dns => Some("DNS"),
        L7Protocol::Tls => Some(l(
            "conexión segura (TLS/HTTPS)",
            "secure connection (TLS/HTTPS)",
        )),
        L7Protocol::Http => Some(l("web sin cifrar (HTTP)", "unencrypted web (HTTP)")),
        L7Protocol::Ssh => Some(l(
            "acceso remoto seguro (SSH)",
            "secure remote access (SSH)",
        )),
        L7Protocol::Ntp => Some(l("hora (NTP)", "time (NTP)")),
        L7Protocol::Dhcp => Some(l(
            "reparto de direcciones (DHCP)",
            "address assignment (DHCP)",
        )),
        L7Protocol::Unknown => None,
    };
    if let Some(s) = by_l7 {
        return s.to_string();
    }
    match service_by_port_in(flow.dst_port, flow.transport, lang) {
        Some((_, long)) => long.to_string(),
        None => tr!(
            lang,
            "el puerto {}/{}",
            "port {}/{}",
            flow.dst_port,
            flow.transport.as_str().to_ascii_lowercase()
        ),
    }
}

/// Servicios públicos muy conocidos (resolutores DNS), sin artículo.
fn well_known(ip: IpAddr, lang: Lang) -> Option<&'static str> {
    let l = |es: &'static str, en: &'static str| lang.pick(es, en);
    Some(match ip.to_string().as_str() {
        "8.8.8.8" | "8.8.4.4" | "2001:4860:4860::8888" | "2001:4860:4860::8844" => {
            l("DNS de Google", "Google DNS")
        }
        "1.1.1.1" | "1.0.0.1" | "2606:4700:4700::1111" | "2606:4700:4700::1001" => {
            l("DNS de Cloudflare", "Cloudflare DNS")
        }
        "9.9.9.9" | "149.112.112.112" => l("DNS de Quad9", "Quad9 DNS"),
        "208.67.222.222" | "208.67.220.220" => l("DNS de OpenDNS", "OpenDNS DNS"),
        _ => return None,
    })
}

/// Nombre conocido de un servidor público sin artículo («DNS de Google»).
pub fn well_known_name(ip: IpAddr) -> Option<&'static str> {
    well_known(ip, Lang::Es)
}

/// Como [`well_known_name`], en el idioma dado («Google DNS»).
pub fn well_known_name_in(ip: IpAddr, lang: Lang) -> Option<&'static str> {
    well_known(ip, lang)
}

/// Una IP contada para personas: «el DNS de Google (8.8.8.8)», «el equipo
/// 192.168.1.30», «el servidor 93.184.216.34», «la red local (multicast)».
pub fn host_name(ip: IpAddr) -> String {
    host_name_in(ip, Lang::Es)
}

/// Como [`host_name`], en el idioma dado («the device 192.168.1.30»).
pub fn host_name_in(ip: IpAddr, lang: Lang) -> String {
    if let Some(name) = well_known(ip, lang) {
        return tr!(lang, "el {name} ({ip})", "the {name} ({ip})");
    }
    let (local, multicast, loopback, broadcast) = match ip {
        IpAddr::V4(v4) => (
            v4.is_private() || v4.is_link_local(),
            v4.is_multicast(),
            v4.is_loopback(),
            v4.is_broadcast(),
        ),
        // Únicas locales (fc00::/7) y enlace local (fe80::/10).
        IpAddr::V6(v6) => (
            (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
            v6.is_multicast(),
            v6.is_loopback(),
            false,
        ),
    };
    // x.x.x.255 en una red privada: la difusión de una red /24 (la de casa).
    let subnet_broadcast = matches!(ip, IpAddr::V4(v4) if v4.is_private() && v4.octets()[3] == 255);
    if ip.is_unspecified() {
        lang.pick(
            "un equipo que aún no tiene dirección",
            "a device that has no address yet",
        )
        .to_string()
    } else if loopback {
        tr!(lang, "este mismo equipo ({ip})", "this same device ({ip})")
    } else if broadcast || subnet_broadcast {
        lang.pick(
            "toda la red local (difusión)",
            "the whole local network (broadcast)",
        )
        .to_string()
    } else if multicast {
        tr!(
            lang,
            "la red local (multicast {ip})",
            "the local network (multicast {ip})"
        )
    } else if local {
        tr!(lang, "el equipo {ip}", "the device {ip}")
    } else {
        tr!(lang, "el servidor {ip}", "the server {ip}")
    }
}

/// Nombre amable de un programa: `chrome.exe` → «Chrome».
pub fn program_label(process: &str) -> String {
    program_label_in(process, Lang::Es)
}

/// Como [`program_label`], en el idioma dado.
pub fn program_label_in(process: &str, lang: Lang) -> String {
    let base = process.rsplit(['/', '\\']).next().unwrap_or(process);
    let stem = match base.len().checked_sub(4) {
        Some(cut) if base.is_char_boundary(cut) && base[cut..].eq_ignore_ascii_case(".exe") => {
            &base[..cut]
        }
        _ => base,
    };
    let known = match stem.to_ascii_lowercase().as_str() {
        "chrome" | "google chrome" => "Chrome",
        "msedge" => "Microsoft Edge",
        "firefox" => "Firefox",
        "safari" => "Safari",
        "opera" => "Opera",
        "brave" => "Brave",
        "spotify" => "Spotify",
        "discord" => "Discord",
        "steam" | "steamwebhelper" => "Steam",
        "teams" | "ms-teams" => "Microsoft Teams",
        "outlook" | "olk" => "Outlook",
        "onedrive" => "OneDrive",
        "dropbox" => "Dropbox",
        "zoom" => "Zoom",
        "whatsapp" => "WhatsApp",
        "telegram" => "Telegram",
        "code" => "Visual Studio Code",
        "svchost" => lang.pick(
            "un servicio de Windows (svchost)",
            "a Windows service (svchost)",
        ),
        "msmpeng" => lang.pick(
            "el antivirus de Windows (Defender)",
            "the Windows antivirus (Defender)",
        ),
        "systemd-resolved" => lang.pick(
            "el sistema (resolución de nombres)",
            "the system (name resolution)",
        ),
        "node" => "Node.js",
        "java" | "javaw" => "Java",
        s if s.starts_with("python") => "Python",
        _ => return stem.to_string(),
    };
    known.to_string()
}

/// «el programa X del equipo Y» / «the program X on the device Y».
fn program_on(process: &str, host: &str, lang: Lang) -> String {
    let p = program_label_in(process, lang);
    match lang {
        Lang::Es => format!("el programa {p} {}", de(host)),
        Lang::En => format!("the program {p} on {host}"),
    }
}

/// Quién empezó, con el programa si se sabe (solo en vivo y en este
/// ordenador): «el programa Chrome de este ordenador (192.168.1.23)».
fn client_name(flow: &EnrichedFlow, names: &HostDirectory, lang: Lang) -> String {
    // Aún sin dirección (DHCP): se le reconoce por la MAC si se puede.
    let host = match flow.src_mac.as_deref().and_then(|m| names.by_mac(m)) {
        Some(h) if flow.src_ip.is_unspecified() => h.noun_in(lang),
        _ => names.host_name_in(flow.src_ip, lang),
    };
    match &flow.process_name {
        Some(p) if is_this_computer(flow.src_ip, names) => program_on(p, &host, lang),
        _ => host,
    }
}

/// ¿Es esta máquina? (solo se sabe en vivo; el programa es de su lado).
fn is_this_computer(ip: IpAddr, names: &HostDirectory) -> bool {
    ip.is_loopback()
        || names
            .get(ip)
            .is_some_and(|h| h.role == Some(crate::hosts::Role::ThisComputer))
}

/// Destino contado por su nombre si se conoce (dominio o SNI), si no por IP.
fn server_name(flow: &EnrichedFlow, names: &HostDirectory, lang: Lang) -> String {
    // Conexión que llega a un programa de esta máquina desde fuera.
    if let Some(p) = &flow.process_name {
        if is_this_computer(flow.dst_ip, names) && !is_this_computer(flow.src_ip, names) {
            return program_on(p, &names.host_name_in(flow.dst_ip, lang), lang);
        }
    }
    // Un equipo de casa con nombre propio («la impresora «HP…»») gana a su
    // nombre técnico de mDNS (`HP-OfficeJet.local`).
    if let Some(h) = names.get(flow.dst_ip).filter(|h| h.is_identified()) {
        return h.noun_in(lang);
    }
    let named = flow.tls_sni.as_deref().or(flow.resolved_domain.as_deref());
    match named {
        Some(name) if flow.l7_protocol != L7Protocol::Dns => format!("{name} ({})", flow.dst_ip),
        _ => names.host_name_in(flow.dst_ip, lang),
    }
}

/// «de» + nombre, contraído si empieza por «el »: «del equipo X».
fn de(noun: &str) -> String {
    match noun.strip_prefix("el ") {
        Some(rest) => format!("del {rest}"),
        None => format!("de {noun}"),
    }
}

/// «a» + nombre, contraído si empieza por «el »: «al servidor X».
fn a(noun: &str) -> String {
    match noun.strip_prefix("el ") {
        Some(rest) => format!("al {rest}"),
        None => format!("a {noun}"),
    }
}

/// Primera letra en mayúscula (las frases empiezan por un nombre de host).
fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// Acorta nombres largos para una frase: `az3k9t2wq7xm…tun.evil.example`.
fn shorten(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max / 3).collect();
    let tail: String = s.chars().skip(n - (max - max / 3 - 1)).collect();
    format!("{head}…{tail}")
}

/// Un nombre que viene de la captura, entre comillas del idioma.
fn quoted(s: &str, lang: Lang) -> String {
    tr!(lang, "«{s}»", "“{s}”")
}

/// Periodo (s) y número de llamadas de un beacon. El detalle de la alerta
/// manda ("intervalo medio X s ... en N intervalos"): la variante entre
/// flujos no se refleja en `interval_stats`. Si no se puede leer, se usa la
/// estadística del propio flujo.
fn beacon_period(flow: &EnrichedFlow, alert: &socshark_core::Alert) -> (f64, u32) {
    let parsed = (|| {
        let rest = alert.detail.strip_prefix("intervalo medio ")?;
        let secs: f64 = rest.split('s').next()?.trim().parse().ok()?;
        let n: u32 = rest
            .split(" en ")
            .nth(1)?
            .split_whitespace()
            .next()?
            .parse()
            .ok()?;
        Some((secs, n + 1))
    })();
    parsed.unwrap_or_else(|| {
        flow.interval_stats
            .as_ref()
            .map(|s| (s.mean_micros as f64 / 1e6, s.intervals + 1))
            .unwrap_or((0.0, 0))
    })
}

/// Dominio "base" de un nombre (el registrable, eTLD+1 aproximado): lo que
/// se bloquea. `x.evil.co.uk` → `evil.co.uk`, nunca el sufijo `co.uk`.
fn base_domain(name: &str) -> String {
    crate::domain::registrable_domain(name).to_string()
}

fn volume(flow: &EnrichedFlow, lang: Lang) -> String {
    tr!(
        lang,
        "Envió {} y recibió {}.",
        "Sent {} and received {}.",
        fmt_bytes(flow.bytes),
        fmt_bytes(flow.bytes_rev)
    )
}

// ------------------------------------------------------------ flujos

/// Cómo terminó un intento de conexión que nunca se estableció.
fn failed_outcome(flow: &EnrichedFlow, lang: Lang) -> &'static str {
    let f = &flow.tcp_flags;
    if f.ack == 0 {
        lang.pick(
            "No hubo respuesta: no hay nada escuchando o un cortafuegos lo bloquea.",
            "No answer: nothing is listening or a firewall is blocking it.",
        )
    } else if f.syn >= 2 {
        lang.pick(
            "El servicio respondió, pero quien llamaba cortó antes de usarlo (típico de un escaneo).",
            "The service answered, but the caller hung up before using it (typical of a scan).",
        )
    } else {
        lang.pick(
            "El equipo lo rechazó: no hay ningún servicio en ese puerto.",
            "The device refused it: there is no service on that port.",
        )
    }
}

/// Título y explicación del flujo, sin contar sus alertas.
fn describe(flow: &EnrichedFlow, names: &HostDirectory, lang: Lang) -> (String, String) {
    let client = capitalize(&client_name(flow, names, lang));
    let server = server_name(flow, names, lang);
    let l = |es: &str, en: &str| lang.pick(es, en).to_string();

    if flow.l7_protocol == L7Protocol::Dhcp {
        return if flow.src_port == 67 {
            (
                match lang {
                    Lang::Es => format!("{client} dio dirección {}", a(&server)),
                    Lang::En => format!("{client} gave an address to {server}"),
                },
                l(
                    "El router reparte las direcciones de la red a los equipos que se conectan \
                     (DHCP). Normal.",
                    "The router hands out the network's addresses to the devices that connect \
                     (DHCP). Normal.",
                ),
            )
        } else {
            (
                tr!(
                    lang,
                    "{client} se conectó a la red y pidió una dirección",
                    "{client} joined the network and asked for an address"
                ),
                l(
                    "Al conectarse, cada equipo pide una dirección IP para poder hablar (DHCP) y, \
                     de paso, dice cómo se llama. Normal.",
                    "When it connects, every device asks for an IP address so it can talk (DHCP) \
                     and, along the way, says what it is called. Normal.",
                ),
            )
        };
    }

    if flow.is_background_noise {
        return match flow.l7_protocol {
            L7Protocol::Ntp => (
                tr!(
                    lang,
                    "{client} sincronizó la hora con {server}",
                    "{client} synced its clock with {server}"
                ),
                l(
                    "Tráfico automático de fondo: los equipos ajustan su reloj solos. Normal.",
                    "Automatic background traffic: devices set their clocks on their own. Normal.",
                ),
            ),
            _ if flow.dst_port == 5353 || flow.src_port == 5353 => (
                tr!(
                    lang,
                    "{client} se anunció en la red local",
                    "{client} announced itself on the local network"
                ),
                l(
                    "Los equipos presentan solos sus servicios (impresoras, móviles, televisores…). Normal.",
                    "Devices advertise their services on their own (printers, phones, TVs…). Normal.",
                ),
            ),
            _ if flow.dst_port == 137 || flow.src_port == 137 => (
                tr!(
                    lang,
                    "{client} dijo su nombre a la red (NetBIOS)",
                    "{client} told the network its name (NetBIOS)"
                ),
                l(
                    "Los equipos con Windows anuncian su nombre para compartir carpetas e impresoras. \
                     Normal en una red de casa u oficina.",
                    "Windows computers announce their name to share folders and printers. \
                     Normal on a home or office network.",
                ),
            ),
            _ if flow.dst_port == 1900 || flow.src_port == 1900 => (
                tr!(
                    lang,
                    "{client} buscó o anunció dispositivos (SSDP)",
                    "{client} looked for or announced devices (SSDP)"
                ),
                l(
                    "Así se encuentran solos los aparatos de casa: teles, routers, altavoces. Normal.",
                    "This is how home devices find each other on their own: TVs, routers, speakers. Normal.",
                ),
            ),
            _ => (
                tr!(
                    lang,
                    "{client} generó tráfico automático hacia {server}",
                    "{client} sent automatic traffic to {server}"
                ),
                l(
                    "Tráfico de mantenimiento que los equipos envían solos. Normal.",
                    "Maintenance traffic that devices send on their own. Normal.",
                ),
            ),
        };
    }

    match flow.l7_protocol {
        L7Protocol::Dns => describe_dns(flow, &client, names, lang),
        L7Protocol::Tls => (
            tr!(
                lang,
                "{client} abrió una conexión segura con {server}",
                "{client} opened a secure connection with {server}"
            ),
            tr!(
                lang,
                "La conexión va cifrada (HTTPS/TLS): se sabe con quién habla, pero no qué dice. {}",
                "The connection is encrypted (HTTPS/TLS): you can see who it talks to, but not what it says. {}",
                volume(flow, lang)
            ),
        ),
        L7Protocol::Http => {
            let mut story = tr!(
                lang,
                "Es web sin cifrar (HTTP): cualquiera en la red puede leer lo que se envía. {}",
                "This is unencrypted web (HTTP): anyone on the network can read what is sent. {}",
                volume(flow, lang)
            );
            for f in &flow.extracted_files {
                story.push_str(&tr!(
                    lang,
                    " Descargó {} ({}).",
                    " Downloaded {} ({}).",
                    quoted(&shorten(&f.name, 60), lang),
                    fmt_bytes(f.size)
                ));
            }
            let title = match lang {
                Lang::Es => format!("{client} navegó sin cifrar {}", a(&server)),
                Lang::En => format!("{client} browsed {server} without encryption"),
            };
            (title, story)
        }
        L7Protocol::Ssh => (
            tr!(
                lang,
                "{client} entró por acceso remoto seguro (SSH) en {server}",
                "{client} logged in with secure remote access (SSH) on {server}"
            ),
            tr!(
                lang,
                "SSH sirve para administrar equipos a distancia y va cifrado. Normal si lo usa alguien de IT. {}",
                "SSH is used to manage computers remotely and is encrypted. Normal if someone from IT uses it. {}",
                volume(flow, lang)
            ),
        ),
        L7Protocol::Dhcp => (
            tr!(
                lang,
                "{client} pidió una dirección a la red (DHCP)",
                "{client} asked the network for an address (DHCP)"
            ),
            l(
                "Así consigue un equipo su dirección IP al conectarse. Normal.",
                "This is how a device gets its IP address when it connects. Normal.",
            ),
        ),
        _ if is_failed_connect(flow) => (
            match lang {
                Lang::Es => format!(
                    "{client} intentó conectar con {} {}",
                    service_name_in(flow, lang),
                    de(&server)
                ),
                Lang::En => format!(
                    "{client} tried to connect to {} on {server}",
                    service_name_in(flow, lang)
                ),
            },
            failed_outcome(flow, lang).to_string(),
        ),
        _ => match flow.transport {
            Transport::Udp if flow.packets_rev == 0 => (
                match lang {
                    Lang::Es => format!(
                        "{client} envió datos {} por {}",
                        a(&server),
                        service_name_in(flow, lang)
                    ),
                    Lang::En => format!(
                        "{client} sent data to {server} over {}",
                        service_name_in(flow, lang)
                    ),
                },
                tr!(
                    lang,
                    "{} paquetes ({}) sin respuesta.",
                    "{} packets ({}) with no reply.",
                    flow.packets,
                    fmt_bytes(flow.bytes)
                ),
            ),
            Transport::Icmp => (
                match lang {
                    Lang::Es => {
                        format!("{client} envió mensajes de control (ICMP) {}", a(&server))
                    }
                    Lang::En => format!("{client} sent control messages (ICMP) to {server}"),
                },
                l(
                    "ICMP se usa para comprobar si un equipo responde (ping) y avisar de errores.",
                    "ICMP is used to check whether a device answers (ping) and to report errors.",
                ),
            ),
            _ => (
                tr!(
                    lang,
                    "{client} habló con {server} por {}",
                    "{client} talked to {server} over {}",
                    service_name_in(flow, lang)
                ),
                tr!(
                    lang,
                    "{} paquetes en total. {}",
                    "{} packets in total. {}",
                    flow.packets + flow.packets_rev,
                    volume(flow, lang)
                ),
            ),
        },
    }
}

fn describe_dns(
    flow: &EnrichedFlow,
    client: &str,
    names: &HostDirectory,
    lang: Lang,
) -> (String, String) {
    let server = names.host_name_in(flow.dst_ip, lang);
    let guide = lang.pick(
        "El DNS es la guía telefónica de Internet: traduce nombres en direcciones.",
        "DNS is the phone book of the Internet: it turns names into addresses.",
    );
    let Some(dns) = &flow.dns else {
        let title = match lang {
            Lang::Es => format!("{client} usó el DNS {}", de(&server)),
            Lang::En => format!("{client} used DNS on {server}"),
        };
        return (title, guide.into());
    };
    let qname = dns
        .queries
        .first()
        .map(|q| quoted(&shorten(&q.name, 48), lang))
        .unwrap_or_else(|| quoted(lang.pick("un nombre", "a name"), lang));
    let title = tr!(
        lang,
        "{client} preguntó por {qname}",
        "{client} asked for {qname}"
    );
    let addrs: Vec<String> = dns
        .answers
        .iter()
        .filter_map(|a| {
            a.address
                .map(|ip| ip.to_string())
                .or_else(|| a.target.clone())
        })
        .collect();
    let server = capitalize(&server);
    let story = if !dns.is_response {
        tr!(
            lang,
            "{server} no respondió. {guide}",
            "{server} did not answer. {guide}"
        )
    } else if dns.rcode == Some(3) {
        tr!(
            lang,
            "{server} respondió que ese nombre no existe. {guide}",
            "{server} answered that the name does not exist. {guide}"
        )
    } else if addrs.is_empty() {
        tr!(
            lang,
            "{server} respondió sin direcciones. {guide}",
            "{server} answered without addresses. {guide}"
        )
    } else {
        tr!(
            lang,
            "{server} respondió: {}. {guide} Normal.",
            "{server} answered: {}. {guide} Normal.",
            addrs.join(", ")
        )
    };
    (title, story)
}

/// Explica una alerta de un flujo (texto, impacto y qué hacer).
fn explain_alert(
    flow: &EnrichedFlow,
    alert: &socshark_core::Alert,
    names: &HostDirectory,
    lang: Lang,
) -> AlertExplanation {
    let src = names.host_name_in(flow.src_ip, lang);
    let dst = names.host_name_in(flow.dst_ip, lang);
    // R7 pone delante del detalle la IP listada: si es el origen (conexión
    // entrante desde el C2 o la salida Tor), las frases se dan la vuelta.
    let (listed, local) = match alert.detail.split_whitespace().next() {
        Some(ip)
            if ip.parse::<std::net::IpAddr>().ok() == Some(flow.src_ip)
                && flow.src_ip != flow.dst_ip =>
        {
            (src.clone(), dst.clone())
        }
        _ => (dst.clone(), src.clone()),
    };
    let (src_c, listed_c) = (capitalize(&src), capitalize(&listed));
    let detail = alert_detail_in(alert, lang);
    let l = |es: &str, en: &str| lang.pick(es, en).to_string();
    let (title, story, action): (String, String, String) = match alert.id.as_str() {
        "DNS-TUNNELING" => {
            let qname = flow
                .dns
                .as_ref()
                .and_then(|d| d.queries.first())
                .map(|q| q.name.clone())
                .unwrap_or_default();
            // Variante por volumen: el detalle empieza por el número de
            // subdominios únicos ("N subdominios únicos de ...").
            let volume = alert
                .detail
                .split_once(" subdominios únicos")
                .and_then(|(n, _)| n.parse::<u32>().ok());
            let (base, sample) = (base_domain(&qname), quoted(&shorten(&qname, 40), lang));
            let story = match volume {
                Some(n) => tr!(
                    lang,
                    "{src_c} preguntó por {n} nombres distintos de {base} en pocos minutos (por \
                     ejemplo {sample}). Un uso normal repite los mismos nombres; tantos distintos \
                     de un mismo dominio es la forma de sacar datos de la red trocito a trocito.",
                    "{src_c} asked for {n} different names under {base} within a few minutes (for \
                     example {sample}). Normal use repeats the same names; so many different ones \
                     from a single domain is a way to smuggle data out of the network bit by bit."
                ),
                None => tr!(
                    lang,
                    "{src_c} preguntó por un nombre de {} caracteres que parece aleatorio ({sample}). \
                     Los programas maliciosos esconden datos dentro de estos nombres para \
                     sacarlos de la red sin que se note.",
                    "{src_c} asked for a {}-character name that looks random ({sample}). \
                     Malicious programs hide data inside names like these to get it out of the \
                     network unnoticed.",
                    qname.chars().count()
                ),
            };
            (
                l(
                    "Posible fuga de datos escondida en DNS",
                    "Possible data leak hidden in DNS",
                ),
                story,
                match lang {
                    Lang::Es => format!(
                        "Averigua qué programa {} hace estas consultas y bloquea el dominio {base}.",
                        de(&src)
                    ),
                    Lang::En => format!(
                        "Find out which program on {src} makes these queries and block the domain {base}."
                    ),
                },
            )
        }
        "PORT-SCAN" => (
            l("Escaneo de puertos", "Port scan"),
            tr!(
                lang,
                "{detail}. Es lo que hace un programa de escaneo (como nmap) para buscar servicios abiertos.",
                "{detail}. That is what a scanning tool (such as nmap) does to look for open services."
            ),
            tr!(
                lang,
                "Si nadie de IT ha lanzado un escaneo autorizado, revisa {src}: puede estar comprometido.",
                "If nobody in IT has run an authorized scan, check {src}: it may be compromised."
            ),
        ),
        "NETWORK-SWEEP" => (
            l("Barrido de red", "Network sweep"),
            tr!(
                lang,
                "{detail}. Así buscan los atacantes y los gusanos equipos con un servicio concreto abierto.",
                "{detail}. This is how attackers and worms look for devices with a particular service open."
            ),
            tr!(
                lang,
                "Si no es un inventario autorizado, revisa {src}: puede estar comprometido.",
                "If this is not an authorized inventory, check {src}: it may be compromised."
            ),
        ),
        "REPEATED-ATTEMPTS" => (
            l(
                "Intentos de conexión repetidos",
                "Repeated connection attempts",
            ),
            tr!(
                lang,
                "{detail}. Puede ser un servicio caído, un programa mal configurado o alguien insistiendo.",
                "{detail}. It may be a service that is down, a misconfigured program or someone being persistent."
            ),
            match lang {
                Lang::Es => format!(
                    "Comprueba si {} {} debería estar funcionando y qué programa {} insiste.",
                    service_name_in(flow, lang),
                    de(&dst),
                    de(&src)
                ),
                Lang::En => format!(
                    "Check whether {} on {dst} should be working and which program on {src} keeps trying.",
                    service_name_in(flow, lang)
                ),
            },
        ),
        "INSECURE-PORT" => (
            l(
                "Acceso remoto sin cifrar (Telnet)",
                "Unencrypted remote access (Telnet)",
            ),
            tr!(
                lang,
                "{src_c} usó Telnet con {dst}. Telnet envía usuario, contraseña y comandos en texto \
                 claro: cualquiera en la red puede leerlos.",
                "{src_c} used Telnet with {dst}. Telnet sends the username, password and commands \
                 in plain text: anyone on the network can read them."
            ),
            l(
                "Sustituye Telnet por SSH y cambia las contraseñas que se hayan usado.",
                "Replace Telnet with SSH and change any passwords that were used.",
            ),
        ),
        "EXPOSED-DB" => (
            l(
                "Base de datos accesible desde la red",
                "Database reachable from the network",
            ),
            tr!(
                lang,
                "{src_c} se conectó directamente a {} en {dst}. Una base de datos abierta a la red es \
                 un objetivo muy buscado.",
                "{src_c} connected directly to {} on {dst}. A database open to the network is a \
                 much sought-after target.",
                service_name_in(flow, lang)
            ),
            l(
                "Limita con el cortafuegos quién puede conectarse y revisa sus contraseñas.",
                "Use the firewall to limit who can connect and review its passwords.",
            ),
        ),
        "NON-DNS-ON-53" => {
            // Quien escucha en el 53 es el servidor (la captura pudo empezar
            // con un paquete suyo).
            let (client, server) = if flow.dst_port == 53 {
                (src.clone(), dst.clone())
            } else {
                (dst.clone(), src.clone())
            };
            let client_c = capitalize(&client);
            (
                l(
                    "Otra cosa por el puerto del DNS",
                    "Something else on the DNS port",
                ),
                tr!(
                    lang,
                    "{client_c} habla con {server} por el puerto 53, el del DNS, pero lo que viaja no \
                     es DNS. Es un truco clásico para colarse por cortafuegos que dejan pasar el DNS: \
                     suele ser una shell remota, una VPN o un programa de control a distancia.",
                    "{client_c} talks to {server} on port 53, the DNS port, but what travels is not \
                     DNS. It is a classic trick to slip through firewalls that let DNS through: it \
                     is usually a remote shell, a VPN or a remote-control program."
                ),
                match lang {
                    Lang::Es => format!(
                        "Mira qué se dijeron (pestaña Contenido) y qué programa escucha en el puerto \
                         53 {}. Si no es un servidor DNS, trátalo como un equipo comprometido.",
                        de(&server)
                    ),
                    Lang::En => format!(
                        "Look at what they said (Content tab) and which program listens on port 53 \
                         on {server}. If it is not a DNS server, treat it as a compromised device."
                    ),
                },
            )
        }
        "BEACONING" => {
            let (secs, times) = beacon_period(flow, alert);
            // Variante con jitter: el ritmo varía al azar, pero alrededor de
            // un periodo fijo (así se disfrazan los implantes tipo Cobalt Strike).
            let ritmo = if alert.detail.contains("jitter ~") {
                lang.pick(
                    "con pequeñas variaciones al azar pero alrededor del mismo ritmo",
                    "with small random variations but around the same rhythm",
                )
            } else {
                lang.pick("siempre al mismo ritmo", "always at the same rhythm")
            };
            (
                l(
                    "Comunicación sospechosamente regular",
                    "Suspiciously regular communication",
                ),
                tr!(
                    lang,
                    "{src_c} contacta con {dst} cada {secs:.0} segundos, {ritmo} ({times} \
                     veces). Las personas no navegan así; los programas que «llaman a casa» \
                     (como el malware controlado a distancia) sí.",
                    "{src_c} contacts {dst} every {secs:.0} seconds, {ritmo} ({times} \
                     times). People don't browse like that; programs that “phone home” \
                     (such as remotely controlled malware) do."
                ),
                match lang {
                    Lang::Es => format!(
                        "Identifica qué programa {} abre esta conexión y si debería hacerlo.",
                        de(&src)
                    ),
                    Lang::En => format!(
                        "Identify which program on {src} opens this connection and whether it should."
                    ),
                },
            )
        }
        "FILE-MASQUERADING" => {
            let file = flow.extracted_files.iter().find(|f| f.masquerading_suspect);
            let name = quoted(
                &file.map(|f| shorten(&f.name, 60)).unwrap_or_default(),
                lang,
            );
            let magic = file.and_then(|f| f.magic.clone()).unwrap_or_default();
            let sha = file
                .and_then(|f| f.sha256.as_deref())
                .map(|h| {
                    tr!(
                        lang,
                        " Su huella SHA-256 es {h}.",
                        " Its SHA-256 fingerprint is {h}."
                    )
                })
                .unwrap_or_default();
            (
                l("Archivo disfrazado", "Disguised file"),
                tr!(
                    lang,
                    "{src_c} descargó {name}, que aparenta ser otra cosa pero en realidad es un \
                     programa ejecutable ({magic}). Es un truco habitual para colar malware.{sha}",
                    "{src_c} downloaded {name}, which looks like something else but is actually an \
                     executable program ({magic}). It is a common trick to sneak in malware.{sha}"
                ),
                l(
                    "No abras el archivo y analízalo con un antivirus o en VirusTotal (por su SHA-256).",
                    "Don't open the file; scan it with an antivirus or on VirusTotal (by its SHA-256).",
                ),
            )
        }
        "THREAT-INTEL-FEODO" => (
            l(
                "Conexión con un servidor de malware conocido",
                "Connection to a known malware server",
            ),
            tr!(
                lang,
                "{listed_c} aparece en la lista Feodo Tracker de servidores que controlan malware \
                 (Emotet, Dridex, TrickBot…), y {local} se comunicó con él.",
                "{listed_c} is on the Feodo Tracker list of servers that control malware \
                 (Emotet, Dridex, TrickBot…), and {local} communicated with it."
            ),
            tr!(
                lang,
                "Desconecta {local} de la red y revísalo con tu equipo de seguridad.",
                "Disconnect {local} from the network and have your security team check it."
            ),
        ),
        "TOR-USAGE" => (
            l("Uso de la red Tor", "Use of the Tor network"),
            tr!(
                lang,
                "{listed_c} es una salida de Tor, una red que oculta quién habla con quién. Puede ser \
                 privacidad legítima o una forma de esconder actividad.",
                "{listed_c} is a Tor exit, a network that hides who talks to whom. It may be \
                 legitimate privacy or a way to hide activity."
            ),
            l(
                "Comprueba si el uso de Tor está permitido en tu organización.",
                "Check whether Tor is allowed in your organization.",
            ),
        ),
        _ => (
            alert_name_in(alert, lang),
            detail,
            l(
                "Revisa esta conversación con más detalle.",
                "Review this conversation in more detail.",
            ),
        ),
    };
    AlertExplanation {
        id: alert.id.clone(),
        level: Level::from_severity(alert.severity),
        title,
        story,
        action,
        mitre: alert.mitre.clone(),
    }
}

/// Explica un flujo completo para personas.
pub fn explain(flow: &EnrichedFlow) -> Explanation {
    explain_with(flow, &HostDirectory::default())
}

/// Como [`explain`], llamando a cada equipo por su nombre si se conoce
/// («el equipo «iPhone-de-Ana» (192.168.1.30)», «el router (192.168.1.1)»).
pub fn explain_with(flow: &EnrichedFlow, names: &HostDirectory) -> Explanation {
    explain_in(flow, names, Lang::Es)
}

/// Como [`explain_with`], en el idioma dado.
pub fn explain_in(flow: &EnrichedFlow, names: &HostDirectory, lang: Lang) -> Explanation {
    let (title, story) = describe(flow, names, lang);
    let mut alerts: Vec<AlertExplanation> = flow
        .alerts
        .iter()
        .map(|a| explain_alert(flow, a, names, lang))
        .collect();
    // Estable: a igual nivel se conserva el orden del motor de reglas.
    alerts.sort_by_key(|a| std::cmp::Reverse(a.level));
    let level = alerts.first().map_or(Level::Ok, |a| a.level);
    let headline = alerts
        .first()
        .map(|a| format!("{}: {}", a.title, title_case_lower(&title)))
        .unwrap_or_else(|| title.clone());
    Explanation {
        level,
        headline,
        title,
        story,
        alerts,
    }
}

/// «El equipo X hizo Y» → «el equipo X hizo Y» para encadenar tras «Alerta: ».
fn title_case_lower(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_lowercase().chain(c).collect(),
        None => String::new(),
    }
}

// ------------------------------------------------------------ historias

/// Clave de agrupación: las alertas de un mismo patrón se cuentan juntas.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum GroupKey {
    /// Mismo escáner contra el mismo host.
    Scan(IpAddr, IpAddr),
    /// Mismo escáner contra el mismo puerto en muchos hosts.
    Sweep(IpAddr, u16),
    /// Mismo origen insistiendo al mismo servicio.
    Repeat(IpAddr, IpAddr, u16),
    /// El resto: una historia por alerta y flujo.
    Single(String, usize),
}

/// Agrupa las alertas de todos los flujos en historias, de la más grave a la
/// menos y, a igual gravedad, por orden de aparición.
pub fn stories(flows: &[EnrichedFlow]) -> Vec<Story> {
    stories_with(flows, &HostDirectory::default())
}

/// Como [`stories`], con los equipos por su nombre.
pub fn stories_with(flows: &[EnrichedFlow], names: &HostDirectory) -> Vec<Story> {
    stories_in(flows, names, Lang::Es)
}

/// Como [`stories_with`], en el idioma dado.
pub fn stories_in(flows: &[EnrichedFlow], names: &HostDirectory, lang: Lang) -> Vec<Story> {
    let mut groups: BTreeMap<GroupKey, Vec<(usize, &socshark_core::Alert)>> = BTreeMap::new();
    for (i, flow) in flows.iter().enumerate() {
        for alert in &flow.alerts {
            let key = match alert.id.as_str() {
                "PORT-SCAN" => GroupKey::Scan(flow.src_ip, flow.dst_ip),
                "NETWORK-SWEEP" => GroupKey::Sweep(flow.src_ip, flow.dst_port),
                "REPEATED-ATTEMPTS" => GroupKey::Repeat(flow.src_ip, flow.dst_ip, flow.dst_port),
                other => GroupKey::Single(other.to_string(), i),
            };
            groups.entry(key).or_default().push((i, alert));
        }
    }

    let mut out: Vec<Story> = groups
        .into_iter()
        .map(|(key, members)| {
            let idx: Vec<usize> = members.iter().map(|(i, _)| *i).collect();
            let (i0, a0) = members[0];
            let level = members
                .iter()
                .map(|(_, a)| Level::from_severity(a.severity))
                .max()
                .unwrap_or(Level::Ok);
            let first_seen_micros = idx
                .iter()
                .map(|&i| flows[i].first_seen_micros)
                .min()
                .unwrap_or(0);
            let single = explain_alert(&flows[i0], a0, names, lang);
            let (title, story, action) = match key {
                GroupKey::Scan(src, dst) => scan_story(flows, &idx, src, dst, names, lang),
                GroupKey::Sweep(src, port) => sweep_story(flows, &idx, src, port, names, lang),
                GroupKey::Repeat(src, dst, port) => {
                    let (src, dst) = (names.host_name_in(src, lang), names.host_name_in(dst, lang));
                    let port = port_label_in(port, Transport::Tcp, lang);
                    (
                        match lang {
                            Lang::Es => format!(
                                "{} insiste en conectar con {port} {}",
                                capitalize(&src),
                                de(&dst)
                            ),
                            Lang::En => format!(
                                "{} keeps trying to connect to {port} on {dst}",
                                capitalize(&src)
                            ),
                        },
                        tr!(
                            lang,
                            "{} intentos sin llegar a conectar. Puede ser un servicio caído, un \
                             programa mal configurado o alguien insistiendo.",
                            "{} attempts without ever connecting. It may be a service that is \
                             down, a misconfigured program or someone being persistent.",
                            idx.len()
                        ),
                        single.action,
                    )
                }
                GroupKey::Single(..) => (single.title, single.story, single.action),
            };
            Story {
                level,
                alert_id: a0.id.clone(),
                title,
                story,
                action,
                mitre: a0.mitre.clone(),
                flows: idx,
                first_seen_micros,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.level
            .cmp(&a.level)
            .then(a.first_seen_micros.cmp(&b.first_seen_micros))
    });
    out
}

fn scan_story(
    flows: &[EnrichedFlow],
    idx: &[usize],
    src: IpAddr,
    dst: IpAddr,
    names: &HostDirectory,
    lang: Lang,
) -> (String, String, String) {
    let mut open = Vec::new();
    let mut closed = Vec::new();
    let mut silent = 0usize;
    let mut ports: Vec<u16> = idx.iter().map(|&i| flows[i].dst_port).collect();
    ports.sort_unstable();
    ports.dedup();
    for &p in &ports {
        let f = idx
            .iter()
            .map(|&i| &flows[i])
            .find(|f| f.dst_port == p)
            .expect("puerto del grupo");
        if f.tcp_flags.ack == 0 {
            silent += 1;
        } else if f.tcp_flags.syn >= 2 {
            open.push(port_label_in(p, Transport::Tcp, lang));
        } else {
            closed.push(port_label_in(p, Transport::Tcp, lang));
        }
    }
    let (src, dst) = (names.host_name_in(src, lang), names.host_name_in(dst, lang));
    let mut story = match lang {
        Lang::Es => format!(
            "Probó {} puertos {} sin llegar a conectar.",
            ports.len(),
            de(&dst)
        ),
        Lang::En => format!(
            "Tried {} ports on {dst} without ever connecting.",
            ports.len()
        ),
    };
    if !open.is_empty() {
        story.push_str(&tr!(
            lang,
            " Respondieron (abiertos): {}.",
            " Answered (open): {}.",
            open.join(", ")
        ));
    }
    if !closed.is_empty() {
        story.push_str(&tr!(
            lang,
            " Rechazaron (cerrados): {}.",
            " Refused (closed): {}.",
            closed.join(", ")
        ));
    }
    if silent > 0 {
        story.push_str(&tr!(
            lang,
            " Sin respuesta: {silent}.",
            " No answer: {silent}."
        ));
    }
    story.push_str(lang.pick(
        " Es lo que hace un programa de escaneo (como nmap) para buscar servicios abiertos.",
        " That is what a scanning tool (such as nmap) does to look for open services.",
    ));
    (
        tr!(lang, "{} escaneó {dst}", "{} scanned {dst}", capitalize(&src)),
        story,
        tr!(
            lang,
            "Si nadie de IT ha lanzado un escaneo autorizado, revisa {src}: puede estar comprometido.",
            "If nobody in IT has run an authorized scan, check {src}: it may be compromised."
        ),
    )
}

fn sweep_story(
    flows: &[EnrichedFlow],
    idx: &[usize],
    src: IpAddr,
    port: u16,
    names: &HostDirectory,
    lang: Lang,
) -> (String, String, String) {
    let mut hosts: Vec<IpAddr> = idx.iter().map(|&i| flows[i].dst_ip).collect();
    hosts.sort_unstable();
    hosts.dedup();
    let sample: Vec<String> = hosts.iter().take(5).map(|h| h.to_string()).collect();
    let more = if hosts.len() > sample.len() {
        tr!(
            lang,
            " y {} más",
            " and {} more",
            hosts.len() - sample.len()
        )
    } else {
        String::new()
    };
    let src = names.host_name_in(src, lang);
    (
        tr!(
            lang,
            "{} barrió la red buscando {}",
            "{} swept the network looking for {}",
            capitalize(&src),
            port_label_in(port, Transport::Tcp, lang)
        ),
        tr!(
            lang,
            "Probó el mismo servicio en {} equipos ({}{more}) sin llegar a conectar. Así buscan \
             los atacantes y los gusanos equipos con un servicio concreto abierto.",
            "Tried the same service on {} devices ({}{more}) without ever connecting. This is \
             how attackers and worms look for devices with a particular service open.",
            hosts.len(),
            sample.join(", ")
        ),
        tr!(
            lang,
            "Si no es un inventario autorizado, revisa {src}: puede estar comprometido.",
            "If this is not an authorized inventory, check {src}: it may be compromised."
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::flujo_basico;
    use socshark_core::{Alert, DnsAnswerSummary, DnsQuerySummary, DnsSummary};

    /// La red de casa entera por el motor: flujos enriquecidos y su directorio.
    fn red_de_casa() -> (Vec<EnrichedFlow>, HostDirectory) {
        use socshark_core::config::PipelineConfig;
        use socshark_core::{LinkType, RawPacket};
        use socshark_dissectors::DissectorPipeline;
        use socshark_flow::FlowAggregator;

        let pipe = DissectorPipeline::new();
        let mut agg = FlowAggregator::new(10_000, 120, false);
        let mut book = crate::hosts::HostBook::new();
        for (ts, data) in socshark_testgen::home_pcap_packets() {
            let pkt = RawPacket {
                ts_micros: ts,
                orig_len: data.len() as u32,
                data,
            };
            if let Some(dp) = pipe.dissect(&pkt, LinkType::Ethernet) {
                agg.on_packet(pkt.ts_micros, pkt.data.len(), &dp);
                book.observe(&dp);
            }
        }
        let mut flows = agg.finish();
        crate::enrich_all(
            &mut crate::SocContext::default(),
            &mut flows,
            &PipelineConfig::default(),
        );
        (flows, book.directory())
    }

    #[test]
    fn frases_con_los_nombres_de_cada_equipo() {
        let (flows, names) = red_de_casa();
        let all: Vec<String> = flows
            .iter()
            .map(|f| explain_with(f, &names).headline)
            .collect();
        let has = |needle: &str| all.iter().any(|h| h.contains(needle));
        assert!(has("El equipo «iPhone-de-Ana» (192.168.1.30)"), "{all:#?}");
        assert!(
            has("La impresora «HP OfficeJet Pro 8020» (192.168.1.40) se anunció"),
            "{all:#?}"
        );
        // A la impresora se la llama por su nombre, no por `HP-OfficeJet.local`.
        assert!(
            has(
                "con la impresora «HP OfficeJet Pro 8020» (192.168.1.40) por el canal de impresión"
            ),
            "{all:#?}"
        );
        // DHCP y NetBIOS contados como lo que son; el móvil, reconocido por su MAC.
        assert!(
            has("El equipo «iPhone-de-Ana» (192.168.1.30) se conectó a la red y pidió una dirección"),
            "{all:#?}"
        );
        assert!(
            has("El router (192.168.1.1) dio dirección al equipo «iPhone-de-Ana»"),
            "{all:#?}"
        );
        assert!(
            has("El equipo «DESKTOP-AB12» (192.168.1.50) dijo su nombre a la red (NetBIOS)"),
            "{all:#?}"
        );
        assert!(
            !all.iter().any(|h| h.contains("tráfico automático")
                || h.contains("0.0.0.0")
                || h.contains("192.168.1.255")),
            "{all:#?}"
        );
        // El Telnet al router: la alerta lo nombra como «el router».
        let telnet = flows.iter().find(|f| f.dst_port == 23).unwrap();
        let e = explain_with(telnet, &names);
        assert!(
            e.title.contains("el router (192.168.1.1)")
                || e.title.contains("al router (192.168.1.1)"),
            "{e:#?}"
        );
        assert!(e.title.contains("«DESKTOP-AB12»"), "{e:#?}");
        // Sin directorio, las frases de siempre.
        assert!(explain(telnet).title.starts_with("El equipo 192.168.1.50"));
    }

    #[test]
    fn el_programa_si_se_conoce() {
        assert_eq!(
            program_label(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            "Chrome"
        );
        assert_eq!(program_label("/usr/lib/firefox/firefox"), "Firefox");
        assert_eq!(program_label("mi-programa"), "mi-programa");
        assert_eq!(program_label("python3.13"), "Python");
        let (mut flows, names) = red_de_casa();
        let f = flows
            .iter_mut()
            .find(|f| f.dst_port == 443 && f.src_port == 50124)
            .unwrap();
        f.process_name = Some("OUTLOOK.EXE".into());
        // Solo se atribuye a quien empezó si es esta máquina (en vivo).
        assert!(explain_with(f, &names)
            .title
            .starts_with("El equipo «DESKTOP-AB12»"));
        let mut names = names;
        names.mark_this_computer(&["192.168.1.50".parse().unwrap()]);
        let e = explain_with(f, &names);
        assert!(
            e.title
                .starts_with("El programa Outlook de este ordenador (192.168.1.50)"),
            "{}",
            e.title
        );
    }

    fn alerta(id: &str, sev: Severity, detail: &str) -> Alert {
        Alert {
            id: id.into(),
            name: id.into(),
            severity: sev,
            detail: detail.into(),
            mitre: Some("T0000".into()),
        }
    }

    #[test]
    fn nombres_de_hosts_y_servicios() {
        assert_eq!(
            host_name("8.8.8.8".parse().unwrap()),
            "el DNS de Google (8.8.8.8)"
        );
        assert_eq!(
            host_name("192.168.1.30".parse().unwrap()),
            "el equipo 192.168.1.30"
        );
        assert_eq!(host_name("fd00::10".parse().unwrap()), "el equipo fd00::10");
        assert_eq!(
            host_name("93.184.216.34".parse().unwrap()),
            "el servidor 93.184.216.34"
        );
        assert_eq!(
            host_name("224.0.0.251".parse().unwrap()),
            "la red local (multicast 224.0.0.251)"
        );
        assert_eq!(port_label(445, Transport::Tcp), "445 (SMB)");
        assert_eq!(port_label(40001, Transport::Tcp), "40001");
        assert_eq!(port_label(443, Transport::Udp), "443 (QUIC)");
        // El 8080/udp no es web: sin nombre en lugar de uno equivocado.
        let f = flujo_basico(17, 53100, 8080);
        assert_eq!(service_name(&f), "el puerto 8080/udp");
        assert_eq!(de("el equipo X"), "del equipo X");
        assert_eq!(a("el servidor Y"), "al servidor Y");
        assert_eq!(a("example.com (1.2.3.4)"), "a example.com (1.2.3.4)");
        let f = flujo_basico(6, 40000, 3389);
        assert_eq!(service_name(&f), "escritorio remoto (RDP)");
        let f = flujo_basico(17, 40000, 9999);
        assert_eq!(service_name(&f), "el puerto 9999/udp");
    }

    #[test]
    fn dns_normal_se_cuenta_como_pregunta_y_respuesta() {
        let mut f = flujo_basico(17, 53001, 53);
        f.src_ip = "192.168.1.10".parse().unwrap();
        f.dst_ip = "8.8.8.8".parse().unwrap();
        f.l7_protocol = L7Protocol::Dns;
        f.dns = Some(DnsSummary {
            is_response: true,
            rcode: Some(0),
            queries: vec![DnsQuerySummary {
                name: "example.com".into(),
                qtype: 1,
            }],
            answers: vec![DnsAnswerSummary {
                name: "example.com".into(),
                rtype: 1,
                ttl: 300,
                address: Some("93.184.216.34".parse().unwrap()),
                target: None,
            }],
        });
        let e = explain(&f);
        assert_eq!(e.level, Level::Ok);
        assert_eq!(e.title, "El equipo 192.168.1.10 preguntó por «example.com»");
        assert!(e
            .story
            .starts_with("El DNS de Google (8.8.8.8) respondió: 93.184.216.34."));
        assert_eq!(e.headline, e.title);
    }

    #[test]
    fn sonda_sin_respuesta_explica_el_desenlace() {
        let mut f = flujo_basico(6, 40001, 23);
        f.tcp_flags.syn = 1;
        let e = explain(&f);
        assert_eq!(
            e.title,
            "El equipo 10.0.0.5 intentó conectar con acceso remoto sin cifrar (Telnet) del equipo 10.0.0.99"
        );
        assert!(e.story.starts_with("No hubo respuesta"));

        f.tcp_flags.ack = 1;
        f.tcp_flags.rst = 1;
        assert!(explain(&f).story.starts_with("El equipo lo rechazó"));
        f.tcp_flags.syn = 2;
        assert!(explain(&f).story.starts_with("El servicio respondió"));
    }

    #[test]
    fn alerta_grave_manda_en_el_semaforo_y_el_titular() {
        let mut f = flujo_basico(17, 53002, 53);
        f.l7_protocol = L7Protocol::Dns;
        f.dns = Some(DnsSummary {
            is_response: false,
            rcode: None,
            queries: vec![DnsQuerySummary {
                name: "az3k9t2wq7xm5vb8n4rj6yp1chfdgsaz3k9t2wq7xm5vb8n4rj6.tun.evil.example".into(),
                qtype: 16,
            }],
            answers: vec![],
        });
        f.alerts = vec![
            alerta("TOR-USAGE", Severity::Medium, ""),
            alerta("DNS-TUNNELING", Severity::High, ""),
        ];
        let e = explain(&f);
        assert_eq!(e.level, Level::Peligro);
        assert_eq!(e.alerts[0].id, "DNS-TUNNELING", "la más grave primero");
        assert!(e
            .headline
            .starts_with("Posible fuga de datos escondida en DNS: el equipo 10.0.0.5 preguntó"));
        assert!(e.alerts[0]
            .action
            .contains("bloquea el dominio evil.example"));
        assert!(e.alerts[0].story.contains("68 caracteres"));
    }

    #[test]
    fn beacon_entre_flujos_toma_el_periodo_del_detalle() {
        let f = flujo_basico(6, 40000, 443);
        let a = alerta(
            "BEACONING",
            Severity::Medium,
            "intervalo medio 300.0s con jitter ±0.5% en 7 intervalos entre conexiones",
        );
        assert_eq!(beacon_period(&f, &a), (300.0, 8));
        let e = explain_alert(&f, &a, &HostDirectory::default(), Lang::Es);
        assert!(e.story.contains("cada 300 segundos"), "{}", e.story);
    }

    #[test]
    fn feodo_entrante_nombra_al_origen_como_listado() {
        let mut f = flujo_basico(6, 4444, 22);
        f.src_ip = "203.0.113.66".parse().unwrap();
        let a = alerta(
            "THREAT-INTEL-FEODO",
            Severity::High,
            "203.0.113.66 aparece en la lista Feodo cargada (--intel-feodo)",
        );
        let e = explain_alert(&f, &a, &HostDirectory::default(), Lang::Es);
        assert!(
            e.story.starts_with("El servidor 203.0.113.66 aparece"),
            "{}",
            e.story
        );
        assert!(e.action.contains("10.0.0.99"), "{}", e.action);
    }

    #[test]
    fn dominio_a_bloquear_respeta_sufijos_de_dos_niveles() {
        // Regresión: recomendaba bloquear "co.uk" entero.
        assert_eq!(base_domain("x.evil.co.uk"), "evil.co.uk");
        assert_eq!(base_domain("a.b.evil.com.br"), "evil.com.br");
        assert_eq!(base_domain("a.tun.evil.example"), "evil.example");
        assert_eq!(base_domain("evil.com"), "evil.com");
    }

    #[test]
    fn todas_las_alertas_del_motor_tienen_explicacion_propia() {
        for id in [
            "DNS-TUNNELING",
            "PORT-SCAN",
            "NETWORK-SWEEP",
            "REPEATED-ATTEMPTS",
            "INSECURE-PORT",
            "EXPOSED-DB",
            "NON-DNS-ON-53",
            "BEACONING",
            "FILE-MASQUERADING",
            "THREAT-INTEL-FEODO",
            "TOR-USAGE",
        ] {
            let f = flujo_basico(6, 40000, 22);
            let a = explain_alert(
                &f,
                &alerta(id, Severity::Medium, "detalle"),
                &HostDirectory::default(),
                Lang::Es,
            );
            assert_ne!(a.title, id, "{id} cae en la explicación genérica");
            assert!(!a.action.is_empty());
        }
    }

    #[test]
    fn un_escaneo_es_una_sola_historia_con_desenlaces() {
        let mk = |port: u16, syn: u32, ack: u32, rst: u32| {
            let mut f = flujo_basico(6, 40001, port);
            f.src_ip = "192.168.1.30".parse().unwrap();
            f.dst_ip = "192.168.1.1".parse().unwrap();
            f.tcp_flags.syn = syn;
            f.tcp_flags.ack = ack;
            f.tcp_flags.rst = rst;
            f.alerts = vec![alerta("PORT-SCAN", Severity::Medium, "x")];
            f
        };
        let mut flows = vec![mk(22, 2, 1, 1), mk(21, 1, 1, 1), mk(23, 1, 0, 0)];
        // Una alerta suelta de otro tipo en otro flujo: historia aparte.
        let mut tunel = flujo_basico(17, 53002, 53);
        tunel.alerts = vec![alerta("DNS-TUNNELING", Severity::High, "")];
        flows.push(tunel);

        let s = stories(&flows);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].alert_id, "DNS-TUNNELING", "peligro antes que raro");
        let scan = &s[1];
        assert_eq!(scan.flows, vec![0, 1, 2]);
        assert_eq!(
            scan.title,
            "El equipo 192.168.1.30 escaneó el equipo 192.168.1.1"
        );
        assert!(scan.story.contains("Probó 3 puertos"));
        assert!(scan.story.contains("Respondieron (abiertos): 22 (SSH)."));
        assert!(scan.story.contains("Rechazaron (cerrados): 21 (FTP)."));
        assert!(scan.story.contains("Sin respuesta: 1."));
    }

    /// Palabras que delatan un texto sin traducir.
    fn suena_a_espanol(s: &str) -> Option<&'static str> {
        [
            " el ",
            " la ",
            " del ",
            " de ",
            " que ",
            " con ",
            " por ",
            " sin ",
            "«",
            "»",
            "equipo",
            "conexión",
            "puerto",
            "preguntó",
            "respondió",
        ]
        .into_iter()
        .find(|w| s.contains(w))
    }

    #[test]
    fn frases_en_ingles_para_la_red_de_casa() {
        let (flows, names) = red_de_casa();
        let mut texts = Vec::new();
        for f in &flows {
            let e = explain_in(f, &names, Lang::En);
            texts.extend([e.headline, e.title, e.story]);
            for a in e.alerts {
                texts.extend([a.title, a.story, a.action]);
            }
        }
        for st in stories_in(&flows, &names, Lang::En) {
            texts.extend([st.title, st.story, st.action]);
        }
        for t in &texts {
            assert!(
                suena_a_espanol(t).is_none(),
                "{t:?}: {:?}",
                suena_a_espanol(t)
            );
        }
        let has = |needle: &str| texts.iter().any(|t| t.contains(needle));
        assert!(
            has("The device “iPhone-de-Ana” (192.168.1.30)"),
            "{texts:#?}"
        );
        assert!(
            has("The router (192.168.1.1) gave an address to"),
            "{texts:#?}"
        );
        assert!(has("Unencrypted remote access (Telnet)"), "{texts:#?}");
        // El español sigue siendo el de siempre.
        let telnet = flows.iter().find(|f| f.dst_port == 23).unwrap();
        assert_eq!(
            explain_in(telnet, &names, Lang::Es),
            explain_with(telnet, &names)
        );
    }

    #[test]
    fn alertas_y_escaneo_en_ingles() {
        for id in [
            "DNS-TUNNELING",
            "PORT-SCAN",
            "NETWORK-SWEEP",
            "REPEATED-ATTEMPTS",
            "INSECURE-PORT",
            "EXPOSED-DB",
            "NON-DNS-ON-53",
            "BEACONING",
            "FILE-MASQUERADING",
            "THREAT-INTEL-FEODO",
            "TOR-USAGE",
        ] {
            let f = flujo_basico(6, 40000, 22);
            let a = explain_alert(
                &f,
                &alerta(id, Severity::Medium, "detalle"),
                &HostDirectory::default(),
                Lang::En,
            );
            for t in [&a.title, &a.action] {
                assert!(suena_a_espanol(t).is_none(), "{id}: {t}");
            }
        }
        let mut f = flujo_basico(6, 40001, 22);
        f.src_ip = "192.168.1.30".parse().unwrap();
        f.dst_ip = "192.168.1.1".parse().unwrap();
        f.tcp_flags.syn = 2;
        f.tcp_flags.ack = 1;
        f.alerts = vec![alerta(
            "PORT-SCAN",
            Severity::Medium,
            "192.168.1.30 probó 1 puertos distintos de 192.168.1.1 sin establecer conexión",
        )];
        let s = stories_in(&[f.clone()], &HostDirectory::default(), Lang::En);
        assert_eq!(
            s[0].title,
            "The device 192.168.1.30 scanned the device 192.168.1.1"
        );
        assert!(
            s[0].story
                .starts_with("Tried 1 ports on the device 192.168.1.1"),
            "{}",
            s[0].story
        );
        assert!(s[0].story.contains("Answered (open): 22 (SSH)."));
        let e = explain_in(&f, &HostDirectory::default(), Lang::En);
        assert!(
            e.alerts[0]
                .story
                .starts_with("192.168.1.30 probed 1 different ports"),
            "{e:#?}"
        );
        assert_eq!(
            host_name_in("8.8.8.8".parse().unwrap(), Lang::En),
            "the Google DNS (8.8.8.8)"
        );
        assert_eq!(
            service_name_in(&flujo_basico(17, 1, 8080), Lang::En),
            "port 8080/udp"
        );
        assert_eq!(
            program_label_in("svchost.exe", Lang::En),
            "a Windows service (svchost)"
        );
    }
}
