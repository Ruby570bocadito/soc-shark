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
//! Todo el texto es plano (nunca HTML): los nombres de dominio, rutas y
//! archivos vienen de la captura y los controla quien genera el tráfico,
//! así que la interfaz que lo muestre debe tratarlo como texto.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Serialize;
use socshark_core::{EnrichedFlow, L7Protocol, Severity, Transport};

use crate::is_failed_connect;
use crate::summarize::fmt_bytes;

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
fn service_by_port(port: u16, transport: Transport) -> Option<(&'static str, &'static str)> {
    if transport == Transport::Udp {
        return Some(match port {
            53 => ("DNS", "DNS"),
            67 | 68 => ("DHCP", "reparto de direcciones (DHCP)"),
            123 => ("NTP", "hora (NTP)"),
            137 | 138 => ("NetBIOS", "red de Windows (NetBIOS)"),
            161 | 162 => ("SNMP", "gestión de equipos de red (SNMP)"),
            443 => ("QUIC", "web segura (QUIC/HTTP3)"),
            500 | 4500 => ("IPsec", "VPN (IPsec)"),
            514 => ("Syslog", "registro de eventos (syslog)"),
            1900 => ("SSDP", "descubrimiento de dispositivos (SSDP)"),
            5353 => ("mDNS", "anuncios de la red local (mDNS)"),
            _ => return None,
        });
    }
    Some(match port {
        20 | 21 => ("FTP", "transferencia de archivos (FTP)"),
        22 => ("SSH", "acceso remoto seguro (SSH)"),
        23 => ("Telnet", "acceso remoto sin cifrar (Telnet)"),
        25 | 465 | 587 => ("SMTP", "envío de correo (SMTP)"),
        53 => ("DNS", "DNS"),
        67 | 68 => ("DHCP", "reparto de direcciones (DHCP)"),
        80 | 8080 => ("HTTP", "web sin cifrar (HTTP)"),
        110 | 995 => ("POP3", "recogida de correo (POP3)"),
        123 => ("NTP", "hora (NTP)"),
        135 => ("RPC", "servicios internos de Windows (RPC)"),
        137..=139 => ("NetBIOS", "red de Windows (NetBIOS)"),
        143 | 993 => ("IMAP", "correo (IMAP)"),
        443 | 8443 => ("HTTPS", "web segura (HTTPS)"),
        445 => ("SMB", "carpetas compartidas de Windows (SMB)"),
        1433 => ("SQL Server", "la base de datos SQL Server"),
        3306 => ("MySQL", "la base de datos MySQL"),
        3389 => ("RDP", "escritorio remoto (RDP)"),
        5353 => ("mDNS", "anuncios de la red local (mDNS)"),
        5432 => ("PostgreSQL", "la base de datos PostgreSQL"),
        5900 => ("VNC", "escritorio remoto (VNC)"),
        6379 => ("Redis", "la base de datos Redis"),
        27017 => ("MongoDB", "la base de datos MongoDB"),
        _ => return None,
    })
}

/// `22 (SSH)`, o el número solo si el puerto no es conocido.
pub fn port_label(port: u16, transport: Transport) -> String {
    match service_by_port(port, transport) {
        Some((short, _)) => format!("{port} ({short})"),
        None => port.to_string(),
    }
}

/// Servicio del flujo en palabras: por protocolo detectado y, si no, por puerto.
pub fn service_name(flow: &EnrichedFlow) -> String {
    let by_l7 = match flow.l7_protocol {
        L7Protocol::Dns => Some("DNS"),
        L7Protocol::Tls => Some("conexión segura (TLS/HTTPS)"),
        L7Protocol::Http => Some("web sin cifrar (HTTP)"),
        L7Protocol::Ssh => Some("acceso remoto seguro (SSH)"),
        L7Protocol::Ntp => Some("hora (NTP)"),
        L7Protocol::Dhcp => Some("reparto de direcciones (DHCP)"),
        L7Protocol::Unknown => None,
    };
    if let Some(s) = by_l7 {
        return s.to_string();
    }
    match service_by_port(flow.dst_port, flow.transport) {
        Some((_, long)) => long.to_string(),
        None => format!(
            "el puerto {}/{}",
            flow.dst_port,
            flow.transport.as_str().to_ascii_lowercase()
        ),
    }
}

/// Servicios públicos muy conocidos (resolutores DNS).
fn well_known_host(ip: IpAddr) -> Option<&'static str> {
    Some(match ip.to_string().as_str() {
        "8.8.8.8" | "8.8.4.4" | "2001:4860:4860::8888" | "2001:4860:4860::8844" => {
            "el DNS de Google"
        }
        "1.1.1.1" | "1.0.0.1" | "2606:4700:4700::1111" | "2606:4700:4700::1001" => {
            "el DNS de Cloudflare"
        }
        "9.9.9.9" | "149.112.112.112" => "el DNS de Quad9",
        "208.67.222.222" | "208.67.220.220" => "el DNS de OpenDNS",
        _ => return None,
    })
}

/// Una IP contada para personas: «el DNS de Google (8.8.8.8)», «el equipo
/// 192.168.1.30», «el servidor 93.184.216.34», «la red local (multicast)».
pub fn host_name(ip: IpAddr) -> String {
    if let Some(name) = well_known_host(ip) {
        return format!("{name} ({ip})");
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
    if loopback {
        format!("este mismo equipo ({ip})")
    } else if broadcast {
        "toda la red local (difusión)".to_string()
    } else if multicast {
        format!("la red local (multicast {ip})")
    } else if local {
        format!("el equipo {ip}")
    } else {
        format!("el servidor {ip}")
    }
}

/// Destino contado por su nombre si se conoce (dominio o SNI), si no por IP.
fn server_name(flow: &EnrichedFlow) -> String {
    let named = flow.tls_sni.as_deref().or(flow.resolved_domain.as_deref());
    match named {
        Some(name) if flow.l7_protocol != L7Protocol::Dns => format!("{name} ({})", flow.dst_ip),
        _ => host_name(flow.dst_ip),
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

/// Dominio "base" de un nombre (las dos últimas etiquetas): lo que se bloquea.
fn base_domain(name: &str) -> String {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    if labels.len() <= 2 {
        name.to_string()
    } else {
        labels[labels.len() - 2..].join(".")
    }
}

fn volume(flow: &EnrichedFlow) -> String {
    format!(
        "Envió {} y recibió {}.",
        fmt_bytes(flow.bytes),
        fmt_bytes(flow.bytes_rev)
    )
}

// ------------------------------------------------------------ flujos

/// Cómo terminó un intento de conexión que nunca se estableció.
fn failed_outcome(flow: &EnrichedFlow) -> &'static str {
    let f = &flow.tcp_flags;
    if f.ack == 0 {
        "No hubo respuesta: no hay nada escuchando o un cortafuegos lo bloquea."
    } else if f.syn >= 2 {
        "El servicio respondió, pero quien llamaba cortó antes de usarlo (típico de un escaneo)."
    } else {
        "El equipo lo rechazó: no hay ningún servicio en ese puerto."
    }
}

/// Título y explicación del flujo, sin contar sus alertas.
fn describe(flow: &EnrichedFlow) -> (String, String) {
    let client = capitalize(&host_name(flow.src_ip));
    let server = server_name(flow);

    if flow.is_background_noise {
        return match flow.l7_protocol {
            L7Protocol::Ntp => (
                format!("{client} sincronizó la hora con {server}"),
                "Tráfico automático de fondo: los equipos ajustan su reloj solos. Normal."
                    .to_string(),
            ),
            _ if flow.dst_port == 5353 || flow.src_port == 5353 => (
                format!("{client} se anunció en la red local"),
                "Los equipos presentan solos sus servicios (impresoras, móviles, televisores…). Normal."
                    .to_string(),
            ),
            _ => (
                format!("{client} generó tráfico automático hacia {server}"),
                "Tráfico de mantenimiento que los equipos envían solos. Normal.".to_string(),
            ),
        };
    }

    match flow.l7_protocol {
        L7Protocol::Dns => describe_dns(flow, &client),
        L7Protocol::Tls => (
            format!("{client} abrió una conexión segura con {server}"),
            format!(
                "La conexión va cifrada (HTTPS/TLS): se sabe con quién habla, pero no qué dice. {}",
                volume(flow)
            ),
        ),
        L7Protocol::Http => {
            let mut story = format!(
                "Es web sin cifrar (HTTP): cualquiera en la red puede leer lo que se envía. {}",
                volume(flow)
            );
            for f in &flow.extracted_files {
                story.push_str(&format!(
                    " Descargó «{}» ({}).",
                    shorten(&f.name, 60),
                    fmt_bytes(f.size)
                ));
            }
            (format!("{client} navegó sin cifrar {}", a(&server)), story)
        }
        L7Protocol::Ssh => (
            format!("{client} entró por acceso remoto seguro (SSH) en {server}"),
            format!(
                "SSH sirve para administrar equipos a distancia y va cifrado. Normal si lo usa alguien de IT. {}",
                volume(flow)
            ),
        ),
        L7Protocol::Dhcp => (
            format!("{client} pidió una dirección a la red (DHCP)"),
            "Así consigue un equipo su dirección IP al conectarse. Normal.".to_string(),
        ),
        _ if is_failed_connect(flow) => (
            format!(
                "{client} intentó conectar con {} {}",
                service_name(flow),
                de(&server)
            ),
            failed_outcome(flow).to_string(),
        ),
        _ => match flow.transport {
            Transport::Udp if flow.packets_rev == 0 => (
                format!(
                    "{client} envió datos {} por {}",
                    a(&server),
                    service_name(flow)
                ),
                format!(
                    "{} paquetes ({}) sin respuesta.",
                    flow.packets,
                    fmt_bytes(flow.bytes)
                ),
            ),
            Transport::Icmp => (
                format!("{client} envió mensajes de control (ICMP) {}", a(&server)),
                "ICMP se usa para comprobar si un equipo responde (ping) y avisar de errores."
                    .to_string(),
            ),
            _ => (
                format!("{client} habló con {server} por {}", service_name(flow)),
                format!(
                    "{} paquetes en total. {}",
                    flow.packets + flow.packets_rev,
                    volume(flow)
                ),
            ),
        },
    }
}

fn describe_dns(flow: &EnrichedFlow, client: &str) -> (String, String) {
    let server = host_name(flow.dst_ip);
    let Some(dns) = &flow.dns else {
        return (
            format!("{client} usó el DNS {}", de(&server)),
            "El DNS es la guía telefónica de Internet: traduce nombres en direcciones.".into(),
        );
    };
    let qname = dns
        .queries
        .first()
        .map(|q| shorten(&q.name, 48))
        .unwrap_or_else(|| "un nombre".into());
    let title = format!("{client} preguntó por «{qname}»");
    let guide = "El DNS es la guía telefónica de Internet: traduce nombres en direcciones.";
    let addrs: Vec<String> = dns
        .answers
        .iter()
        .filter_map(|a| {
            a.address
                .map(|ip| ip.to_string())
                .or_else(|| a.target.clone())
        })
        .collect();
    let story = if !dns.is_response {
        format!("{} no respondió. {guide}", capitalize(&server))
    } else if dns.rcode == Some(3) {
        format!(
            "{} respondió que ese nombre no existe. {guide}",
            capitalize(&server)
        )
    } else if addrs.is_empty() {
        format!("{} respondió sin direcciones. {guide}", capitalize(&server))
    } else {
        format!(
            "{} respondió: {}. {guide} Normal.",
            capitalize(&server),
            addrs.join(", ")
        )
    };
    (title, story)
}

/// Explica una alerta de un flujo (texto, impacto y qué hacer).
fn explain_alert(flow: &EnrichedFlow, alert: &socshark_core::Alert) -> AlertExplanation {
    let src = host_name(flow.src_ip);
    let dst = host_name(flow.dst_ip);
    let (title, story, action): (String, String, String) = match alert.id.as_str() {
        "DNS-TUNNELING" => {
            let qname = flow
                .dns
                .as_ref()
                .and_then(|d| d.queries.first())
                .map(|q| q.name.clone())
                .unwrap_or_default();
            (
                "Posible fuga de datos escondida en DNS".into(),
                format!(
                    "{} preguntó por un nombre de {} caracteres que parece aleatorio («{}»). \
                     Los programas maliciosos esconden datos dentro de estos nombres para \
                     sacarlos de la red sin que se note.",
                    capitalize(&src),
                    qname.chars().count(),
                    shorten(&qname, 40)
                ),
                format!(
                    "Averigua qué programa {} hace estas consultas y bloquea el dominio {}.",
                    de(&src),
                    base_domain(&qname)
                ),
            )
        }
        "PORT-SCAN" => (
            "Escaneo de puertos".into(),
            format!(
                "{}. Es lo que hace un programa de escaneo (como nmap) para buscar servicios abiertos.",
                alert.detail
            ),
            format!(
                "Si nadie de IT ha lanzado un escaneo autorizado, revisa {src}: puede estar comprometido."
            ),
        ),
        "NETWORK-SWEEP" => (
            "Barrido de red".into(),
            format!(
                "{}. Así buscan los atacantes y los gusanos equipos con un servicio concreto abierto.",
                alert.detail
            ),
            format!(
                "Si no es un inventario autorizado, revisa {src}: puede estar comprometido."
            ),
        ),
        "REPEATED-ATTEMPTS" => (
            "Intentos de conexión repetidos".into(),
            format!(
                "{}. Puede ser un servicio caído, un programa mal configurado o alguien insistiendo.",
                alert.detail
            ),
            format!(
                "Comprueba si {} {} debería estar funcionando y qué programa {} insiste.",
                service_name(flow),
                de(&dst),
                de(&src)
            ),
        ),
        "INSECURE-PORT" => (
            "Acceso remoto sin cifrar (Telnet)".into(),
            format!(
                "{} usó Telnet con {dst}. Telnet envía usuario, contraseña y comandos en texto \
                 claro: cualquiera en la red puede leerlos.",
                capitalize(&src)
            ),
            "Sustituye Telnet por SSH y cambia las contraseñas que se hayan usado.".into(),
        ),
        "EXPOSED-DB" => (
            "Base de datos accesible desde la red".into(),
            format!(
                "{} se conectó directamente a {} en {dst}. Una base de datos abierta a la red es \
                 un objetivo muy buscado.",
                capitalize(&src),
                service_name(flow)
            ),
            "Limita con el cortafuegos quién puede conectarse y revisa sus contraseñas.".into(),
        ),
        "BEACONING" => {
            let (secs, times) = flow
                .interval_stats
                .as_ref()
                .map(|s| (s.mean_micros as f64 / 1e6, s.intervals + 1))
                .unwrap_or((0.0, 0));
            (
                "Comunicación sospechosamente regular".into(),
                format!(
                    "{} contacta con {dst} cada {secs:.0} segundos, siempre al mismo ritmo ({times} \
                     veces). Las personas no navegan así; los programas que «llaman a casa» \
                     (como el malware controlado a distancia) sí.",
                    capitalize(&src)
                ),
                format!(
                    "Identifica qué programa {} abre esta conexión y si debería hacerlo.",
                    de(&src)
                ),
            )
        }
        "FILE-MASQUERADING" => {
            let file = flow.extracted_files.iter().find(|f| f.masquerading_suspect);
            let name = file.map(|f| shorten(&f.name, 60)).unwrap_or_default();
            let magic = file.and_then(|f| f.magic.clone()).unwrap_or_default();
            let sha = file
                .and_then(|f| f.sha256.as_deref())
                .map(|h| format!(" Su huella SHA-256 es {h}."))
                .unwrap_or_default();
            (
                "Archivo disfrazado".into(),
                format!(
                    "{} descargó «{name}», que aparenta ser otra cosa pero en realidad es un \
                     programa ejecutable ({magic}). Es un truco habitual para colar malware.{sha}",
                    capitalize(&src)
                ),
                "No abras el archivo y analízalo con un antivirus o en VirusTotal (por su SHA-256)."
                    .into(),
            )
        }
        "THREAT-INTEL-FEODO" => (
            "Conexión con un servidor de malware conocido".into(),
            format!(
                "{} aparece en la lista Feodo Tracker de servidores que controlan malware \
                 (Emotet, Dridex, TrickBot…), y {src} se comunicó con él.",
                capitalize(&dst)
            ),
            format!("Desconecta {src} de la red y revísalo con tu equipo de seguridad."),
        ),
        "TOR-USAGE" => (
            "Uso de la red Tor".into(),
            format!(
                "{} es una salida de Tor, una red que oculta quién habla con quién. Puede ser \
                 privacidad legítima o una forma de esconder actividad.",
                capitalize(&dst)
            ),
            "Comprueba si el uso de Tor está permitido en tu organización.".into(),
        ),
        _ => (
            alert.name.clone(),
            alert.detail.clone(),
            "Revisa esta conversación con más detalle.".into(),
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
    let (title, story) = describe(flow);
    let mut alerts: Vec<AlertExplanation> =
        flow.alerts.iter().map(|a| explain_alert(flow, a)).collect();
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
            let single = explain_alert(&flows[i0], a0);
            let (title, story, action) = match key {
                GroupKey::Scan(src, dst) => scan_story(flows, &idx, src, dst),
                GroupKey::Sweep(src, port) => sweep_story(flows, &idx, src, port),
                GroupKey::Repeat(src, dst, port) => (
                    format!(
                        "{} insiste en conectar con {} {}",
                        capitalize(&host_name(src)),
                        port_label(port, Transport::Tcp),
                        de(&host_name(dst))
                    ),
                    format!(
                        "{} intentos sin llegar a conectar. Puede ser un servicio caído, un \
                         programa mal configurado o alguien insistiendo.",
                        idx.len()
                    ),
                    single.action,
                ),
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
            open.push(port_label(p, Transport::Tcp));
        } else {
            closed.push(port_label(p, Transport::Tcp));
        }
    }
    let mut story = format!(
        "Probó {} puertos {} sin llegar a conectar.",
        ports.len(),
        de(&host_name(dst))
    );
    if !open.is_empty() {
        story.push_str(&format!(" Respondieron (abiertos): {}.", open.join(", ")));
    }
    if !closed.is_empty() {
        story.push_str(&format!(" Rechazaron (cerrados): {}.", closed.join(", ")));
    }
    if silent > 0 {
        story.push_str(&format!(" Sin respuesta: {silent}."));
    }
    story.push_str(
        " Es lo que hace un programa de escaneo (como nmap) para buscar servicios abiertos.",
    );
    (
        format!("{} escaneó {}", capitalize(&host_name(src)), host_name(dst)),
        story,
        format!(
            "Si nadie de IT ha lanzado un escaneo autorizado, revisa {}: puede estar comprometido.",
            host_name(src)
        ),
    )
}

fn sweep_story(
    flows: &[EnrichedFlow],
    idx: &[usize],
    src: IpAddr,
    port: u16,
) -> (String, String, String) {
    let mut hosts: Vec<IpAddr> = idx.iter().map(|&i| flows[i].dst_ip).collect();
    hosts.sort_unstable();
    hosts.dedup();
    let sample: Vec<String> = hosts.iter().take(5).map(|h| h.to_string()).collect();
    let more = if hosts.len() > sample.len() {
        format!(" y {} más", hosts.len() - sample.len())
    } else {
        String::new()
    };
    (
        format!(
            "{} barrió la red buscando {}",
            capitalize(&host_name(src)),
            port_label(port, Transport::Tcp)
        ),
        format!(
            "Probó el mismo servicio en {} equipos ({}{more}) sin llegar a conectar. Así buscan \
             los atacantes y los gusanos equipos con un servicio concreto abierto.",
            hosts.len(),
            sample.join(", ")
        ),
        format!(
            "Si no es un inventario autorizado, revisa {}: puede estar comprometido.",
            host_name(src)
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::flujo_basico;
    use socshark_core::{Alert, DnsAnswerSummary, DnsQuerySummary, DnsSummary};

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
    fn todas_las_alertas_del_motor_tienen_explicacion_propia() {
        for id in [
            "DNS-TUNNELING",
            "PORT-SCAN",
            "NETWORK-SWEEP",
            "REPEATED-ATTEMPTS",
            "INSECURE-PORT",
            "EXPOSED-DB",
            "BEACONING",
            "FILE-MASQUERADING",
            "THREAT-INTEL-FEODO",
            "TOR-USAGE",
        ] {
            let f = flujo_basico(6, 40000, 22);
            let a = explain_alert(&f, &alerta(id, Severity::Medium, "detalle"));
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
}
