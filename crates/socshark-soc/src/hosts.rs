//! Quién es quién en la red local.
//!
//! Una dirección como `192.168.1.30` no le dice nada a nadie; «el iPhone de
//! Ana», «la impresora HP» o «el router» sí. [`HostBook`] aprende de los
//! paquetes lo que los propios equipos anuncian (nombre por DHCP, mDNS,
//! LLMNR o NetBIOS, servicios que ofrecen) y quién es el router, y le pone
//! fabricante a cada MAC con el registro público del IEEE. El resultado,
//! [`HostDirectory`], es lo que usan las frases de [`crate::explain`] y la
//! interfaz.
//!
//! Todo es informativo: un equipo puede mentir sobre su nombre, así que
//! nada de esto se usa para decidir alertas.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::Serialize;
use socshark_core::Transport;
use socshark_dissectors::{clean_name, parse_dhcp, parse_nbns, DissectedPacket};

use crate::oui_data::{BRANDS, OUI};

// ------------------------------------------------------------ fabricante

/// Fabricante de una MAC: `(marca, a qué suele corresponder)`.
pub fn vendor(mac: &[u8; 6]) -> Option<(&'static str, Option<&'static str>)> {
    // Prefijos administrados localmente con dueño conocido.
    if mac[..3] == [0x52, 0x54, 0x00] {
        return Some(("QEMU/KVM", Some("máquina virtual")));
    }
    if mac[..2] == [0x02, 0x42] {
        return Some(("Docker", Some("contenedor")));
    }
    let key = u32::from_be_bytes([0, mac[0], mac[1], mac[2]]);
    let i = OUI.binary_search_by_key(&key, |&(p, _)| p).ok()?;
    Some(BRANDS[OUI[i].1 as usize])
}

/// MAC inventada por el propio equipo (bit «administrada localmente»): los
/// móviles y portátiles modernos la generan por privacidad en cada Wi-Fi.
pub fn is_random_mac(mac: &[u8; 6]) -> bool {
    mac[0] & 0x02 != 0 && mac[0] & 0x01 == 0 && vendor(mac).is_none()
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for b in &mut out {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

// ------------------------------------------------------------ direcciones

/// Unicast de la red local (privada, enlace local, ULA): las únicas a las
/// que se les aprende nombre.
fn is_lan_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => (v4.is_private() || v4.is_link_local()) && !v4.is_broadcast(),
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            (s0 & 0xfe00) == 0xfc00 || (s0 & 0xffc0) == 0xfe80
        }
    }
}

/// Unicast de Internet: los paquetes que van o vienen de ella pasan por el
/// router, así que su MAC del lado local es la del router.
fn is_internet_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => (v6.segments()[0] & 0xe000) == 0x2000,
    }
}

// ------------------------------------------------------------ servicios mDNS

/// Qué es un equipo según los servicios que anuncia por mDNS.
fn kind_from_service(service: &str) -> Option<&'static str> {
    Some(match service {
        "_ipp" | "_ipps" | "_printer" | "_pdl-datastream" | "_scanner" | "_uscan" => "la impresora",
        "_googlecast" => "el Chromecast",
        "_airplay" | "_raop" => "el dispositivo AirPlay",
        "_spotify-connect" | "_sonos" => "el altavoz",
        "_hap" | "_homekit" | "_matter" | "_matterc" | "_hue" => "el dispositivo de domótica",
        "_amzn-wplay" => "el Fire TV",
        "_workstation" => "el ordenador",
        _ => return None,
    })
}

// ------------------------------------------------------------ aprendizaje

/// De dónde salió un nombre; a más prioridad, más fiable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Source {
    Netbios,
    Llmnr,
    Mdns,
    MdnsService,
    Dhcp,
}

impl Source {
    fn label(self) -> &'static str {
        match self {
            Source::Netbios => "NetBIOS",
            Source::Llmnr => "LLMNR",
            Source::Mdns | Source::MdnsService => "mDNS",
            Source::Dhcp => "DHCP",
        }
    }
}

#[derive(Debug, Default, Clone)]
struct Learned {
    mac: Option<[u8; 6]>,
    name: Option<(String, Source)>,
    kind: Option<&'static str>,
}

#[derive(Debug, Default, Clone)]
struct MacFacts {
    name: Option<(String, Source)>,
    os: Option<&'static str>,
}

/// Cuaderno de equipos: se alimenta paquete a paquete.
#[derive(Debug, Default, Clone)]
pub struct HostBook {
    by_ip: HashMap<IpAddr, Learned>,
    by_mac: HashMap<[u8; 6], MacFacts>,
    /// Votos de "esta MAC es la puerta a Internet".
    gateway_votes: HashMap<[u8; 6], u32>,
    /// Routers anunciados por DHCP.
    routers: Vec<IpAddr>,
}

/// ¿Un nombre de `source` sustituye al actual? (a igual fuente, el último).
fn better(current: &Option<(String, Source)>, source: Source) -> bool {
    match current {
        None => true,
        Some((_, s)) => *s <= source,
    }
}

/// Sistema operativo por la «clase de fabricante» de DHCP (opción 60).
fn os_from_vendor_class(vc: &str) -> Option<&'static str> {
    let v = vc.to_ascii_lowercase();
    Some(if v.starts_with("msft") {
        "Windows"
    } else if v.starts_with("android-dhcp") {
        "Android"
    } else if v.starts_with("dhcpcd") {
        "Linux o Android"
    } else if v.starts_with("udhcp") {
        "Linux (dispositivo)"
    } else {
        return None;
    })
}

impl HostBook {
    pub fn new() -> Self {
        Self::default()
    }

    fn entry(&mut self, ip: IpAddr) -> &mut Learned {
        self.by_ip.entry(ip).or_default()
    }

    fn name_ip(&mut self, ip: IpAddr, raw: &str, source: Source) {
        if !is_lan_unicast(ip) {
            return;
        }
        let Some(name) = clean_name(raw.trim_end_matches(".local").as_bytes()) else {
            return;
        };
        let e = self.entry(ip);
        if better(&e.name, source) {
            e.name = Some((name, source));
        }
    }

    /// Aprende lo que pueda de un paquete ya diseccionado.
    pub fn observe(&mut self, dp: &DissectedPacket) {
        let (Some(src), Some(dst)) = (dp.src_ip(), dp.dst_ip()) else {
            return;
        };
        if let Some(eth) = &dp.eth {
            if is_lan_unicast(src) {
                self.entry(src).mac = Some(eth.src_mac);
            }
            // Lo que llega de Internet o va hacia Internet cruza el router.
            if is_internet_unicast(src) {
                *self.gateway_votes.entry(eth.src_mac).or_default() += 1;
            }
            if is_internet_unicast(dst) {
                *self.gateway_votes.entry(eth.dst_mac).or_default() += 1;
            }
        }
        // Todos los anuncios de identidad van por UDP.
        let Some(udp) = dp.udp.as_ref().filter(|_| dp.transport == Transport::Udp) else {
            return;
        };
        let (sport, dport) = (udp.src_port, udp.dst_port);
        match (sport, dport) {
            (67 | 68, 67 | 68) => self.observe_dhcp(&dp.payload),
            (137, _) | (_, 137) => {
                if let Some(n) = parse_nbns(&dp.payload) {
                    self.name_ip(IpAddr::V4(n.address), &n.name, Source::Netbios);
                }
            }
            (5353, _) | (5355, _) => self.observe_mdns(dp, src, sport == 5355),
            _ => {}
        }
    }

    fn observe_dhcp(&mut self, payload: &[u8]) {
        let Some(d) = parse_dhcp(payload) else { return };
        if let Some(r) = d.router {
            let r = IpAddr::V4(r);
            if !self.routers.contains(&r) {
                self.routers.push(r);
            }
        }
        let Some(mac) = d.client_mac else { return };
        let facts = self.by_mac.entry(mac).or_default();
        if let Some(name) = d.hostname.filter(|_| d.op == 1) {
            facts.name = Some((name, Source::Dhcp));
        }
        if let Some(os) = d.vendor_class.as_deref().and_then(os_from_vendor_class) {
            facts.os = Some(os);
        }
        // Solo cuando la dirección es firme (ACK o la que ya usa el cliente).
        let ip = match d.message_type {
            Some(5) => d.your_ip.or(d.client_ip),
            _ => d.client_ip,
        };
        if let Some(ip) = ip {
            self.entry(IpAddr::V4(ip)).mac = Some(mac);
        }
    }

    fn observe_mdns(&mut self, dp: &DissectedPacket, src: IpAddr, llmnr: bool) {
        let Some(dns) = &dp.dns else { return };
        if !dns.is_response {
            return;
        }
        let source = if llmnr { Source::Llmnr } else { Source::Mdns };
        for rec in &dns.answers {
            if let Some(addr) = rec.address {
                self.name_ip(addr, &rec.name, source);
            }
            // PTR de servicio: «_ipp._tcp.local» → «HP OfficeJet._ipp._tcp.local».
            if llmnr || rec.rtype != 12 {
                continue;
            }
            let Some(target) = rec.target.as_deref() else {
                continue;
            };
            let service = rec.name.split('.').next().unwrap_or("");
            if let Some(kind) = kind_from_service(service) {
                if is_lan_unicast(src) {
                    self.entry(src).kind = Some(kind);
                }
            }
            if let Some(instance) = target.strip_suffix(&format!(".{}", rec.name)) {
                if kind_from_service(service).is_some() {
                    self.name_ip(src, instance, Source::MdnsService);
                }
            }
        }
    }

    /// MAC del router: la que más se usa para salir a Internet.
    fn gateway_mac(&self) -> Option<[u8; 6]> {
        self.gateway_votes
            .iter()
            .filter(|(_, &v)| v >= 3)
            .max_by_key(|(mac, &v)| (v, std::cmp::Reverse(**mac)))
            .map(|(mac, _)| *mac)
    }

    /// Lo aprendido, listo para frases y pantallas.
    pub fn directory(&self) -> HostDirectory {
        let gateway = self.gateway_mac();
        let mut hosts: Vec<HostInfo> = self
            .by_ip
            .iter()
            .map(|(&ip, l)| {
                let facts = l.mac.and_then(|m| self.by_mac.get(&m));
                let name = match (&l.name, facts.and_then(|f| f.name.as_ref())) {
                    (Some(a), Some(b)) => Some(if b.1 >= a.1 { b } else { a }),
                    (a, b) => a.as_ref().or(b),
                };
                let vendor = l.mac.as_ref().and_then(vendor);
                let router = self.routers.contains(&ip) || (l.mac.is_some() && l.mac == gateway);
                HostInfo {
                    ip,
                    mac: l.mac.map(|m| socshark_dissectors::fmt_mac(&m)),
                    name: name.map(|n| n.0.clone()),
                    name_source: name.map(|n| n.1.label()),
                    nickname: None,
                    vendor: vendor.map(|v| v.0),
                    vendor_hint: vendor.and_then(|v| v.1),
                    kind: if router { None } else { l.kind },
                    os: facts.and_then(|f| f.os),
                    random_mac: l.mac.as_ref().is_some_and(is_random_mac),
                    role: router.then_some(Role::Router),
                }
            })
            .collect();
        // Routers que solo conocemos por DHCP (aún sin paquetes propios).
        for &r in &self.routers {
            if !self.by_ip.contains_key(&r) {
                hosts.push(HostInfo::bare(r, Some(Role::Router)));
            }
        }
        HostDirectory::from_hosts(hosts)
    }
}

// ------------------------------------------------------------ directorio

/// Papel especial de un equipo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// La puerta a Internet.
    Router,
    /// El ordenador donde corre soc-shark (solo en vivo).
    ThisComputer,
}

/// Lo que se sabe de un equipo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostInfo {
    pub ip: IpAddr,
    pub mac: Option<String>,
    /// Nombre que el equipo anuncia («iPhone-de-Ana»).
    pub name: Option<String>,
    /// Por dónde lo anunció: DHCP, mDNS, LLMNR o NetBIOS.
    pub name_source: Option<&'static str>,
    /// Apodo que le puso la persona usuaria (manda sobre todo lo demás).
    pub nickname: Option<String>,
    /// Marca del fabricante de su tarjeta de red.
    pub vendor: Option<&'static str>,
    /// A qué suele corresponder esa marca («router de operadora»).
    pub vendor_hint: Option<&'static str>,
    /// Qué es, por los servicios que ofrece («la impresora»).
    pub kind: Option<&'static str>,
    /// Sistema operativo según DHCP.
    pub os: Option<&'static str>,
    /// MAC inventada por privacidad (móviles y portátiles modernos).
    pub random_mac: bool,
    pub role: Option<Role>,
}

impl HostInfo {
    fn bare(ip: IpAddr, role: Option<Role>) -> Self {
        Self {
            ip,
            mac: None,
            name: None,
            name_source: None,
            nickname: None,
            vendor: None,
            vendor_hint: None,
            kind: None,
            os: None,
            random_mac: false,
            role,
        }
    }

    /// ¿Se sabe quién es (más allá del fabricante)?
    pub fn is_identified(&self) -> bool {
        self.nickname.is_some() || self.role.is_some() || self.name.is_some() || self.kind.is_some()
    }

    /// Clave estable para el apodo: la MAC si es fija, si no la IP.
    pub fn key(&self) -> String {
        match &self.mac {
            Some(mac) => format!("mac:{mac}"),
            None => format!("ip:{}", self.ip),
        }
    }

    /// Nombre corto para tablas y mapas (sin la IP).
    pub fn short(&self) -> Option<String> {
        if let Some(n) = &self.nickname {
            return Some(n.clone());
        }
        match self.role {
            Some(Role::Router) => return Some("Router".into()),
            Some(Role::ThisComputer) => return Some("Este ordenador".into()),
            None => {}
        }
        if let Some(n) = &self.name {
            return Some(n.clone());
        }
        let kind = self
            .kind
            .map(|k| capital(k.split_once(' ').map_or(k, |x| x.1)));
        match (kind, self.vendor) {
            (Some(k), Some(v)) => Some(format!("{k} {v}")),
            (Some(k), None) => Some(k),
            (None, Some(v)) => Some(format!("Equipo {v}")),
            (None, None) => None,
        }
    }

    /// El equipo en una frase: «el equipo «iPhone-de-Ana» (192.168.1.30)».
    pub fn noun(&self) -> String {
        let ip = self.ip;
        if let Some(n) = &self.nickname {
            return format!("«{n}» ({ip})");
        }
        match self.role {
            Some(Role::Router) => return format!("el router ({ip})"),
            Some(Role::ThisComputer) => return format!("este ordenador ({ip})"),
            None => {}
        }
        match (&self.name, self.kind, self.vendor) {
            (Some(n), Some(k), _) => format!("{k} «{n}» ({ip})"),
            (Some(n), None, _) => format!("el equipo «{n}» ({ip})"),
            (None, Some(k), Some(v)) => format!("{k} {v} ({ip})"),
            (None, Some(k), None) => format!("{k} {ip}"),
            (None, None, Some(v)) => format!("el equipo {v} ({ip})"),
            (None, None, None) => crate::explain::host_name(ip),
        }
    }
}

fn capital(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// Todos los equipos conocidos, por IP.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(transparent)]
pub struct HostDirectory {
    hosts: Vec<HostInfo>,
    #[serde(skip)]
    by_ip: HashMap<IpAddr, usize>,
}

impl HostDirectory {
    fn from_hosts(mut hosts: Vec<HostInfo>) -> Self {
        hosts.sort_by_key(|h| h.ip);
        let by_ip = hosts.iter().enumerate().map(|(i, h)| (h.ip, i)).collect();
        Self { hosts, by_ip }
    }

    pub fn get(&self, ip: IpAddr) -> Option<&HostInfo> {
        self.by_ip.get(&ip).map(|&i| &self.hosts[i])
    }

    /// El equipo con esta MAC (`aa:bb:…`), si se conoce su IP.
    pub fn by_mac(&self, mac: &str) -> Option<&HostInfo> {
        self.hosts.iter().find(|h| h.mac.as_deref() == Some(mac))
    }

    pub fn hosts(&self) -> &[HostInfo] {
        &self.hosts
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// El equipo en una frase; sin datos, como siempre («el equipo 192.168.1.30»).
    pub fn host_name(&self, ip: IpAddr) -> String {
        match self.get(ip) {
            Some(h) => h.noun(),
            None => crate::explain::host_name(ip),
        }
    }

    /// Marca las direcciones de este ordenador (en vivo se conocen).
    pub fn mark_this_computer(&mut self, addrs: &[IpAddr]) {
        for &ip in addrs {
            if ip.is_loopback() {
                continue;
            }
            match self.by_ip.get(&ip) {
                Some(&i) => self.hosts[i].role = Some(Role::ThisComputer),
                None => {
                    self.hosts
                        .push(HostInfo::bare(ip, Some(Role::ThisComputer)));
                    *self = Self::from_hosts(std::mem::take(&mut self.hosts));
                }
            }
        }
    }

    /// Aplica los apodos (clave `mac:…` o `ip:…` → apodo). Los equipos con
    /// apodo pero sin paquetes en esta captura se añaden si su clave es IP.
    pub fn apply_nicknames(&mut self, nicknames: &HashMap<String, String>) {
        for h in &mut self.hosts {
            let by_mac = h
                .mac
                .as_ref()
                .and_then(|m| nicknames.get(&format!("mac:{m}")));
            h.nickname = by_mac
                .or_else(|| nicknames.get(&format!("ip:{}", h.ip)))
                .cloned();
        }
    }

    /// Normaliza una clave de apodo recibida de fuera (`mac:…`/`ip:…`).
    pub fn valid_key(key: &str) -> Option<String> {
        if let Some(mac) = key.strip_prefix("mac:") {
            return parse_mac(mac).map(|m| format!("mac:{}", socshark_dissectors::fmt_mac(&m)));
        }
        if let Some(ip) = key.strip_prefix("ip:") {
            return ip.parse::<IpAddr>().ok().map(|ip| format!("ip:{ip}"));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_core::{LinkType, RawPacket};
    use socshark_dissectors::DissectorPipeline;
    use socshark_testgen as tg;

    fn feed(book: &mut HostBook, frames: &[Vec<u8>]) {
        let pipe = DissectorPipeline::new();
        for (i, data) in frames.iter().enumerate() {
            let pkt = RawPacket {
                ts_micros: i as u64,
                orig_len: data.len() as u32,
                data: data.clone(),
            };
            if let Some(dp) = pipe.dissect(&pkt, LinkType::Ethernet) {
                book.observe(&dp);
            }
        }
    }

    #[test]
    fn fabricante_por_mac() {
        assert_eq!(
            vendor(&[0xb8, 0x27, 0xeb, 1, 2, 3]).unwrap().0,
            "Raspberry Pi"
        );
        assert_eq!(
            vendor(&[0x00, 0x50, 0x56, 1, 2, 3]).unwrap().1,
            Some("máquina virtual")
        );
        assert_eq!(vendor(&[0x52, 0x54, 0x00, 1, 2, 3]).unwrap().0, "QEMU/KVM");
        assert!(vendor(&[0x12, 0x34, 0x56, 1, 2, 3]).is_none());
        assert!(is_random_mac(&[0xda, 0xa1, 0x19, 1, 2, 3]));
        assert!(!is_random_mac(&[0xb8, 0x27, 0xeb, 1, 2, 3]));
    }

    #[test]
    fn el_escenario_casa_tiene_nombres_y_router() {
        let mut book = HostBook::new();
        feed(&mut book, &tg::home_network_frames());
        let dir = book.directory();
        let get = |ip: &str| dir.get(ip.parse().unwrap()).cloned().unwrap();

        let phone = get(tg::HOME_PHONE_IP);
        assert_eq!(phone.name.as_deref(), Some("iPhone-de-Ana"));
        assert_eq!(phone.name_source, Some("DHCP"));
        assert!(phone.random_mac);
        assert_eq!(
            phone.noun(),
            format!("el equipo «iPhone-de-Ana» ({})", tg::HOME_PHONE_IP)
        );

        let printer = get(tg::HOME_PRINTER_IP);
        assert_eq!(printer.kind, Some("la impresora"));
        assert_eq!(printer.vendor, Some("HP"));
        assert!(
            printer.noun().starts_with("la impresora «HP OfficeJet"),
            "{}",
            printer.noun()
        );

        let pc = get(tg::HOME_PC_IP);
        assert_eq!(pc.name.as_deref(), Some("DESKTOP-AB12"));
        assert_eq!(pc.os, Some("Windows"));

        let router = get(tg::HOME_ROUTER_IP);
        assert_eq!(router.role, Some(Role::Router));
        assert_eq!(router.noun(), format!("el router ({})", tg::HOME_ROUTER_IP));
        assert_eq!(router.short().as_deref(), Some("Router"));

        // Internet no recibe nombres locales.
        assert!(dir.get("93.184.216.34".parse().unwrap()).is_none());
    }

    #[test]
    fn apodos_y_este_ordenador() {
        let mut book = HostBook::new();
        feed(&mut book, &tg::home_network_frames());
        let mut dir = book.directory();
        let phone = dir.get(tg::HOME_PHONE_IP.parse().unwrap()).unwrap().clone();
        let mut nicks = HashMap::new();
        nicks.insert(phone.key(), "Móvil de Ana".to_string());
        dir.apply_nicknames(&nicks);
        let ip: IpAddr = tg::HOME_PHONE_IP.parse().unwrap();
        assert_eq!(dir.host_name(ip), format!("«Móvil de Ana» ({ip})"));

        let me: IpAddr = "192.168.1.99".parse().unwrap();
        dir.mark_this_computer(&[me]);
        assert_eq!(dir.host_name(me), "este ordenador (192.168.1.99)");
        assert_eq!(
            dir.host_name(ip),
            format!("«Móvil de Ana» ({ip})"),
            "índice rehecho"
        );

        assert_eq!(
            HostDirectory::valid_key("mac:AA:BB:CC:00:11:22").as_deref(),
            Some("mac:aa:bb:cc:00:11:22")
        );
        assert!(HostDirectory::valid_key("mac:zz").is_none());
        assert!(HostDirectory::valid_key("ip:../etc").is_none());
    }
}
