//! socshark-soc: capa de análisis SOC ("soc-engine" del diseño original).
//!
//! Módulos independientes orquestados por [`enrich::enrich_all`]:
//! - [`noise`]: Smart Noise Dimming (clasificación de tráfico de fondo).
//! - [`passive_dns`]: caché dominio↔IP construida con las respuestas DNS.
//! - [`risk`]: mini-IDS heurístico + puntuación de riesgo (0-100).
//! - [`beacon`]: beaconing entre flujos (inicios de conexión regulares).
//! - [`summarize`]: resumen técnico de una línea por flujo.
//! - [`explain`]: traducción a lenguaje humano (semáforo, frases, qué hacer
//!   e historias agrupadas) para la GUI y cualquier persona.
//! - [`carve`]: file carving HTTP + detección de encubrimiento T1036.
//! - [`domain`]: dominio registrable aproximado (eTLD+1) sin PSL completa.
//! - [`intel`]: threat intel offline (Feodo C2, salidas de Tor).
//! - [`siem`]: export a SIEM (ECS y Wazuh).
//!
//! Las fases posteriores añadirán aquí: correlación de proceso (eBPF) y
//! GeoIP/ASN. Ver `docs/soc-features.md`, `docs/siem-export.md` y
//! `docs/soc-mitre-mapping.md`.

pub mod beacon;
pub mod carve;
pub mod domain;
pub mod enrich;
pub mod explain;
pub mod hosts;
pub mod intel;
pub mod noise;
mod oui_data;
pub mod passive_dns;
pub mod risk;
pub mod siem;
pub mod summarize;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use socshark_core::{EnrichedFlow, Transport};

pub use enrich::{enrich_all, SocContext};
pub use intel::ThreatIntelDb;

/// (ip_origen, ip_destino, puerto_destino): un servicio concreto.
pub type ScanKey = (IpAddr, IpAddr, u16);

/// Cota de puertos/hosts distintos recordados por clave. Supera con creces
/// cualquier umbral y evita que un barrido masivo (o direcciones
/// falsificadas) haga crecer los conjuntos sin límite en el daemon.
const MAX_DISTINCT_PER_KEY: usize = 4096;

/// Cota de claves por mapa del [`ScanTracker`]. En el daemon el rastreador
/// vive semanas: sin tope, cada origen/destino nuevo (o falsificado) suma
/// una entrada para siempre. Al superarla se olvida la mitad menos reciente.
pub const MAX_SCAN_KEYS: usize = 65_536;

/// Desaloja la mitad menos reciente de `map` según el reloj lógico que
/// devuelve `seen` (mayor = más reciente). Coste O(n), pero solo se paga al
/// rebasar la cota, así que amortizado es O(1) por inserción.
pub(crate) fn evict_oldest_half<K, V, F>(map: &mut HashMap<K, V>, seen: F)
where
    K: Eq + std::hash::Hash,
    F: Fn(&V) -> u64,
{
    if map.is_empty() {
        return;
    }
    let mut ticks: Vec<u64> = map.values().map(&seen).collect();
    let mid = ticks.len() / 2;
    let (_, cut, _) = ticks.select_nth_unstable(mid);
    let cut = *cut;
    map.retain(|_, v| seen(v) > cut);
}

/// ¿Es el flujo un intento de conexión TCP que nunca llegó a establecerse?
///
/// Los contadores de flags suman las dos direcciones, así que se reconocen
/// los tres desenlaces de una sonda: sin respuesta (puerto filtrado: solo
/// SYN), RST/ACK (puerto cerrado) y SYN/ACK seguido de RST del cliente
/// (half-open de `nmap -sS`, o connect + RST). Lo que una sonda nunca tiene
/// es carga útil (PSH) ni cierre ordenado (FIN).
pub fn is_failed_connect(flow: &EnrichedFlow) -> bool {
    let f = &flow.tcp_flags;
    flow.transport == Transport::Tcp
        && f.syn > 0
        && f.psh == 0
        && f.fin == 0
        && (f.ack == 0 || f.rst > 0)
}

/// Señales de escaneo acumuladas para el origen y destino de un flujo.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanSignals {
    /// Puertos distintos de `dst_ip` que el origen probó sin éxito
    /// (escaneo vertical).
    pub distinct_ports: u32,
    /// Hosts distintos en `dst_port` que el origen probó sin éxito
    /// (barrido horizontal).
    pub distinct_hosts: u32,
    /// Intentos fallidos del origen al mismo `dst_ip:dst_port`.
    pub attempts: u32,
}

/// Rastrea intentos de conexión fallidos a través de flujos.
///
/// ¿Por qué aquí y no en el agregador? Cada sonda de un escáner es un
/// *flujo distinto* (otro puerto o host destino), así que el patrón solo es
/// visible con estado **entre flujos**. Se agrupa de tres formas: por
/// (origen, destino) → puertos probados, por (origen, puerto) → hosts
/// probados y por servicio exacto → número de intentos.
///
/// Cada mapa está acotado a [`MAX_SCAN_KEYS`] claves; el valor guarda el
/// reloj lógico de su última actualización para desalojar lo más antiguo.
#[derive(Default)]
pub struct ScanTracker {
    ports: HashMap<(IpAddr, IpAddr), (HashSet<u16>, u64)>,
    hosts: HashMap<(IpAddr, u16), (HashSet<IpAddr>, u64)>,
    attempts: HashMap<ScanKey, (u32, u64)>,
    tick: u64,
}

impl ScanTracker {
    /// Observa un flujo exportado; solo cuentan los intentos fallidos
    /// ([`is_failed_connect`]): una conexión establecida nunca es una sonda.
    pub fn observe(&mut self, flow: &EnrichedFlow) {
        if !is_failed_connect(flow) {
            return;
        }
        self.tick += 1;
        let tick = self.tick;
        if self.ports.len() >= MAX_SCAN_KEYS {
            evict_oldest_half(&mut self.ports, |v| v.1);
        }
        if self.hosts.len() >= MAX_SCAN_KEYS {
            evict_oldest_half(&mut self.hosts, |v| v.1);
        }
        if self.attempts.len() >= MAX_SCAN_KEYS {
            evict_oldest_half(&mut self.attempts, |v| v.1);
        }
        let ports = self.ports.entry((flow.src_ip, flow.dst_ip)).or_default();
        if ports.0.len() < MAX_DISTINCT_PER_KEY {
            ports.0.insert(flow.dst_port);
        }
        ports.1 = tick;
        let hosts = self.hosts.entry((flow.src_ip, flow.dst_port)).or_default();
        if hosts.0.len() < MAX_DISTINCT_PER_KEY {
            hosts.0.insert(flow.dst_ip);
        }
        hosts.1 = tick;
        let attempts = self
            .attempts
            .entry((flow.src_ip, flow.dst_ip, flow.dst_port))
            .or_default();
        attempts.0 = attempts.0.saturating_add(1);
        attempts.1 = tick;
    }

    /// Claves vivas en el mapa más grande (para métricas y tests).
    pub fn tracked_keys(&self) -> usize {
        self.ports
            .len()
            .max(self.hosts.len())
            .max(self.attempts.len())
    }

    /// Señales acumuladas para el origen/destino/puerto de este flujo.
    pub fn signals(&self, flow: &EnrichedFlow) -> ScanSignals {
        let len = |s: Option<usize>| s.unwrap_or(0) as u32;
        ScanSignals {
            distinct_ports: len(self
                .ports
                .get(&(flow.src_ip, flow.dst_ip))
                .map(|v| v.0.len())),
            distinct_hosts: len(self
                .hosts
                .get(&(flow.src_ip, flow.dst_port))
                .map(|v| v.0.len())),
            attempts: self
                .attempts
                .get(&(flow.src_ip, flow.dst_ip, flow.dst_port))
                .map_or(0, |v| v.0),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    use socshark_core::{EnrichedFlow, FlowId, FlowState, L7Protocol, TcpFlagCounts, Transport};
    use std::net::{IpAddr, Ipv4Addr};

    /// Flujo genérico para tests: extremos neutros y el protocolo indicado.
    /// `proto_num` es el número de protocolo IP (6=TCP, 17=UDP).
    pub(crate) fn flujo_basico(proto_num: u8, sport: u16, dport: u16) -> EnrichedFlow {
        let transport = Transport::from_ip_proto(proto_num);
        EnrichedFlow {
            flow_id: FlowId(format!("{transport:?}/10.0.0.5:{sport}-10.0.0.99:{dport}")),
            state: FlowState::Idle,
            transport,
            ip_version: 4,
            l7_protocol: L7Protocol::Unknown,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            src_port: sport,
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
            dst_port: dport,
            src_mac: None,
            dst_mac: None,
            first_seen_micros: 0,
            last_seen_micros: 1_000,
            duration_micros: 1_000,
            packets: 1,
            bytes: 100,
            packets_rev: 0,
            bytes_rev: 0,
            tcp_flags: TcpFlagCounts::default(),
            process_name: None,
            pid: None,
            user: None,
            resolved_domain: None,
            dns: None,
            dst_geo_asn: None,
            ja4_fingerprint: None,
            tls_sni: None,
            interval_stats: None,
            threat_intel: vec![],
            is_background_noise: false,
            human_summary: String::new(),
            risk_score: 0,
            alerts: vec![],
            extracted_files: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_core::TcpFlagCounts;

    fn flujo_tcp(dst: &str, dport: u16, flags: TcpFlagCounts) -> EnrichedFlow {
        let mut f = crate::tests_support::flujo_basico(6, 45000, dport);
        f.src_ip = "10.0.0.9".parse().unwrap();
        f.dst_ip = dst.parse().unwrap();
        f.tcp_flags = flags;
        f
    }

    fn flags(syn: u32, ack: u32, rst: u32, psh: u32, fin: u32) -> TcpFlagCounts {
        TcpFlagCounts {
            syn,
            ack,
            rst,
            psh,
            fin,
            urg: 0,
        }
    }

    #[test]
    fn sondas_fallidas_vs_conexiones_establecidas() {
        let es = |f: TcpFlagCounts| is_failed_connect(&flujo_tcp("10.0.0.1", 22, f));
        assert!(es(flags(1, 0, 0, 0, 0)), "filtrado: solo SYN");
        assert!(es(flags(2, 0, 0, 0, 0)), "filtrado con retransmisión");
        assert!(es(flags(1, 1, 1, 0, 0)), "cerrado: SYN → RST/ACK");
        assert!(
            es(flags(2, 1, 1, 0, 0)),
            "abierto, half-open: SYN, SYN/ACK, RST"
        );
        assert!(es(flags(2, 2, 1, 0, 0)), "connect + RST sin datos");
        assert!(!es(flags(2, 3, 0, 0, 0)), "handshake completo sin cerrar");
        assert!(!es(flags(2, 6, 0, 2, 2)), "sesión con datos y FIN");
        assert!(!es(flags(2, 5, 1, 1, 0)), "datos y luego RST");
        assert!(!es(flags(0, 4, 0, 2, 0)), "captura a mitad de sesión");
        let mut udp = flujo_tcp("10.0.0.1", 53, flags(1, 0, 0, 0, 0));
        udp.transport = Transport::Udp;
        assert!(!is_failed_connect(&udp));
    }

    #[test]
    fn tracker_separa_vertical_horizontal_y_reintentos() {
        let mut t = ScanTracker::default();
        let sonda = flags(1, 0, 0, 0, 0);
        // Vertical: 3 puertos de 10.0.0.1 (uno con dos intentos).
        for p in [22, 80, 443, 443] {
            t.observe(&flujo_tcp("10.0.0.1", p, sonda));
        }
        // Horizontal: el 445 en 2 hosts más.
        for h in ["10.0.0.2", "10.0.0.3"] {
            t.observe(&flujo_tcp(h, 445, sonda));
        }
        // Una conexión establecida no cuenta para nada.
        t.observe(&flujo_tcp("10.0.0.1", 8080, flags(2, 6, 0, 2, 2)));

        let s = t.signals(&flujo_tcp("10.0.0.1", 443, sonda));
        assert_eq!(s.distinct_ports, 3);
        assert_eq!(s.attempts, 2);
        assert_eq!(
            t.signals(&flujo_tcp("10.0.0.3", 445, sonda)).distinct_hosts,
            2
        );
        assert_eq!(t.signals(&flujo_tcp("10.0.0.1", 8080, sonda)).attempts, 0);
    }

    #[test]
    fn tracker_acotado_en_claves_y_conserva_lo_reciente() {
        let mut t = ScanTracker::default();
        let sonda = flags(1, 0, 0, 0, 0);
        // Orígenes falsificados distintos: cada uno crea claves nuevas.
        for i in 0..(MAX_SCAN_KEYS as u32 + 1000) {
            let mut f = flujo_tcp("10.0.0.1", 22, sonda);
            f.src_ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0b00_0000 + i));
            t.observe(&f);
        }
        assert!(t.tracked_keys() <= MAX_SCAN_KEYS, "{}", t.tracked_keys());
        // El último origen sigue contando.
        let mut f = flujo_tcp("10.0.0.1", 22, sonda);
        f.src_ip = IpAddr::V4(std::net::Ipv4Addr::from(
            0x0b00_0000 + MAX_SCAN_KEYS as u32 + 999,
        ));
        assert_eq!(t.signals(&f).attempts, 1);
    }

    #[test]
    fn desalojo_quita_la_mitad_mas_antigua() {
        let mut m: HashMap<u32, u64> = (0..10).map(|i| (i, i as u64)).collect();
        evict_oldest_half(&mut m, |v| *v);
        assert!(m.len() <= 5 && !m.is_empty());
        assert!(m.contains_key(&9));
        assert!(!m.contains_key(&0));
    }
}
