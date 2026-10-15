//! Modelo de datos clave: `EnrichedFlow`, la "fila legible" del visor SOC.
//!
//! Es el contrato entre el motor y cualquier UI (TUI/GUI/ECS): contiene la
//! identidad enriquecida (proceso, dominio, ASN), la clasificación, el
//! resumen humano y el contexto Blue Team (riesgo, alertas, artefactos).

use socshark_common::ipaddr::IpAddr;
use socshark_common::json::Json;
use socshark_common::soc_types::{Artifact, SocAlert};
use socshark_common::timefmt;

/// Estado del flujo (máquina de estados TCP ligera).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    Active,
    Closed,
    Reset,
    Timeout,
}

impl FlowState {
    pub fn as_str(&self) -> &'static str {
        match self {
            FlowState::Active => "active",
            FlowState::Closed => "closed",
            FlowState::Reset => "reset",
            FlowState::Timeout => "timeout",
        }
    }
}

/// De dónde salió el dominio asociado al destino.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainSource {
    /// Respuesta DNS vista antes del flujo (Passive DNS).
    PassiveDns,
    /// Cabecera Host: de HTTP.
    HttpHost,
    /// Server Name Indication del ClientHello TLS.
    TlsSni,
    /// Sin resolución: conexión directa por IP (típico de C2/malware).
    None,
}

impl DomainSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            DomainSource::PassiveDns => "passive_dns",
            DomainSource::HttpHost => "http_host",
            DomainSource::TlsSni => "tls_sni",
            DomainSource::None => "none",
        }
    }
}

/// La conversación enriquecida: una sola fila legible por flujo.
#[derive(Debug, Clone)]
pub struct EnrichedFlow {
    pub flow_id: u64,
    /// Clave direccional (cliente → servidor según el primer paquete).
    pub key: FlowKey,
    pub state: FlowState,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub duration_ms: u64,

    // ── 1. Identidad enriquecida ─────────────────────────────────────────
    /// eBPF fase 3: nombre del proceso local (ej. "powershell.exe").
    pub process_name: Option<String>,
    /// eBPF fase 3: PID del proceso local.
    pub process_pid: Option<u32>,
    /// Passive DNS / Host / SNI: dominio del destino.
    pub resolved_domain: Option<String>,
    pub domain_source: DomainSource,
    /// Threat intel fase 3 (MMDB): "AS14061 DigitalOcean (NL)".
    pub dst_geo_asn: Option<String>,

    // ── 2. Clasificación y legibilidad ───────────────────────────────────
    /// Protocolo L7 principal: "HTTP", "TLS", "DNS", "TCP"...
    pub l7_protocol: &'static str,
    /// true si es ARP/mDNS/SSDP/NTP repetitivo → se atenúa en la UI.
    pub is_background_noise: bool,
    /// Frase legible generada por `human_summary`.
    pub human_summary: String,

    // ── 3. Contexto SOC / Blue Team ──────────────────────────────────────
    /// 0–100; determina el color de la fila.
    pub risk_score: u8,
    pub alerts: Vec<SocAlert>,
    /// Archivos reconstruidos en este flujo con su SHA-256.
    pub extracted_files: Vec<Artifact>,
    /// Huella JA4-like del ClientHello TLS (si lo hubo).
    pub ja4_fingerprint: Option<String>,

    // ── 4. Estadísticas y punteros a paquetes ────────────────────────────
    pub packets_c2s: u64,
    pub packets_s2c: u64,
    pub bytes_c2s: u64,
    pub bytes_s2c: u64,
    /// Número total de paquetes (c2s + s2c).
    pub packet_count: usize,
    /// Offsets de archivo por paquete (lectura instantánea vía mmap).
    pub packet_offsets: Vec<u64>,
    /// Timestamps por paquete (para beaconing); limitado a `MAX_TS`.
    pub packet_ts: Vec<u64>,
    /// 1 si el paquete llevaba datos de aplicación (PSH/payload).
    pub packet_data: Vec<u8>,

    // ── 5. Digests L7 acumulados (flat, para DSL y resúmenes) ────────────
    /// Queries DNS únicas vistas en el flujo (máx 32).
    pub dns_queries: Vec<String>,
    /// Respuestas "tipo valor" (ej. "A 185.220.101.4").
    pub dns_answers: Vec<String>,
    pub http_method: Option<String>,
    pub http_target: Option<String>,
    pub http_host: Option<String>,
    pub http_status: Option<u16>,
    pub http_content_length: Option<u64>,
    pub http_content_type: Option<String>,
    pub tls_version: Option<String>,
    pub tls_sni: Option<String>,
    pub tls_alpn: Option<String>,
    pub icmp_type: Option<u8>,
}

/// Límite de timestamps/offsets almacenados por flujo (el resto solo cuenta).
pub const MAX_PACKET_PTRS: usize = 4096;

impl EnrichedFlow {
    /// Fila vacía para un flujo nuevo.
    pub fn new(flow_id: u64, key: FlowKey, first_seen_us: u64) -> Self {
        EnrichedFlow {
            flow_id,
            key,
            state: FlowState::Active,
            first_seen_us,
            last_seen_us: first_seen_us,
            duration_ms: 0,
            process_name: None,
            process_pid: None,
            resolved_domain: None,
            domain_source: DomainSource::None,
            dst_geo_asn: None,
            l7_protocol: "TCP",
            is_background_noise: false,
            human_summary: String::new(),
            risk_score: 0,
            alerts: Vec::new(),
            extracted_files: Vec::new(),
            ja4_fingerprint: None,
            packets_c2s: 0,
            packets_s2c: 0,
            bytes_c2s: 0,
            bytes_s2c: 0,
            packet_count: 0,
            packet_offsets: Vec::new(),
            packet_ts: Vec::new(),
            packet_data: Vec::new(),
            dns_queries: Vec::new(),
            dns_answers: Vec::new(),
            http_method: None,
            http_target: None,
            http_host: None,
            http_status: None,
            http_content_length: None,
            http_content_type: None,
            tls_version: None,
            tls_sni: None,
            tls_alpn: None,
            icmp_type: None,
        }
    }

    /// ¿Hubo transferencia de datos de aplicación? (heurística beaconing)
    pub fn had_data(&self) -> bool {
        self.bytes_c2s > 0 || self.bytes_s2c > 0
    }

    /// Serialización JSON completa (informe del daemon / API futura).
    pub fn to_json(&self) -> Json {
        let dur = format_duration_fields(self);
        Json::obj(vec![
            ("flow_id", Json::Int(self.flow_id as i64)),
            ("state", Json::s(self.state.as_str())),
            (
                "first_seen",
                Json::s(timefmt::format_ts_us(self.first_seen_us)),
            ),
            (
                "last_seen",
                Json::s(timefmt::format_ts_us(self.last_seen_us)),
            ),
            ("duration_ms", Json::Int(dur.0)),
            ("duration", Json::s(dur.1)),
            (
                "src",
                Json::obj(vec![
                    ("ip", Json::s(self.key.src.to_string())),
                    ("port", Json::Int(self.key.sport as i64)),
                    (
                        "process",
                        match &self.process_name {
                            Some(p) => Json::s(p.clone()),
                            None => Json::Null,
                        },
                    ),
                    ("mac", Json::Null),
                ]),
            ),
            (
                "dst",
                Json::obj(vec![
                    ("ip", Json::s(self.key.dst.to_string())),
                    ("port", Json::Int(self.key.dport as i64)),
                    (
                        "domain",
                        match &self.resolved_domain {
                            Some(d) => Json::s(d.clone()),
                            None => Json::Null,
                        },
                    ),
                    (
                        "geo_asn",
                        match &self.dst_geo_asn {
                            Some(g) => Json::s(g.clone()),
                            None => Json::Null,
                        },
                    ),
                ]),
            ),
            ("domain_source", Json::s(self.domain_source.as_str())),
            ("l7_protocol", Json::s(self.l7_protocol)),
            ("is_background_noise", Json::Bool(self.is_background_noise)),
            ("human_summary", Json::s(self.human_summary.clone())),
            ("risk_score", Json::Int(self.risk_score as i64)),
            (
                "alerts",
                Json::Arr(self.alerts.iter().map(|a| a.to_json()).collect()),
            ),
            (
                "extracted_files",
                Json::Arr(self.extracted_files.iter().map(|a| a.to_json()).collect()),
            ),
            (
                "ja4_fingerprint",
                match &self.ja4_fingerprint {
                    Some(j) => Json::s(j.clone()),
                    None => Json::Null,
                },
            ),
            ("packets", Json::Int(self.packet_count as i64)),
            ("packets_c2s", Json::Int(self.packets_c2s as i64)),
            ("packets_s2c", Json::Int(self.packets_s2c as i64)),
            ("bytes_c2s", Json::Int(self.bytes_c2s as i64)),
            ("bytes_s2c", Json::Int(self.bytes_s2c as i64)),
            (
                "dns_queries",
                Json::Arr(
                    self.dns_queries
                        .iter()
                        .map(|q| Json::s(q.clone()))
                        .collect(),
                ),
            ),
            ("http", self.http_json()),
            ("tls", self.tls_json()),
        ])
    }

    fn http_json(&self) -> Json {
        if self.http_method.is_none() && self.http_status.is_none() {
            return Json::Null;
        }
        Json::obj(vec![
            (
                "method",
                match &self.http_method {
                    Some(m) => Json::s(m.clone()),
                    None => Json::Null,
                },
            ),
            (
                "target",
                match &self.http_target {
                    Some(t) => Json::s(t.clone()),
                    None => Json::Null,
                },
            ),
            (
                "host",
                match &self.http_host {
                    Some(h) => Json::s(h.clone()),
                    None => Json::Null,
                },
            ),
            (
                "status",
                match self.http_status {
                    Some(s) => Json::Int(s as i64),
                    None => Json::Null,
                },
            ),
            (
                "content_length",
                match self.http_content_length {
                    Some(l) => Json::Int(l as i64),
                    None => Json::Null,
                },
            ),
            (
                "content_type",
                match &self.http_content_type {
                    Some(c) => Json::s(c.clone()),
                    None => Json::Null,
                },
            ),
        ])
    }

    fn tls_json(&self) -> Json {
        if self.tls_version.is_none() && self.tls_sni.is_none() {
            return Json::Null;
        }
        Json::obj(vec![
            (
                "version",
                match &self.tls_version {
                    Some(v) => Json::s(v.clone()),
                    None => Json::Null,
                },
            ),
            (
                "sni",
                match &self.tls_sni {
                    Some(s) => Json::s(s.clone()),
                    None => Json::Null,
                },
            ),
            (
                "alpn",
                match &self.tls_alpn {
                    Some(a) => Json::s(a.clone()),
                    None => Json::Null,
                },
            ),
        ])
    }
}

fn format_duration_fields(f: &EnrichedFlow) -> (i64, String) {
    let ms = f.duration_ms as i64;
    (ms, timefmt::format_duration_us(f.duration_ms * 1000))
}

/// Clave de flujo: 5-tupla direccional.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
    pub proto: u8,
}

impl FlowKey {
    pub fn reversed(&self) -> FlowKey {
        FlowKey {
            src: self.dst,
            sport: self.dport,
            dst: self.src,
            dport: self.sport,
            proto: self.proto,
        }
    }

    pub fn to_string(&self) -> String {
        format!(
            "{}:{} → {}:{} ({})",
            self.src, self.sport, self.dst, self.dport, self.proto
        )
    }
}
