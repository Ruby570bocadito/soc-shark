//! Modelo de datos central: flujos enriquecidos y tipos asociados.
//!
//! [`EnrichedFlow`] es la unidad de información que produce soc-shark. Todo el
//! proyecto está orientado a flujos ("flow-first"): el analista ve sesiones
//! completas, no paquetes sueltos. Los campos marcados con "Fase N" existen
//! desde la Fase 1 con valor por defecto y se rellenarán cuando el módulo
//! correspondiente esté implementado (ver `docs/data-model.md` para la tabla
//! completa campo por campo y su fase de activación).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

/// Identificador canónico de un flujo bidireccional.
///
/// El formato es `transporte/extremo_bajo-extremo_alto`, donde los extremos
/// se ordenan con la clave canónica de [`crate::flow`]. El mismo intercambio
/// A→B y B→A produce siempre el mismo identificador.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowId(pub String);

impl fmt::Display for FlowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Protocolo de transporte observado en la capa IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Transport {
    Tcp,
    Udp,
    Icmp,
    /// Cualquier otro número de protocolo IP (ICMPv6=58, SCTP=132, ...).
    Other(u8),
}

impl Transport {
    /// Mapea un número de protocolo IP a su variante.
    pub fn from_ip_proto(proto: u8) -> Self {
        match proto {
            6 => Transport::Tcp,
            17 => Transport::Udp,
            1 => Transport::Icmp,
            other => Transport::Other(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Transport::Tcp => "TCP",
            Transport::Udp => "UDP",
            Transport::Icmp => "ICMP",
            Transport::Other(_) => "OTRO",
        }
    }
}

/// Protocolo de aplicación detectado por los dissectors o por heurísticas de
/// puerto/inspección ligera de payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum L7Protocol {
    Dns,
    Dhcp,
    Ntp,
    Http,
    Tls,
    Ssh,
    Unknown,
}

impl L7Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            L7Protocol::Dns => "DNS",
            L7Protocol::Dhcp => "DHCP",
            L7Protocol::Ntp => "NTP",
            L7Protocol::Http => "HTTP",
            L7Protocol::Tls => "TLS",
            L7Protocol::Ssh => "SSH",
            L7Protocol::Unknown => "?",
        }
    }
}

/// Estado del flujo al momento de exportarlo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowState {
    /// Aún recibe tráfico.
    Active,
    /// Inactivo (sin cierre TCP observado).
    Idle,
    /// Cerrado limpiamente (FIN) o abortado (RST).
    Closed,
}

impl FlowState {
    pub fn as_str(&self) -> &'static str {
        match self {
            FlowState::Active => "activo",
            FlowState::Idle => "inactivo",
            FlowState::Closed => "cerrado",
        }
    }
}

/// Severidad de una alerta SOC (ordenable de Info a Critical).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "baja",
            Severity::Medium => "media",
            Severity::High => "alta",
            Severity::Critical => "crítica",
        }
    }
}

/// Alerta generada por el motor SOC (mini-IDS y heurísticas de riesgo).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Identificador estable y legible por máquina, p. ej. `DNS-TUNNELING`.
    pub id: String,
    /// Nombre descriptivo en español.
    pub name: String,
    pub severity: Severity,
    /// Detalle específico de esta ocurrencia.
    pub detail: String,
    /// Técnica MITRE ATT&CK asociada, si aplica (p. ej. `T1048.003`).
    pub mitre: Option<String>,
}

/// Archivo potencialmente extraído de un flujo (file carving — Fase 4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFile {
    /// Nombre declarado (headers HTTP, nombre en el stream, ...).
    pub name: String,
    pub size: u64,
    /// SHA-256 del contenido reconstruido (cuando esté disponible).
    pub sha256: Option<String>,
    /// Firma "magic bytes" detectada (p. ej. `PE32`, `PDF`, `ZIP`).
    pub magic: Option<String>,
    /// True si el nombre no coincide con el tipo real → MITRE T1036 (Masquerading).
    pub masquerading_suspect: bool,
}

/// Pregunta DNS observada dentro del flujo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuerySummary {
    pub name: String,
    /// Código numérico del tipo de registro (1=A, 28=AAAA, 16=TXT, ...).
    pub qtype: u16,
}

/// Registro de respuesta DNS observado dentro del flujo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswerSummary {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    /// Dirección IP si el registro es A/AAAA.
    pub address: Option<IpAddr>,
    /// Objetivo si el registro es CNAME/NS/PTR.
    pub target: Option<String>,
}

/// Resumen del intercambio DNS visto en el flujo (consulta y/o respuesta).
///
/// La agregación combina la(s) pregunta(s) del paquete de consulta con las
/// respuestas del paquete de respuesta en un único objeto por flujo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSummary {
    pub is_response: bool,
    /// Código de respuesta DNS (0=NOERROR, 3=NXDOMAIN, ...) si hubo respuesta.
    pub rcode: Option<u8>,
    pub queries: Vec<DnsQuerySummary>,
    pub answers: Vec<DnsAnswerSummary>,
}

/// Contadores de flags TCP acumulados en ambas direcciones.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpFlagCounts {
    pub syn: u32,
    pub ack: u32,
    pub fin: u32,
    pub rst: u32,
    pub psh: u32,
    pub urg: u32,
}

/// La unidad central de información de soc-shark: un flujo de red enriquecido.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedFlow {
    /// Identificador canónico bidireccional, p. ej.
    /// `tcp/192.168.1.10:52000-93.184.216.34:443`.
    pub flow_id: FlowId,
    pub state: FlowState,
    pub transport: Transport,
    pub l7_protocol: L7Protocol,

    // ---- Extremos (orientados según el primer paquete observado) ----
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    /// MACs de origen/destino del primer paquete (si la captura es Ethernet).
    #[serde(default)]
    pub src_mac: Option<String>,
    #[serde(default)]
    pub dst_mac: Option<String>,

    // ---- Temporalidad y volumen ----
    /// Timestamp Unix en microsegundos del primer paquete.
    pub first_seen_micros: u64,
    pub last_seen_micros: u64,
    pub duration_micros: u64,
    /// Paquetes/bytes en dirección src→dst (contando cabeceras capturadas).
    pub packets: u64,
    pub bytes: u64,
    /// Paquetes/bytes en dirección dst→src.
    pub packets_rev: u64,
    pub bytes_rev: u64,
    pub tcp_flags: TcpFlagCounts,

    // ---- Enriquecimiento por eBPF (Fase 3; hoy siempre None) ----
    #[serde(default)]
    pub process_name: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub user: Option<String>,

    // ---- Enriquecimiento SOC ----
    /// Dominio resuelto para `dst_ip` vía DNS pasivo (o el qname si el flujo ES DNS).
    #[serde(default)]
    pub resolved_domain: Option<String>,
    /// Resumen del intercambio DNS si el flujo es DNS.
    #[serde(default)]
    pub dns: Option<DnsSummary>,
    /// Contexto geográfico/ASN del destino (threat intel — Fase 4; hoy None).
    #[serde(default)]
    pub dst_geo_asn: Option<String>,
    /// Huella JA4 del handshake TLS (Fase 3; hoy None).
    #[serde(default)]
    pub ja4_fingerprint: Option<String>,

    // ---- Capa semántica SOC ----
    /// True si es tráfico de fondo (mDNS, NTP, ...) que la UI debe atenuar.
    #[serde(default)]
    pub is_background_noise: bool,
    /// Traducción del flujo a lenguaje humano.
    pub human_summary: String,
    /// Puntuación de riesgo 0-100 calculada por heurísticas (ver `docs/soc-features.md`).
    pub risk_score: u8,
    #[serde(default)]
    pub alerts: Vec<Alert>,
    #[serde(default)]
    pub extracted_files: Vec<ExtractedFile>,
}

/// Nombre legible de un tipo de registro DNS (subconjunto Fase 1; el resto
/// se muestra como `TYPE<n>`).
pub fn dns_type_str(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        35 => "NAPTR".into(),
        41 => "OPT".into(),
        43 => "DS".into(),
        46 => "RRSIG".into(),
        48 => "DNSKEY".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

/// Nombre legible de un código RCODE DNS.
pub fn dns_rcode_str(rc: u8) -> &'static str {
    match rc {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "RCODE?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_desde_protocolo_ip() {
        assert_eq!(Transport::from_ip_proto(6), Transport::Tcp);
        assert_eq!(Transport::from_ip_proto(17), Transport::Udp);
        assert_eq!(Transport::from_ip_proto(1), Transport::Icmp);
        assert_eq!(Transport::from_ip_proto(132), Transport::Other(132));
    }

    #[test]
    fn severidad_es_ordenable_de_info_a_critical() {
        let mut sev = [
            Severity::High,
            Severity::Info,
            Severity::Critical,
            Severity::Low,
        ];
        sev.sort();
        assert_eq!(sev[0], Severity::Info);
        assert_eq!(sev[3], Severity::Critical);
    }

    #[test]
    fn nombres_legibles_de_tipos_dns() {
        assert_eq!(dns_type_str(1), "A");
        assert_eq!(dns_type_str(28), "AAAA");
        assert_eq!(dns_type_str(999), "TYPE999");
        assert_eq!(dns_rcode_str(3), "NXDOMAIN");
    }
}
