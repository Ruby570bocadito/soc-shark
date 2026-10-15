//! Tipos compartidos del dominio SOC: alertas, severidad y artefactos.
//!
//! Viven en `common` porque los produce `soc-engine`, los consume
//! `flow-aggregator` (campo `EnrichedFlow::alerts`) y los serializan tanto el
//! daemon (informe/ECS) como las futuras UIs.

use crate::json::Json;

/// Severidad de una alerta SOC; ordena de menor a mayor gravedad.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    /// Peso que aporta al `risk_score` (0–100) del flujo.
    pub fn weight(&self) -> u8 {
        match self {
            Severity::Low => 5,
            Severity::Medium => 15,
            Severity::High => 30,
            Severity::Critical => 45,
        }
    }

    /// Etiqueta legible en español para la terminal.
    pub fn label_es(&self) -> &'static str {
        match self {
            Severity::Low => "BAJA",
            Severity::Medium => "MEDIA",
            Severity::High => "ALTA",
            Severity::Critical => "CRÍTICA",
        }
    }
}

/// Alerta generada por los detectores de `soc-engine`.
#[derive(Debug, Clone)]
pub struct SocAlert {
    /// Identificador estable del detector, ej. `"C2-BEACON"`.
    pub id: &'static str,
    pub severity: Severity,
    /// Título corto legible, ej. `"Beaconing C2 (HTTP POST cada 10.0s)"`.
    pub title: String,
    /// Detalle con evidencia técnica para el analista.
    pub detail: String,
    /// Técnica MITRE ATT&CK indicativa, ej. `Some("T1071.001")`.
    pub mitre: Option<&'static str>,
    /// Evidencia adicional opcional (hash, dominio, contador...).
    pub evidence: Option<String>,
}

impl SocAlert {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("id", Json::s(self.id)),
            ("severity", Json::s(self.severity.as_str())),
            ("title", Json::s(self.title.clone())),
            ("detail", Json::s(self.detail.clone())),
            (
                "mitre",
                match self.mitre {
                    Some(m) => Json::s(m),
                    None => Json::Null,
                },
            ),
            (
                "evidence",
                match &self.evidence {
                    Some(e) => Json::s(e.clone()),
                    None => Json::Null,
                },
            ),
        ])
    }
}

/// Archivo reconstruido al vuelo desde un flujo (Live File Carving).
#[derive(Debug, Clone)]
pub struct Artifact {
    /// Nombre inferido (URI HTTP, nombre SMB...).
    pub name: String,
    pub size: u64,
    /// SHA-256 completo en hexadecimal.
    pub sha256: String,
    /// Magic bytes reales detectados, ej. `"MZ"`, `"ELF"`, `"PDF"`.
    pub magic: &'static str,
    /// ¿La extensión del nombre no coincide con los magic bytes? (Masquerading)
    pub masquerade: bool,
    /// Origen del carving, ej. `"HTTP"`.
    pub source: &'static str,
}

impl Artifact {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("name", Json::s(self.name.clone())),
            ("size", Json::Int(self.size as i64)),
            ("sha256", Json::s(self.sha256.clone())),
            ("magic", Json::s(self.magic)),
            ("masquerade", Json::Bool(self.masquerade)),
            ("source", Json::s(self.source)),
        ])
    }
}

/// Puntuación de riesgo 0–100 a partir de las alertas del flujo.
pub fn risk_score(alerts: &[SocAlert]) -> u8 {
    alerts
        .iter()
        .map(|a| a.severity.weight() as u32)
        .sum::<u32>()
        .min(100) as u8
}
