//! Composición de reglas de detección por flujo + mapeo MITRE ATT&CK.
//!
//! Fase 1: heurísticas propias (`anomaly_detector`, `file_carver`).
//! Fase 3: carga de reglas Sigma/Suricata simplificadas sobre el mismo
//! motor de evaluación del `filter-dsl` (ver docs/06-soc-engine.md).

use crate::anomaly_detector;
use socshark_common::soc_types::Artifact;
use socshark_common::soc_types::{Severity, SocAlert};
use socshark_flow_aggregator::model::EnrichedFlow;

/// Reglas por-flujo puras (sin estado global).
pub fn apply_flow_rules(flow: &EnrichedFlow) -> Vec<SocAlert> {
    let mut out = Vec::new();
    // Port mismatch (HTTP/TLS/DNS en puertos raros); se respeta el ruido de
    // fondo: mDNS en 5353 no es una anomalía.
    if !flow.is_background_noise {
        if let Some(a) = anomaly_detector::port_mismatch_alert(flow) {
            out.push(a);
        }
    }
    // TLS sin SNI hacia IPs externas: escaneos y malware.
    if flow.l7_protocol == "TLS" && flow.tls_sni.is_none() && flow.key.dst.is_global_candidate() {
        out.push(SocAlert {
            id: "TLS-NO-SNI",
            severity: Severity::Low,
            title: format!("TLS sin SNI hacia {}", flow.key.dst),
            detail: "Un ClientHello sin SNI hacia una IP externa es típico de \
                     escaneos automatizados, malware con IPs hardcodeadas o \
                     bibliotecas no estándar."
                .into(),
            mitre: Some("T1071"),
            evidence: flow.ja4_fingerprint.clone(),
        });
    }
    out
}

/// Alertas asociadas a artefactos extraídos (por archivo).
pub fn artifact_alerts(art: &Artifact) -> Vec<SocAlert> {
    let mut out = Vec::new();
    if matches!(art.magic, "MZ" | "ELF") {
        out.push(SocAlert {
            id: "EXE-TRANSFER",
            severity: Severity::High,
            title: format!("Ejecutable extraído por {}: {}", art.source, art.name),
            detail: format!(
                "Archivo de {} bytes con magic {} reconstruido del tráfico. \
                 SHA-256: {}. Verifícalo en VirusTotal / sandbox.",
                art.size, art.magic, art.sha256
            ),
            mitre: Some("T1105"),
            evidence: Some(art.sha256.clone()),
        });
    }
    if art.masquerade {
        out.push(SocAlert {
            id: "MASQUERADE",
            severity: Severity::High,
            title: format!("Masquerading: {} no es lo que dice ser", art.name),
            detail: format!(
                "El nombre sugiere una extensión distinta del magic real ({}). \
                 Técnica T1036: disfrazar ejecutables como documentos/inágenes.",
                art.magic
            ),
            mitre: Some("T1036"),
            evidence: Some(art.sha256.clone()),
        });
    }
    out
}
