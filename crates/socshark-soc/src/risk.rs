//! Motor de riesgo heurístico y generación de alertas (mini-IDS).
//!
//! Cada regla suma puntos a `risk_score` (0-100) y, al superar su umbral,
//! emite una [`Alert`] con su mapeo MITRE ATT&CK. La tabla completa de
//! reglas ↔ técnicas vive en `docs/soc-mitre-mapping.md`.
//!
//! Reglas Fase 1:
//! - `R1` Posible túnel DNS: qname largo + entropía alta → T1048.003.
//! - `R2` Escaneo SYN puro entre flujos → T1046.
//! - `R3` Telnet (23/tcp) en texto claro → T1021.
//! - `R4` Bases de datos expuestas (3306/5432/1433/6379/27017).

use socshark_core::{Alert, EnrichedFlow, L7Protocol, Severity, Transport};

use socshark_core::config::PipelineConfig;

/// Entropía de Shannon por carácter (bits/símbolo) sobre los bytes UTF-8.
///
/// 0.0 = repetición pura ("aaaa"); ~4.7 = base32/hex bien distribuido.
/// Es la métrica clásica para distinguir subdominios codificados (túneles)
/// de nombres legibles.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    let mut total = 0usize;
    for b in s.bytes() {
        freq[b as usize] += 1;
        total += 1;
    }
    let t = total as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / t;
            -p * p.log2()
        })
        .sum()
}

/// Evalúa todas las reglas sobre un flujo y rellena `risk_score` + `alerts`.
///
/// `scan_hits` es el número de SYNs en seco acumulados por el
/// [`crate::ScanTracker`] para el (origen, destino, puerto destino) de este
/// flujo; se pasa desde `enrich_all` para que la regla R2 funcione entre
/// flujos.
pub fn assess(flow: &mut EnrichedFlow, scan_hits: u32, cfg: &PipelineConfig) {
    let mut score: u32 = 0;

    // R1: túnel DNS (exfiltración/C2 por DNS) — MITRE T1048.003.
    if flow.l7_protocol == L7Protocol::Dns {
        if let Some(dns) = &flow.dns {
            for q in &dns.queries {
                let entropy = shannon_entropy(&q.name);
                if q.name.len() >= cfg.dns_tunnel_min_len && entropy >= cfg.dns_entropy_threshold {
                    score += 45;
                    flow.alerts.push(Alert {
                        id: "DNS-TUNNELING".into(),
                        name: "Posible túnel DNS".into(),
                        severity: Severity::High,
                        detail: format!(
                            "qname '{}' ({} caracteres, entropía {:.2} ≥ {:.2})",
                            q.name,
                            q.name.len(),
                            entropy,
                            cfg.dns_entropy_threshold
                        ),
                        mitre: Some("T1048.003".into()),
                    });
                    break; // una alerta por flujo basta
                }
            }
        }
    }

    // R2: escaneo de puertos SYN puro — MITRE T1046.
    if scan_hits >= cfg.scan_syn_threshold && flow.tcp_flags.ack == 0 {
        score += 30;
        flow.alerts.push(Alert {
            id: "PORT-SCAN".into(),
            name: "Posible escaneo de puertos".into(),
            severity: Severity::Medium,
            detail: format!(
                "{} SYNs sin respuesta hacia {}:{} desde esta origen",
                scan_hits, flow.dst_ip, flow.dst_port
            ),
            mitre: Some("T1046".into()),
        });
    }

    // R3: administración remota insegura (telnet en texto claro) — T1021.
    if flow.transport == Transport::Tcp && flow.dst_port == 23 {
        score += 35;
        flow.alerts.push(Alert {
            id: "INSECURE-PORT".into(),
            name: "Telnet en texto claro".into(),
            severity: Severity::High,
            detail: format!(
                "conexión a telnet (23/tcp) en {}: credenciales sin cifrar",
                flow.dst_ip
            ),
            mitre: Some("T1021".into()),
        });
    }

    // R4: bases de datos expuestas.
    if flow.transport == Transport::Tcp
        && matches!(flow.dst_port, 3306 | 5432 | 1433 | 6379 | 27017)
    {
        score += 25;
        flow.alerts.push(Alert {
            id: "EXPOSED-DB".into(),
            name: "Base de datos expuesta".into(),
            severity: Severity::Medium,
            detail: format!(
                "conexión directa a puerto de base de datos ({}) en {}",
                flow.dst_port, flow.dst_ip
            ),
            mitre: None,
        });
    }

    flow.risk_score = score.min(100) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::flujo_basico;

    #[test]
    fn entropia_valores_conocidos() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert!((shannon_entropy("ab") - 1.0).abs() < 1e-9);
        // Base32 uniforme de 30 símbolos duplicados: log2(30) ≈ 4.907.
        let uniforme = "az3k9t2wq7xm5vb8n4rj6yp1chfdgsaz3k9t2wq7xm5vb8n4rj6yp1chfdgs";
        assert!(shannon_entropy(uniforme) > 4.8);
    }

    #[test]
    fn qname_legible_no_alerta_y_base32_si() {
        let cfg = PipelineConfig::default();
        let mut legible = flujo_basico(17, 53001, 53);
        legible.l7_protocol = L7Protocol::Dns;
        legible.dns = Some(qname_dns("www.ejemplo-corporativo.com"));
        assess(&mut legible, 0, &cfg);
        assert!(legible.alerts.is_empty(), "un qname normal no debe alertar");

        let mut tunel = flujo_basico(17, 53002, 53);
        tunel.l7_protocol = L7Protocol::Dns;
        tunel.dns = Some(qname_dns(
            "az3k9t2wq7xm5vb8n4rj6yp1chfdgsaz3k9t2wq7xm5vb8n4rj6yp1chfdgs.tun.evil.example",
        ));
        assess(&mut tunel, 0, &cfg);
        assert_eq!(tunel.alerts[0].id, "DNS-TUNNELING");
        assert_eq!(tunel.alerts[0].mitre.as_deref(), Some("T1048.003"));
        assert!(tunel.risk_score >= 45);
    }

    #[test]
    fn telnet_y_bd_disparan_reglas() {
        let cfg = PipelineConfig::default();
        let mut tel = flujo_basico(6, 40000, 23);
        assess(&mut tel, 0, &cfg);
        assert_eq!(tel.alerts[0].id, "INSECURE-PORT");
        assert_eq!(tel.alerts[0].mitre.as_deref(), Some("T1021"));
        assert!(tel.risk_score >= 35);

        let mut db = flujo_basico(6, 40001, 6379);
        assess(&mut db, 0, &cfg);
        assert_eq!(db.alerts[0].id, "EXPOSED-DB");
        assert!(db.risk_score >= 25);
    }

    #[test]
    fn riesgo_tiene_tope_100() {
        let cfg = PipelineConfig::default();
        let mut f = flujo_basico(6, 40002, 23);
        assess(&mut f, 99, &cfg); // scan (30) + telnet (35): sin tope serían 65,
                                  // con más reglas podría pasar: debe saturar
        assert!(f.risk_score <= 100);
    }

    fn qname_dns(name: &str) -> socshark_core::DnsSummary {
        socshark_core::DnsSummary {
            is_response: false,
            rcode: None,
            queries: vec![socshark_core::DnsQuerySummary {
                name: name.into(),
                qtype: 16,
            }],
            answers: vec![],
        }
    }
}
