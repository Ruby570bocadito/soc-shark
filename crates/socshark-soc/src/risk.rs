//! Motor de riesgo heurístico y generación de alertas (mini-IDS).
//!
//! Cada regla suma puntos a `risk_score` (0-100) y, al superar su umbral,
//! emite una [`Alert`] con su mapeo MITRE ATT&CK. La tabla completa de
//! reglas ↔ técnicas vive en `docs/soc-mitre-mapping.md`.
//!
//! Reglas Fase 1:
//! - `R1` Posible túnel DNS: qname largo + entropía alta → T1048.003.
//! - `R2` Escaneo sobre intentos de conexión fallidos entre flujos:
//!   vertical (muchos puertos de un host, `PORT-SCAN`) y horizontal (un
//!   puerto en muchos hosts, `NETWORK-SWEEP`) → T1046. Si no llega a
//!   escaneo, los reintentos al mismo servicio dan un aviso de severidad
//!   baja (`REPEATED-ATTEMPTS`, sin técnica).
//! - `R3` Telnet (23/tcp) en texto claro → T1021.
//! - `R4` Bases de datos expuestas (3306/5432/1433/6379/27017).
//!
//! R3 y R4 exigen que la conexión no sea una sonda fallida: un SYN sin
//! respuesta al 23 durante un escaneo no transporta credenciales.
//!
//! Reglas Fase 3:
//! - `R5` Beaconing por regularidad de intervalos → T1071: los intervalos
//!   entre paquetes del iniciador (ver `IntervalStats`) son demasiado
//!   regulares para tráfico humano y caen en la ventana típica de un
//!   malware que "llama a casa" con un sleep programado.
//!
//! Reglas Fase 4:
//! - `R6` Encubrimiento de archivos transferidos por HTTP (magic ≠ extensión
//!   o doble extensión ejecutable) → T1036. Un ejecutable bajado sin
//!   encubrimiento también suma riesgo (sin alerta propia).
//! - `R7` Destino en listas de threat intel offline: C2 de Feodo → T1071.001
//!   y nodos de salida de Tor → T1090.003 (proxy multi-salto).

use socshark_core::{Alert, EnrichedFlow, L7Protocol, Severity, Transport};

use socshark_core::config::PipelineConfig;

use crate::{is_failed_connect, ScanSignals};

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
/// `scan` son las señales que el [`crate::ScanTracker`] acumuló para el
/// origen y destino de este flujo; se pasan desde `enrich_all` para que la
/// regla R2 funcione entre flujos.
pub fn assess(flow: &mut EnrichedFlow, scan: ScanSignals, cfg: &PipelineConfig) {
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

    // R2: escaneo y barrido de red — MITRE T1046. Solo sobre sondas: el
    // flujo de un escáner nunca llega a establecerse.
    let failed = is_failed_connect(flow);
    if failed {
        let vertical = scan.distinct_ports >= cfg.scan_port_threshold;
        let horizontal = scan.distinct_hosts >= cfg.scan_host_threshold;
        if vertical {
            flow.alerts.push(Alert {
                id: "PORT-SCAN".into(),
                name: "Posible escaneo de puertos".into(),
                severity: Severity::Medium,
                detail: format!(
                    "{} probó {} puertos distintos de {} sin establecer conexión",
                    flow.src_ip, scan.distinct_ports, flow.dst_ip
                ),
                mitre: Some("T1046".into()),
            });
        }
        if horizontal {
            flow.alerts.push(Alert {
                id: "NETWORK-SWEEP".into(),
                name: "Posible barrido de red".into(),
                severity: Severity::Medium,
                detail: format!(
                    "{} probó el puerto {} en {} hosts distintos sin establecer conexión",
                    flow.src_ip, flow.dst_port, scan.distinct_hosts
                ),
                mitre: Some("T1046".into()),
            });
        }
        if vertical || horizontal {
            score += 30;
        } else if scan.attempts >= cfg.repeated_attempt_threshold {
            score += 10;
            flow.alerts.push(Alert {
                id: "REPEATED-ATTEMPTS".into(),
                name: "Intentos de conexión repetidos".into(),
                severity: Severity::Low,
                detail: format!(
                    "{} intentos de {} a {}:{} sin llegar a establecer conexión",
                    scan.attempts, flow.src_ip, flow.dst_ip, flow.dst_port
                ),
                mitre: None,
            });
        }
    }

    // R3: administración remota insegura (telnet en texto claro) — T1021.
    if flow.transport == Transport::Tcp && flow.dst_port == 23 && !failed {
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
        && !failed
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

    // R5: beaconing por regularidad de intervalos — MITRE T1071.
    // Solo tráfico no-ruido (NTP/mDNS son regulares por diseño) y con los
    // umbrales configurables: ventana de intervalo y regularidad (CV).
    if !flow.is_background_noise {
        if let Some(stats) = &flow.interval_stats {
            let mean_secs = stats.mean_micros as f64 / 1_000_000.0;
            if stats.intervals >= cfg.beacon_min_intervals
                && mean_secs >= cfg.beacon_min_interval_secs as f64
                && mean_secs <= cfg.beacon_max_interval_secs as f64
                && stats.cv() <= cfg.beacon_max_cv
            {
                score += 20;
                let jitter_pct = 100.0 * stats.cv();
                flow.alerts.push(Alert {
                    id: "BEACONING".into(),
                    name: "Comunicación periódica (beacon)".into(),
                    severity: Severity::Medium,
                    detail: format!(
                        "intervalo medio {:.1}s con jitter ±{:.1}% en {} intervalos",
                        mean_secs, jitter_pct, stats.intervals
                    ),
                    mitre: Some("T1071".into()),
                });
            }
        }
    }

    // R6: encubrimiento de archivos transferidos — MITRE T1036. Basta con
    // que UN archivo del flujo sea sospechoso para alertar (se listan todos).
    let mut ejecutables: Vec<&str> = Vec::new();
    let mut encubiertos: Vec<&str> = Vec::new();
    for f in &flow.extracted_files {
        if matches!(
            f.magic.as_deref(),
            Some("PE32") | Some("ELF") | Some("Mach-O")
        ) {
            ejecutables.push(&f.name);
        }
        if f.masquerading_suspect {
            encubiertos.push(&f.name);
        }
    }
    if !ejecutables.is_empty() {
        // Descarga de ejecutable sin encubrir: riesgo, no alerta (es
        // operación normal de distribución de software).
        score += 15;
    }
    if !encubiertos.is_empty() {
        score += 40;
        flow.alerts.push(Alert {
            id: "FILE-MASQUERADING".into(),
            name: "Archivo transferido con identidad falseada".into(),
            severity: Severity::High,
            detail: format!(
                "tipo real ≠ extensión declarada en {}",
                encubiertos.join(", ")
            ),
            mitre: Some("T1036".into()),
        });
    }

    // R7: destino en listas de threat intel offline — MITRE T1071.001 (C2
    // conocido de Feodo) y T1090.003 (salida Tor = proxy multi-salto).
    if flow
        .threat_intel
        .iter()
        .any(|t| t == crate::intel::TAG_FEODO)
    {
        score += 45;
        flow.alerts.push(Alert {
            id: "THREAT-INTEL-FEODO".into(),
            name: "Destino en lista de C2 (Feodo)".into(),
            severity: Severity::High,
            detail: format!(
                "{} aparece en la lista Feodo cargada (--intel-feodo)",
                flow.dst_ip
            ),
            mitre: Some("T1071.001".into()),
        });
    }
    if flow.threat_intel.iter().any(|t| t == crate::intel::TAG_TOR) {
        score += 20;
        flow.alerts.push(Alert {
            id: "TOR-USAGE".into(),
            name: "Conexión a nodo de salida de Tor".into(),
            severity: Severity::Medium,
            detail: format!(
                "{} es un nodo de salida de Tor (lista --intel-tor): posible proxy multi-salto",
                flow.dst_ip
            ),
            mitre: Some("T1090.003".into()),
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
        assess(&mut legible, ScanSignals::default(), &cfg);
        assert!(legible.alerts.is_empty(), "un qname normal no debe alertar");

        let mut tunel = flujo_basico(17, 53002, 53);
        tunel.l7_protocol = L7Protocol::Dns;
        tunel.dns = Some(qname_dns(
            "az3k9t2wq7xm5vb8n4rj6yp1chfdgsaz3k9t2wq7xm5vb8n4rj6yp1chfdgs.tun.evil.example",
        ));
        assess(&mut tunel, ScanSignals::default(), &cfg);
        assert_eq!(tunel.alerts[0].id, "DNS-TUNNELING");
        assert_eq!(tunel.alerts[0].mitre.as_deref(), Some("T1048.003"));
        assert!(tunel.risk_score >= 45);
    }

    #[test]
    fn telnet_y_bd_disparan_reglas() {
        let cfg = PipelineConfig::default();
        let mut tel = flujo_basico(6, 40000, 23);
        assess(&mut tel, ScanSignals::default(), &cfg);
        assert_eq!(tel.alerts[0].id, "INSECURE-PORT");
        assert_eq!(tel.alerts[0].mitre.as_deref(), Some("T1021"));
        assert!(tel.risk_score >= 35);

        let mut db = flujo_basico(6, 40001, 6379);
        assess(&mut db, ScanSignals::default(), &cfg);
        assert_eq!(db.alerts[0].id, "EXPOSED-DB");
        assert!(db.risk_score >= 25);
    }

    fn sonda(dport: u16) -> EnrichedFlow {
        let mut f = flujo_basico(6, 40000, dport);
        f.tcp_flags.syn = 1;
        f
    }

    #[test]
    fn sonda_fallida_a_telnet_o_bd_no_alerta_r3_r4() {
        let cfg = PipelineConfig::default();
        for port in [23, 3306] {
            let mut f = sonda(port);
            assess(&mut f, ScanSignals::default(), &cfg);
            assert!(
                f.alerts.is_empty(),
                "SYN sin respuesta a {port}: {:?}",
                f.alerts
            );
            assert_eq!(f.risk_score, 0);
        }
    }

    #[test]
    fn r2_escaneo_vertical_horizontal_y_reintentos() {
        let cfg = PipelineConfig::default();
        let ids = |s: ScanSignals| {
            let mut f = sonda(22);
            assess(&mut f, s, &cfg);
            let ids: Vec<String> = f.alerts.iter().map(|a| a.id.clone()).collect();
            (ids, f.risk_score)
        };

        let (v, score) = ids(ScanSignals {
            distinct_ports: cfg.scan_port_threshold,
            ..Default::default()
        });
        assert_eq!(v, ["PORT-SCAN"]);
        assert_eq!(score, 30);

        let (h, _) = ids(ScanSignals {
            distinct_hosts: cfg.scan_host_threshold,
            ..Default::default()
        });
        assert_eq!(h, ["NETWORK-SWEEP"]);

        // Vertical y horizontal a la vez: dos alertas, el riesgo suma una vez.
        let (ambos, score) = ids(ScanSignals {
            distinct_ports: 99,
            distinct_hosts: 99,
            attempts: 99,
        });
        assert_eq!(ambos, ["PORT-SCAN", "NETWORK-SWEEP"]);
        assert_eq!(score, 30);

        // Reintentos al mismo servicio sin variedad de puertos/hosts.
        let (r, score) = ids(ScanSignals {
            distinct_ports: 1,
            distinct_hosts: 1,
            attempts: cfg.repeated_attempt_threshold,
        });
        assert_eq!(r, ["REPEATED-ATTEMPTS"]);
        assert_eq!(score, 10);

        // Por debajo de todos los umbrales: nada.
        let (nada, _) = ids(ScanSignals {
            distinct_ports: cfg.scan_port_threshold - 1,
            distinct_hosts: cfg.scan_host_threshold - 1,
            attempts: cfg.repeated_attempt_threshold - 1,
        });
        assert!(nada.is_empty());

        // Una conexión establecida nunca es escaneo, aunque el origen escanee.
        let mut ok = flujo_basico(6, 40000, 22);
        ok.tcp_flags.syn = 2;
        ok.tcp_flags.ack = 5;
        ok.tcp_flags.psh = 2;
        assess(
            &mut ok,
            ScanSignals {
                distinct_ports: 99,
                distinct_hosts: 99,
                attempts: 99,
            },
            &cfg,
        );
        assert!(ok.alerts.is_empty());
    }

    #[test]
    fn riesgo_tiene_tope_100() {
        let cfg = PipelineConfig::default();
        let mut f = flujo_basico(6, 40002, 23);
        f.threat_intel = vec![
            crate::intel::TAG_FEODO.to_string(),
            crate::intel::TAG_TOR.to_string(),
        ];
        f.extracted_files = vec![socshark_core::ExtractedFile {
            name: "factura.jpg".into(),
            size: 1,
            sha256: None,
            magic: Some("PE32".into()),
            masquerading_suspect: true,
        }];
        // telnet 35 + Feodo 45 + Tor 20 + PE 15 + encubrimiento 40 = 155.
        assess(&mut f, ScanSignals::default(), &cfg);
        assert_eq!(f.risk_score, 100);
    }

    #[test]
    fn beacon_regular_de_30s_alerta_con_periodo_estimado() {
        let cfg = PipelineConfig::default();
        let mut f = flujo_basico(6, 45000, 8080);
        // Beacon perfecto: 9 intervalos de 30 s → media 30.0 s, CV 0.
        f.interval_stats = Some(socshark_core::IntervalStats {
            intervals: 9,
            mean_micros: 30_000_000,
            std_micros: 200_000, // ±0.67%: jitter de reloj realista
        });
        assess(&mut f, ScanSignals::default(), &cfg);
        let alert = f
            .alerts
            .iter()
            .find(|a| a.id == "BEACONING")
            .expect("el beacon regular debe alertar");
        assert_eq!(alert.mitre.as_deref(), Some("T1071"));
        assert!(alert.detail.contains("30.0s"), "detalle: {}", alert.detail);
        assert!(f.risk_score >= 20);
    }

    #[test]
    fn trafico_humano_y_mantenimiento_no_alertan_beacon() {
        let cfg = PipelineConfig::default();

        // Intervalos irregulares (navegación humana): CV alto.
        let mut humano = flujo_basico(6, 45001, 443);
        humano.interval_stats = Some(socshark_core::IntervalStats {
            intervals: 12,
            mean_micros: 12_000_000,
            std_micros: 9_000_000, // CV 0.75
        });
        assess(&mut humano, ScanSignals::default(), &cfg);
        assert!(!humano.alerts.iter().any(|a| a.id == "BEACONING"));

        // NTP (ruido de fondo): regular por diseño pero marcado como ruido.
        let mut ntp = flujo_basico(17, 123, 123);
        ntp.is_background_noise = true;
        ntp.interval_stats = Some(socshark_core::IntervalStats {
            intervals: 20,
            mean_micros: 1_024_000_000, // poll NTP típico (17 min): fuera de ventana
            std_micros: 1_000,
        });
        assess(&mut ntp, ScanSignals::default(), &cfg);
        assert!(!ntp.alerts.iter().any(|a| a.id == "BEACONING"));

        // Intervalo por debajo del mínimo (retransmisiones/push interactivo).
        let mut rapido = flujo_basico(6, 45002, 443);
        rapido.interval_stats = Some(socshark_core::IntervalStats {
            intervals: 10,
            mean_micros: 50_000, // 50 ms
            std_micros: 100,
        });
        assess(&mut rapido, ScanSignals::default(), &cfg);
        assert!(!rapido.alerts.iter().any(|a| a.id == "BEACONING"));
    }

    #[test]
    fn r6_pe_llamado_jpg_alerta_t1036_y_pe_honesto_solo_riesgo() {
        let cfg = PipelineConfig::default();

        // Encubierto: factura.jpg que en realidad es un PE → alerta alta.
        let mut encubierto = flujo_basico(6, 46000, 80);
        encubierto.extracted_files = vec![socshark_core::ExtractedFile {
            name: "factura.jpg".into(),
            size: 2048,
            sha256: Some("ab".repeat(32)),
            magic: Some("PE32".into()),
            masquerading_suspect: true,
        }];
        assess(&mut encubierto, ScanSignals::default(), &cfg);
        let alert = encubierto
            .alerts
            .iter()
            .find(|a| a.id == "FILE-MASQUERADING")
            .expect("el encubrimiento debe alertar");
        assert_eq!(alert.mitre.as_deref(), Some("T1036"));
        assert_eq!(alert.severity, Severity::High);
        assert!(alert.detail.contains("factura.jpg"));
        assert!(
            encubierto.risk_score >= 55,
            "40 (encubrimiento) + 15 (PE): {}",
            encubierto.risk_score
        );

        // Honesto: setup.exe que ES un PE → riesgo sin alerta FILE-*.
        let mut honesto = flujo_basico(6, 46001, 80);
        honesto.extracted_files = vec![socshark_core::ExtractedFile {
            name: "setup.exe".into(),
            size: 1024,
            sha256: None,
            magic: Some("PE32".into()),
            masquerading_suspect: false,
        }];
        assess(&mut honesto, ScanSignals::default(), &cfg);
        assert!(!honesto.alerts.iter().any(|a| a.id == "FILE-MASQUERADING"));
        assert_eq!(
            honesto.risk_score, 15,
            "solo la descarga de ejecutable suma"
        );
    }

    #[test]
    fn r7_listas_intel_disparan_feodo_y_tor() {
        let cfg = PipelineConfig::default();

        let mut c2 = flujo_basico(6, 47000, 8080);
        c2.threat_intel = vec![crate::intel::TAG_FEODO.to_string()];
        assess(&mut c2, ScanSignals::default(), &cfg);
        let alert = c2
            .alerts
            .iter()
            .find(|a| a.id == "THREAT-INTEL-FEODO")
            .expect("Feodo debe alertar");
        assert_eq!(alert.mitre.as_deref(), Some("T1071.001"));
        assert_eq!(alert.severity, Severity::High);
        assert!(c2.risk_score >= 45);

        let mut tor = flujo_basico(6, 47001, 9001);
        tor.threat_intel = vec![crate::intel::TAG_TOR.to_string()];
        assess(&mut tor, ScanSignals::default(), &cfg);
        let alert = tor
            .alerts
            .iter()
            .find(|a| a.id == "TOR-USAGE")
            .expect("Tor debe alertar");
        assert_eq!(alert.mitre.as_deref(), Some("T1090.003"));
        assert_eq!(tor.risk_score, 20);

        // Sin etiquetas no hay alertas R7 (camino por defecto).
        let mut limpio = flujo_basico(6, 47002, 443);
        assess(&mut limpio, ScanSignals::default(), &cfg);
        assert!(!limpio
            .alerts
            .iter()
            .any(|a| a.id.starts_with("THREAT-INTEL") || a.id == "TOR-USAGE"));
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
