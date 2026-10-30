//! Motor de riesgo heurístico y generación de alertas (mini-IDS).
//!
//! Cada regla suma puntos a `risk_score` (0-100) y, al superar su umbral,
//! emite una [`Alert`] con su mapeo MITRE ATT&CK. La tabla completa de
//! reglas ↔ técnicas vive en `docs/soc-mitre-mapping.md`.
//!
//! Reglas Fase 1:
//! - `R1` Posible túnel DNS: subdominio largo, codificado y de entropía
//!   alta (ver [`dns_tunnel_suspect`]) → T1071.004 (C2 sobre DNS).
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
//!   Variante entre flujos ([`assess_interflow_beacon`]): misma prueba
//!   sobre los intervalos entre inicios de conexión al mismo servicio, para
//!   beacons lentos que el timeout de inactividad parte en flujos sueltos.
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

/// Técnica MITRE del túnel DNS: Application Layer Protocol: DNS (C2 y
/// exfiltración encapsulados en consultas DNS).
pub const MITRE_DNS_TUNNEL: &str = "T1071.004";

/// Longitud mínima de la etiqueta más larga del subdominio para sospechar
/// de datos codificados (base32/hex/base64 suelen ir en etiquetas de 30-63).
const TUNNEL_MIN_LABEL: usize = 24;
/// Etiqueta "muy larga": basta entropía alta aunque no mezcle dígitos
/// (base64 solo letras).
const TUNNEL_LONG_LABEL: usize = 32;
/// Subdominio total largo (varias etiquetas medianas: dnscat2, iodine).
const TUNNEL_MIN_SUBDOMAIN: usize = 48;
/// Margen sobre el umbral configurado para los casos sin mezcla
/// letra/dígito: el texto legible largo ronda 3.5-3.7 bits.
const TUNNEL_ENTROPY_MARGIN: f64 = 0.5;
/// Cambios letra↔dígito mínimos en la etiqueta: las codificaciones los
/// reparten por todo el texto; los nombres humanos agrupan los dígitos
/// ("balancer-1234567890").
const TUNNEL_MIN_TRANSITIONS: usize = 4;

/// Evidencias de un qname sospechoso de túnel DNS.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DnsTunnelEvidence {
    /// Caracteres del subdominio (sin el dominio registrable ni los puntos).
    pub subdomain_len: usize,
    /// Longitud de la etiqueta más larga del subdominio.
    pub label_len: usize,
    /// Entropía de la parte evaluada (etiqueta o subdominio completo).
    pub entropy: f64,
    /// Umbral efectivo que se superó.
    pub threshold: f64,
}

/// Cambios entre letra y dígito a lo largo de la etiqueta.
fn letter_digit_transitions(s: &str) -> usize {
    let b = s.as_bytes();
    b.windows(2)
        .filter(|w| {
            (w[0].is_ascii_alphabetic() && w[1].is_ascii_digit())
                || (w[0].is_ascii_digit() && w[1].is_ascii_alphabetic())
        })
        .count()
}

/// ¿Parece el qname un túnel DNS? La entropía se mide solo sobre la parte a
/// la izquierda del dominio registrable ([`crate::domain`]): el dominio de
/// la organización (`microsoft.com`, `cloudflare.net`) no aporta nada y
/// medirlo junto con varias etiquetas legibles cortas disparaba falsos
/// positivos (`settings-win.data.microsoft.com`).
///
/// Dispara si el qname completo alcanza `dns_tunnel_min_len` y además:
/// - la etiqueta más larga tiene ≥ 24 caracteres, entropía ≥ umbral y
///   mezcla letras y dígitos repartidos (base32/hex/base64), o
/// - la etiqueta tiene ≥ 32 caracteres y entropía ≥ umbral + 0.5, o
/// - el subdominio suma ≥ 48 caracteres con entropía ≥ umbral + 0.5.
pub fn dns_tunnel_suspect(qname: &str, cfg: &PipelineConfig) -> Option<DnsTunnelEvidence> {
    if qname.len() < cfg.dns_tunnel_min_len {
        return None;
    }
    let lower = qname.to_ascii_lowercase();
    let labels = crate::domain::subdomain_labels(&lower);
    let longest = labels.iter().copied().max_by_key(|l| l.len())?;
    let subdomain: String = labels.concat();
    let thr = cfg.dns_entropy_threshold;
    let high = thr + TUNNEL_ENTROPY_MARGIN;
    let ev = |entropy: f64, threshold: f64| DnsTunnelEvidence {
        subdomain_len: subdomain.len(),
        label_len: longest.len(),
        entropy,
        threshold,
    };

    let h_label = shannon_entropy(longest);
    if longest.len() >= TUNNEL_MIN_LABEL
        && h_label >= thr
        && letter_digit_transitions(longest) >= TUNNEL_MIN_TRANSITIONS
    {
        return Some(ev(h_label, thr));
    }
    if longest.len() >= TUNNEL_LONG_LABEL && h_label >= high {
        return Some(ev(h_label, high));
    }
    if subdomain.len() >= TUNNEL_MIN_SUBDOMAIN {
        let h_sub = shannon_entropy(&subdomain);
        if h_sub >= high {
            return Some(ev(h_sub, high));
        }
    }
    None
}

/// R5 entre flujos: si los inicios de conexión al servicio de `flow`
/// (origen, destino, puerto) son regulares según los mismos umbrales que
/// R5, añade la alerta `BEACONING` (+20 de riesgo). `stats` viene de
/// [`crate::beacon::FlowStartTracker::stats`]. Devuelve si alertó.
pub fn assess_interflow_beacon(
    flow: &mut EnrichedFlow,
    stats: &socshark_core::IntervalStats,
    cfg: &PipelineConfig,
) -> bool {
    let mean_secs = stats.mean_micros as f64 / 1_000_000.0;
    if stats.intervals < cfg.beacon_min_intervals
        || mean_secs < cfg.beacon_min_interval_secs as f64
        || mean_secs > cfg.beacon_max_interval_secs as f64
        || stats.cv() > cfg.beacon_max_cv
    {
        return false;
    }
    flow.risk_score = (u32::from(flow.risk_score) + 20).min(100) as u8;
    flow.alerts.push(Alert {
        id: "BEACONING".into(),
        name: "Comunicación periódica (beacon)".into(),
        severity: Severity::Medium,
        detail: format!(
            "intervalo medio {:.1}s con jitter ±{:.1}% en {} intervalos entre conexiones",
            mean_secs,
            100.0 * stats.cv(),
            stats.intervals
        ),
        mitre: Some("T1071".into()),
    });
    true
}

/// Evalúa todas las reglas sobre un flujo y rellena `risk_score` + `alerts`.
///
/// `scan` son las señales que el [`crate::ScanTracker`] acumuló para el
/// origen y destino de este flujo; se pasan desde `enrich_all` para que la
/// regla R2 funcione entre flujos.
pub fn assess(flow: &mut EnrichedFlow, scan: ScanSignals, cfg: &PipelineConfig) {
    assess_with_intel(flow, scan, cfg, None);
}

/// Como [`assess`], pero con la base de threat intel a mano para que R7
/// nombre el extremo realmente listado (puede ser el origen en una
/// conexión entrante). Sin base se asume el destino.
pub fn assess_with_intel(
    flow: &mut EnrichedFlow,
    scan: ScanSignals,
    cfg: &PipelineConfig,
    intel: Option<&crate::intel::ThreatIntelDb>,
) {
    let listed = |flow: &EnrichedFlow, tag: &str| {
        intel
            .and_then(|db| db.listed_endpoint(flow.src_ip, flow.dst_ip, tag))
            .unwrap_or(flow.dst_ip)
    };
    let mut score: u32 = 0;

    // R1: túnel DNS (C2/exfiltración por DNS) — MITRE T1071.004.
    if flow.l7_protocol == L7Protocol::Dns {
        if let Some(dns) = &flow.dns {
            for q in &dns.queries {
                if let Some(ev) = dns_tunnel_suspect(&q.name, cfg) {
                    score += 45;
                    flow.alerts.push(Alert {
                        id: "DNS-TUNNELING".into(),
                        name: "Posible túnel DNS".into(),
                        severity: Severity::High,
                        detail: format!(
                            "qname '{}': subdominio de {} caracteres codificado (etiqueta de {}, entropía {:.2} ≥ {:.2})",
                            q.name, ev.subdomain_len, ev.label_len, ev.entropy, ev.threshold
                        ),
                        mitre: Some(MITRE_DNS_TUNNEL.into()),
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
                listed(flow, crate::intel::TAG_FEODO)
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
                listed(flow, crate::intel::TAG_TOR)
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
        assert_eq!(tunel.alerts[0].mitre.as_deref(), Some("T1071.004"));
        assert!(tunel.risk_score >= 45);
    }

    #[test]
    fn nombres_legitimos_largos_no_son_tunel() {
        // Regresión: los tres primeros daban DNS-TUNNELING (+45) midiendo la
        // entropía sobre el qname completo.
        let cfg = PipelineConfig::default();
        for name in [
            "settings-win.data.microsoft.com",
            "self.events.data.microsoft.com",
            "fonts.googleapis.com.cdn.cloudflare.net",
            "www.ejemplo-corporativo.com",
            "my-load-balancer-1234567890.us-west-2.elb.amazonaws.com",
            "prod-eu-west-1-telemetry-collector.service.signalfx.com",
            "ec2-52-14-201-33.us-east-2.compute.amazonaws.com",
            "b.6.5.4.3.2.1.0.0.0.0.0.0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            "_ldap._tcp.dc._msdcs.corp.example.com",
        ] {
            assert!(dns_tunnel_suspect(name, &cfg).is_none(), "{name}");
            let mut f = flujo_basico(17, 53001, 53);
            f.l7_protocol = L7Protocol::Dns;
            f.dns = Some(qname_dns(name));
            assess(&mut f, ScanSignals::default(), &cfg);
            assert!(f.alerts.is_empty(), "{name}: {:?}", f.alerts);
        }
    }

    #[test]
    fn tuneles_codificados_si_alertan() {
        let cfg = PipelineConfig::default();
        for name in [
            // base64 en una etiqueta.
            "aGVsbG8gd29ybGQgdGhpcyBpcyBleGZpbA.evil.com",
            // base32 (estilo iodine / dnscat).
            "ieqh746yng7by3a4rogubbbayn3bo47owoo5sb2glshv3mts7z.t.evil.com",
            "kcymwgn3m7gys7buzsbkmuiv3nrg.evil.com",
            "paaaaaab1y7jw641rifxipeucfikk6inrwvmg1qxvvhsp38mx9t4filjxg.t.iodine.evil.org",
            // hex (dnscat2) en dos etiquetas.
            "1f7cd5bb2e35cbf0f19c557067cbbe80c46d1fb6dfbdb0ae0755281220e0.3fa9c01d.dnscat.evil.com",
            "0c415ed7e70cad19461922995d84016e.evil.com",
            // Sufijo de dos niveles: el registrable es evil.co.uk.
            "uc2eyjivhyeofrxsh5rgcsaaf2hcmp.2kh4kpkg3ysq6ugnucbasu4zuzeeu.evil.co.uk",
        ] {
            assert!(dns_tunnel_suspect(name, &cfg).is_some(), "{name}");
        }
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
