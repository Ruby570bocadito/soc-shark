//! Motor de riesgo heurístico y generación de alertas (mini-IDS).
//!
//! Cada regla suma puntos a `risk_score` (0-100) y, al superar su umbral,
//! emite una [`Alert`] con su mapeo MITRE ATT&CK. La tabla completa de
//! reglas ↔ técnicas vive en `docs/soc-mitre-mapping.md`.
//!
//! Reglas Fase 1:
//! - `R1` Posible túnel DNS: subdominio largo, codificado y de entropía
//!   alta (ver [`dns_tunnel_suspect`]) → T1071.004 (C2 sobre DNS).
//!   Variante por volumen ([`assess_dns_volume`]): un cliente consulta
//!   demasiados subdominios únicos de un mismo dominio en poco tiempo
//!   (túneles de baja entropía; ver [`crate::dns_volume`]).
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
//!   Variante con jitter (severidad baja, +10): si la prueba estricta no
//!   pasa, una prueba tolerante a jitter aleatorio uniforme (Cobalt Strike
//!   `jitter` 30-50%) sobre la misma serie: mediana + MAD sobre los
//!   intervalos crudos entre conexiones ([`jittered_beacon`]) y CV ≤ 0.30
//!   dentro del flujo (allí solo hay media y desviación). Nunca se emiten
//!   las dos: la estricta gana.
//!
//! Reglas Fase 4:
//! - `R6` Encubrimiento de archivos transferidos por HTTP (magic ≠ extensión
//!   o doble extensión ejecutable) → T1036. Un ejecutable bajado sin
//!   encubrimiento también suma riesgo (sin alerta propia).
//! - `R7` Destino en listas de threat intel offline: C2 de Feodo → T1071.001
//!   y nodos de salida de Tor → T1090.003 (proxy multi-salto).

use socshark_core::{Alert, EnrichedFlow, L7Protocol, Severity, Transport};

use socshark_core::config::PipelineConfig;

use crate::{is_failed_connect, Lang, ScanSignals};

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

/// ¿Habla el equipo consigo mismo? Misma dirección en los dos extremos o
/// loopback. Ese tráfico no sale a la red: una base de datos o un Telnet que
/// solo se usan así no están expuestos, y nadie de la red puede leer sus
/// credenciales. Falso positivo medio real del corpus: las sesiones de MySQL
/// (192.168.0.254 consigo mismo) y PostgreSQL (127.0.0.1) del wiki de
/// Wireshark saltaban como «base de datos expuesta».
pub fn same_host(flow: &EnrichedFlow) -> bool {
    flow.src_ip == flow.dst_ip || flow.src_ip.is_loopback() || flow.dst_ip.is_loopback()
}

/// Non-Standard Port: un protocolo en un puerto que no le corresponde
/// (aquí, cualquier cosa que no sea DNS en el 53).
pub const MITRE_NON_STANDARD_PORT: &str = "T1571";

/// R8: ¿usa el flujo el puerto 53 sin hablar DNS? Devuelve el detalle de la
/// alerta.
///
/// Los cortafuegos dejan pasar el 53 para que funcione el DNS, así que meter
/// ahí otra cosa (una shell remota, una VPN, un programa de control a
/// distancia) es un truco clásico para saltárselos. El caso real del corpus
/// es una shell de `cmd.exe` escuchando en TCP/53 (`dns-remoteshell.pcap`),
/// que antes no saltaba con nada.
///
/// Solo cuenta si viajó contenido y **ningún** paquete del flujo fue un
/// mensaje DNS válido:
/// - en TCP, con datos (`PSH`): las comprobaciones de salud que conectan y
///   cierran no cuentan, ni las sondas rechazadas (eso es R2);
/// - el DNS sobre TCP se reconoce (prefijo de longitud de 2 bytes), y
///   cualquier paquete DNS válido deja `flow.dns` puesto;
/// - solo el 53: mDNS (5353) y LLMNR (5355) van por su cuenta.
pub fn non_dns_on_port_53(flow: &EnrichedFlow) -> Option<String> {
    if flow.src_port != 53 && flow.dst_port != 53 {
        return None;
    }
    let carried = match flow.transport {
        Transport::Tcp => flow.tcp_flags.psh > 0,
        Transport::Udp => flow.packets + flow.packets_rev > 0,
        _ => false,
    };
    if !carried || flow.dns.is_some() || flow.l7_protocol == L7Protocol::Dns {
        return None;
    }
    // Quien escucha en el 53 es el servidor (si la captura empezó a mitad,
    // el primer paquete pudo ser suyo).
    let (client, server) = if flow.dst_port == 53 {
        (flow.src_ip, flow.dst_ip)
    } else {
        (flow.dst_ip, flow.src_ip)
    };
    let content = match flow.l7_protocol {
        L7Protocol::Http | L7Protocol::Tls | L7Protocol::Ssh => flow.l7_protocol.as_str(),
        _ => "desconocido",
    };
    Some(format!(
        "{} {client} → {server}:53 sin ningún mensaje DNS válido (contenido: {content})",
        flow.transport.as_str()
    ))
}

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

/// GUID canónico (`05b5292b-34b8-4fb7-85a3-8beef5fd2069`): 36 caracteres
/// hexadecimales con guiones en 8-4-4-4-12.
fn is_guid_label(l: &str) -> bool {
    l.len() == 36
        && l.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// Etiquetas que no son datos aunque lo parezcan, y por eso no cuentan para
/// la entropía:
/// - GUIDs canónicos: el localizador de controladores de dominio de Active
///   Directory pregunta `_ldap._tcp.<GUID>.domains._msdcs.<bosque>` y
///   `<GUID>._msdcs.<bosque>` en cualquier red Windows con dominio (falso
///   positivo High real del corpus, `dns.cap`). Un túnel que codificara en
///   forma de GUID necesitaría muchos nombres distintos y lo caza la regla
///   de volumen ([`crate::dns_volume`]);
/// - etiquetas de servicio cortas de SRV y DNS-SD (`_ldap`, `_tcp`,
///   `_msdcs`, `_kerberos`, `_services`…).
fn is_structural_label(l: &str) -> bool {
    is_guid_label(l) || (l.starts_with('_') && l.len() <= 16)
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
    let labels: Vec<&str> = crate::domain::subdomain_labels(&lower)
        .into_iter()
        .filter(|l| !is_structural_label(l))
        .collect();
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

/// Fracción mínima de intervalos dentro de la banda [0.4, 2.0] × mediana
/// en la prueba con jitter: tolera algún beacon perdido (intervalo doble)
/// o reintento, pero no la cola pesada del tráfico humano/en ráfagas.
/// (La banda es [`socshark_core::flow::JITTER_BAND`].)
const JITTER_MIN_IN_BAND_PERMILLE: u16 = 900;
/// Riesgo de la variante con jitter: la mitad que la estricta (+20), porque
/// la prueba es más permisiva y caza más polls legítimos de aplicaciones.
const JITTER_SCORE: u32 = 10;

/// Evidencia de un beacon con jitter aleatorio.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JitterBeacon {
    /// Periodo estimado (mediana de los intervalos), en segundos.
    pub period_secs: f64,
    /// Jitter estimado (semiamplitud relativa, %): para jitter uniforme
    /// ±J la MAD vale J/2, así que J ≈ 2·MAD/mediana.
    pub jitter_pct: f64,
    /// Intervalos evaluados.
    pub intervals: u32,
}

/// Prueba de beacon tolerante a jitter sobre intervalos crudos (µs).
///
/// Estadísticos robustos en lugar de media/CV: jitter uniforme ±50%
/// alrededor de un periodo deja todos los intervalos en [0.5, 1.5] ×
/// periodo (MAD/mediana ≈ 0.25), mientras que el tráfico humano o en
/// ráfagas es de cola pesada (MAD/mediana alto o muchos intervalos lejos de
/// la mediana). Ver [`jitter_check`].
pub fn jittered_beacon(deltas: &[u64], cfg: &PipelineConfig) -> Option<JitterBeacon> {
    jitter_check(&socshark_core::IntervalStats::from_deltas(deltas)?, cfg)
}

/// La prueba con jitter sobre la estadística ya calculada (dentro de un
/// flujo o entre conexiones). Exige TODAS:
/// - ≥ `beacon_jitter_min_intervals` (12) intervalos;
/// - mediana dentro de [`beacon_min_interval_secs`, `beacon_max_interval_secs`];
/// - MAD/mediana ≤ `beacon_jitter_max_mad_ratio` (0.35);
/// - ≥ 90% de los intervalos en [0.4, 2.0] × mediana (sin cola larga).
///
/// `None` también si la estadística no trae mediana (JSONL antiguo).
pub fn jitter_check(
    stats: &socshark_core::IntervalStats,
    cfg: &PipelineConfig,
) -> Option<JitterBeacon> {
    if stats.intervals < cfg.beacon_jitter_min_intervals {
        return None;
    }
    let mad_ratio = stats.mad_ratio()?;
    let median_secs = stats.median_micros as f64 / 1_000_000.0;
    if median_secs < cfg.beacon_min_interval_secs as f64
        || median_secs > cfg.beacon_max_interval_secs as f64
        || mad_ratio > cfg.beacon_jitter_max_mad_ratio
        || stats.in_band_permille < JITTER_MIN_IN_BAND_PERMILLE
    {
        return None;
    }
    Some(JitterBeacon {
        period_secs: median_secs,
        jitter_pct: 200.0 * mad_ratio,
        intervals: stats.intervals,
    })
}

/// Alerta `BEACONING` de la variante con jitter (severidad baja).
fn jitter_alert(detail: String) -> Alert {
    Alert {
        id: "BEACONING".into(),
        name: "Comunicación periódica con jitter (beacon)".into(),
        severity: Severity::Low,
        detail,
        mitre: Some("T1071".into()),
    }
}

/// R5 con jitter entre flujos: los intervalos crudos entre inicios de
/// conexión ([`crate::beacon::FlowStartTracker::intervals`]) pasan
/// [`jittered_beacon`] (+10). Llamar solo si la prueba estricta no alertó.
/// Devuelve si alertó.
pub fn assess_interflow_jitter_beacon(
    flow: &mut EnrichedFlow,
    deltas: &[u64],
    cfg: &PipelineConfig,
) -> bool {
    let Some(j) = jittered_beacon(deltas, cfg) else {
        return false;
    };
    flow.risk_score = (u32::from(flow.risk_score) + JITTER_SCORE).min(100) as u8;
    flow.alerts.push(jitter_alert(format!(
        "intervalo medio {:.1}s (mediana) con jitter ~{:.0}% en {} intervalos entre conexiones",
        j.period_secs, j.jitter_pct, j.intervals
    )));
    true
}

/// R1 por volumen: el (cliente, dominio) del flujo DNS alcanzó el umbral de
/// subdominios únicos en la ventana ([`crate::dns_volume`]). Misma alerta,
/// técnica y riesgo que R1 (+45, alta), con detalle propio; si la consulta
/// ya alertó por entropía no se duplica. Devuelve si alertó.
pub fn assess_dns_volume(
    flow: &mut EnrichedFlow,
    sig: &crate::dns_volume::DnsVolumeSignal,
) -> bool {
    if flow.alerts.iter().any(|a| a.id == "DNS-TUNNELING") {
        return false;
    }
    flow.risk_score = (u32::from(flow.risk_score) + 45).min(100) as u8;
    flow.alerts.push(Alert {
        id: "DNS-TUNNELING".into(),
        name: "Posible túnel DNS".into(),
        severity: Severity::High,
        detail: format!(
            "{} subdominios únicos de {} en {} min: volumen propio de un túnel aunque cada nombre parezca inocuo",
            sig.unique_subdomains,
            sig.base_domain,
            sig.window_secs.div_ceil(60)
        ),
        mitre: Some(MITRE_DNS_TUNNEL.into()),
    });
    true
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

    // R3 y R4 hablan de exposición a la red: no cuentan las conexiones del
    // equipo consigo mismo.
    let local = same_host(flow);

    // R3: administración remota insegura (telnet en texto claro) — T1021.
    if flow.transport == Transport::Tcp && flow.dst_port == 23 && !failed && !local {
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
        && !local
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

    // R8: otra cosa en el puerto 53 — MITRE T1571.
    if let Some(detail) = non_dns_on_port_53(flow) {
        score += 40;
        flow.alerts.push(Alert {
            id: "NON-DNS-ON-53".into(),
            name: "Tráfico que no es DNS en el puerto 53".into(),
            severity: Severity::High,
            detail,
            mitre: Some(MITRE_NON_STANDARD_PORT.into()),
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
            } else if let Some(j) = jitter_check(stats, cfg) {
                // Variante con jitter dentro del flujo: mediana + MAD sobre
                // los intervalos del iniciador, igual que entre conexiones.
                score += JITTER_SCORE;
                flow.alerts.push(jitter_alert(format!(
                    "intervalo medio {:.1}s (mediana) con jitter ~{:.0}% en {} intervalos",
                    j.period_secs, j.jitter_pct, j.intervals
                )));
            } else if stats.median_micros == 0
                && stats.intervals >= cfg.beacon_jitter_min_intervals
                && mean_secs >= cfg.beacon_min_interval_secs as f64
                && mean_secs <= cfg.beacon_max_interval_secs as f64
                && stats.cv() <= cfg.beacon_jitter_max_cv
            {
                // Sin mediana (flujo de un JSONL anterior): solo hay media y
                // desviación; se acepta un CV algo mayor (uniforme ±J da
                // CV = J/√3) y se estima J ≈ √3·CV.
                score += JITTER_SCORE;
                flow.alerts.push(jitter_alert(format!(
                    "intervalo medio {:.1}s con jitter ~{:.0}% en {} intervalos (CV {:.2})",
                    mean_secs,
                    100.0 * 3f64.sqrt() * stats.cv(),
                    stats.intervals,
                    stats.cv()
                )));
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

// ------------------------------------------------------------ idioma

/// Nombre de una alerta en el idioma dado. El `name` guardado en la alerta
/// (español) es parte del contrato del JSONL y no cambia: esto es solo
/// para mostrarlo.
pub fn alert_name_in(alert: &Alert, lang: Lang) -> String {
    if lang == Lang::Es {
        return alert.name.clone();
    }
    let jitter = alert.name.contains("jitter");
    match alert.id.as_str() {
        "DNS-TUNNELING" => "Possible DNS tunnel",
        "PORT-SCAN" => "Possible port scan",
        "NETWORK-SWEEP" => "Possible network sweep",
        "REPEATED-ATTEMPTS" => "Repeated connection attempts",
        "INSECURE-PORT" => "Cleartext Telnet",
        "EXPOSED-DB" => "Exposed database",
        "NON-DNS-ON-53" => "Non-DNS traffic on port 53",
        "BEACONING" if jitter => "Periodic communication with jitter (beacon)",
        "BEACONING" => "Periodic communication (beacon)",
        "FILE-MASQUERADING" => "File transferred with a forged identity",
        "THREAT-INTEL-FEODO" => "Destination on a C2 list (Feodo)",
        "TOR-USAGE" => "Connection to a Tor exit node",
        _ => return alert.name.clone(),
    }
    .to_string()
}

/// Detalle de una alerta en el idioma dado (el guardado es el español del
/// contrato). Reconoce las plantillas de las reglas; lo que no reconoce se
/// devuelve tal cual.
pub fn alert_detail_in(alert: &Alert, lang: Lang) -> String {
    if lang == Lang::Es {
        return alert.detail.clone();
    }
    detail_en(&alert.id, &alert.detail).unwrap_or_else(|| alert.detail.clone())
}

fn detail_en(id: &str, d: &str) -> Option<String> {
    Some(match id {
        "DNS-TUNNELING" => {
            if let Some((n, rest)) = d.split_once(" subdominios únicos de ") {
                let (domain, rest) = rest.rsplit_once(" en ")?;
                let mins = rest.split_once(" min")?.0;
                format!(
                    "{n} unique subdomains of {domain} in {mins} min: the volume of a tunnel \
                     even if each name looks harmless"
                )
            } else {
                let rest = d.strip_prefix("qname '")?;
                let (qname, rest) = rest.rsplit_once("': subdominio de ")?;
                let (chars, rest) = rest.split_once(" caracteres codificado (etiqueta de ")?;
                let (label, rest) = rest.split_once(", entropía ")?;
                format!(
                    "qname '{qname}': encoded subdomain of {chars} characters (label of {label}, \
                     entropy {rest}"
                )
            }
        }
        "PORT-SCAN" => {
            let (src, rest) = d.split_once(" probó ")?;
            let (n, rest) = rest.split_once(" puertos distintos de ")?;
            let dst = rest.strip_suffix(" sin establecer conexión")?;
            format!("{src} probed {n} different ports on {dst} without establishing a connection")
        }
        "NETWORK-SWEEP" => {
            let (src, rest) = d.split_once(" probó el puerto ")?;
            let (port, rest) = rest.split_once(" en ")?;
            let hosts = rest.strip_suffix(" hosts distintos sin establecer conexión")?;
            format!(
                "{src} probed port {port} on {hosts} different hosts without establishing a connection"
            )
        }
        "REPEATED-ATTEMPTS" => {
            let (n, rest) = d.split_once(" intentos de ")?;
            let (src, rest) = rest.split_once(" a ")?;
            let dst = rest.strip_suffix(" sin llegar a establecer conexión")?;
            format!("{n} attempts from {src} to {dst} without ever establishing a connection")
        }
        "INSECURE-PORT" => {
            let ip = d
                .strip_prefix("conexión a telnet (23/tcp) en ")?
                .strip_suffix(": credenciales sin cifrar")?;
            format!("telnet connection (23/tcp) to {ip}: unencrypted credentials")
        }
        "EXPOSED-DB" => {
            let rest = d.strip_prefix("conexión directa a puerto de base de datos (")?;
            let (port, ip) = rest.split_once(") en ")?;
            format!("direct connection to a database port ({port}) on {ip}")
        }
        "NON-DNS-ON-53" => {
            let (route, content) = d.split_once(" sin ningún mensaje DNS válido (contenido: ")?;
            let content = content.strip_suffix(')')?;
            let content = if content == "desconocido" {
                "unknown"
            } else {
                content
            };
            format!("{route} with no valid DNS message (content: {content})")
        }
        "BEACONING" => {
            let rest = d.strip_prefix("intervalo medio ")?;
            let rest = rest
                .replace(" (mediana)", " (median)")
                .replace(" con jitter ", " with jitter ")
                .replace(
                    " intervalos entre conexiones",
                    " intervals between connections",
                )
                .replace(" intervalos", " intervals")
                .replacen(" en ", " over ", 1);
            format!("mean interval {rest}")
        }
        "FILE-MASQUERADING" => {
            let files = d.strip_prefix("tipo real ≠ extensión declarada en ")?;
            format!("real type ≠ declared extension in {files}")
        }
        "THREAT-INTEL-FEODO" => {
            let ip = d.strip_suffix(" aparece en la lista Feodo cargada (--intel-feodo)")?;
            format!("{ip} appears on the loaded Feodo list (--intel-feodo)")
        }
        "TOR-USAGE" => {
            let ip = d.strip_suffix(
                " es un nodo de salida de Tor (lista --intel-tor): posible proxy multi-salto",
            )?;
            format!("{ip} is a Tor exit node (--intel-tor list): possible multi-hop proxy")
        }
        _ => return None,
    })
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
            // Localizador de DCs de Active Directory con GUID (falso positivo
            // High real del corpus: wireshark-dns, dns.cap).
            "_ldap._tcp.05b5292b-34b8-4fb7-85a3-8beef5fd2069.domains._msdcs.utelsystems.local",
            "e7c6b0a6-1c4f-4c7b-9c2a-3f1b2d4e5f60._msdcs.corp.example.com",
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
            // Un guion bajo delante no basta para pasar por etiqueta de
            // servicio: solo cuentan las cortas.
            "_x9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0.evil.com",
            // Casi-GUID con datos (no es hexadecimal): sigue siendo sospechoso.
            "zq9xk2vw-7mty-4pln-8rqs-3hgjk5wvz2xb.c2.evil.com",
        ] {
            assert!(dns_tunnel_suspect(name, &cfg).is_some(), "{name}");
        }
    }

    #[test]
    fn otra_cosa_en_el_puerto_53_dispara_r8() {
        let cfg = PipelineConfig::default();
        // Shell en TCP/53 (caso real del corpus, dns-remoteshell.pcap): con
        // datos y sin un solo mensaje DNS.
        let mut shell = flujo_basico(6, 1396, 53);
        shell.tcp_flags.syn = 2;
        shell.tcp_flags.ack = 11;
        shell.tcp_flags.psh = 5;
        shell.tcp_flags.rst = 1;
        assess(&mut shell, ScanSignals::default(), &cfg);
        let a = shell
            .alerts
            .iter()
            .find(|a| a.id == "NON-DNS-ON-53")
            .expect("debe saltar");
        assert_eq!(a.severity, Severity::High);
        assert_eq!(a.mitre.as_deref(), Some(MITRE_NON_STANDARD_PORT));
        assert_eq!(
            a.detail,
            "TCP 10.0.0.5 → 10.0.0.99:53 sin ningún mensaje DNS válido (contenido: desconocido)"
        );
        assert!(shell.risk_score >= 40);
        assert_eq!(alert_name_in(a, Lang::En), "Non-DNS traffic on port 53");
        assert_eq!(
            alert_detail_in(a, Lang::En),
            "TCP 10.0.0.5 → 10.0.0.99:53 with no valid DNS message (content: unknown)"
        );

        // Captura empezada a mitad: el primer paquete es del servidor, que
        // sigue siendo quien escucha en el 53.
        let mut rev = flujo_basico(6, 53, 50000);
        rev.tcp_flags.psh = 1;
        rev.l7_protocol = L7Protocol::Tls;
        assert_eq!(
            non_dns_on_port_53(&rev).as_deref(),
            Some("TCP 10.0.0.99 → 10.0.0.5:53 sin ningún mensaje DNS válido (contenido: TLS)")
        );

        // UDP/53 sin DNS (una VPN por el 53, por ejemplo).
        assert!(non_dns_on_port_53(&flujo_basico(17, 50001, 53)).is_some());
    }

    #[test]
    fn el_dns_de_verdad_y_lo_que_no_lleva_datos_no_dispara_r8() {
        // DNS por UDP y por TCP: cualquier mensaje válido deja `flow.dns`.
        let mut udp = flujo_basico(17, 50001, 53);
        udp.l7_protocol = L7Protocol::Dns;
        udp.dns = Some(qname_dns("example.com"));
        assert!(non_dns_on_port_53(&udp).is_none());
        let mut tcp = flujo_basico(6, 50002, 53);
        tcp.tcp_flags.psh = 2;
        tcp.l7_protocol = L7Protocol::Dns;
        tcp.dns = Some(qname_dns("example.com"));
        assert!(non_dns_on_port_53(&tcp).is_none());

        // Comprobación de salud: conecta y cierra sin enviar nada.
        let mut health = flujo_basico(6, 50003, 53);
        health.tcp_flags.syn = 2;
        health.tcp_flags.ack = 3;
        health.tcp_flags.fin = 2;
        assert!(non_dns_on_port_53(&health).is_none());

        // Sonda rechazada: eso es cosa de R2 (escaneo).
        let mut probe = flujo_basico(6, 50004, 53);
        probe.tcp_flags.syn = 1;
        probe.tcp_flags.rst = 1;
        assert!(non_dns_on_port_53(&probe).is_none());

        // mDNS y LLMNR van por su puerto, no por el 53.
        for port in [5353, 5355] {
            assert!(non_dns_on_port_53(&flujo_basico(17, port, port)).is_none());
        }

        // Y cualquier otro puerto, tampoco.
        let mut web = flujo_basico(6, 50005, 80);
        web.tcp_flags.psh = 3;
        assert!(non_dns_on_port_53(&web).is_none());
    }

    #[test]
    fn el_equipo_consigo_mismo_no_expone_nada() {
        let cfg = PipelineConfig::default();
        let mut casos = Vec::new();
        // Mismo equipo por su dirección de red (caso real: MySQL en .254).
        let mut mismo = flujo_basico(6, 56162, 3306);
        mismo.dst_ip = mismo.src_ip;
        casos.push(mismo);
        // Loopback IPv4 (caso real: PostgreSQL en 127.0.0.1) e IPv6.
        for (ip, port) in [("127.0.0.1", 5432), ("::1", 6379), ("127.0.0.1", 23)] {
            let mut f = flujo_basico(6, 45930, port);
            f.src_ip = ip.parse().unwrap();
            f.dst_ip = ip.parse().unwrap();
            casos.push(f);
        }
        for mut f in casos {
            assess(&mut f, ScanSignals::default(), &cfg);
            assert!(f.alerts.is_empty(), "{} {:?}", f.flow_id.0, f.alerts);
        }
        // Entre dos equipos sigue saltando (telnet_y_bd_disparan_reglas).
        assert!(!same_host(&flujo_basico(6, 40000, 3306)));
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
        });
        assess(&mut ntp, ScanSignals::default(), &cfg);
        assert!(!ntp.alerts.iter().any(|a| a.id == "BEACONING"));

        // Intervalo por debajo del mínimo (retransmisiones/push interactivo).
        let mut rapido = flujo_basico(6, 45002, 443);
        rapido.interval_stats = Some(socshark_core::IntervalStats {
            intervals: 10,
            mean_micros: 50_000, // 50 ms
            std_micros: 100,
            ..Default::default()
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

    fn deltas(times: &[u64]) -> Vec<u64> {
        times.windows(2).map(|w| w[1] - w[0]).collect()
    }

    #[test]
    fn jitter_uniforme_pasa_y_estima_periodo_y_jitter() {
        let cfg = PipelineConfig::default();
        for (pct, seed) in [(30u64, 1u64), (40, 2), (50, 3)] {
            let d = deltas(&socshark_testgen::evasion::jittered_times(
                seed, 60, pct, 20,
            ));
            let j = jittered_beacon(&d, &cfg).unwrap_or_else(|| panic!("±{pct}%"));
            assert!((45.0..=75.0).contains(&j.period_secs), "{j:?}");
            assert!(j.jitter_pct > 10.0 && j.jitter_pct < 70.0, "{j:?}");
            assert_eq!(j.intervals, 20);
        }
    }

    #[test]
    fn jitter_no_alerta_con_poca_muestra_cola_pesada_ni_rafagas() {
        let cfg = PipelineConfig::default();
        // Menos de 12 intervalos.
        let pocos = deltas(&socshark_testgen::evasion::jittered_times(5, 60, 40, 11));
        assert!(jittered_beacon(&pocos, &cfg).is_none());
        // Interactivo de cola pesada (log-normal).
        let humano: Vec<u64> = socshark_testgen::evasion::INTERACTIVE_GAPS_SECS
            .iter()
            .map(|s| s * 1_000_000)
            .collect();
        assert!(jittered_beacon(&humano, &cfg).is_none());
        // Ráfagas: poll cada 10 s mientras hay actividad y pausas largas
        // (MAD pequeña, pero el 25% de los intervalos fuera de banda).
        let rafagas: Vec<u64> = (0..20u64)
            .map(|i| {
                if i % 4 == 3 {
                    600_000_000
                } else {
                    10_000_000 + i * 100_000
                }
            })
            .collect();
        assert!(jittered_beacon(&rafagas, &cfg).is_none());
        // Mediana fuera de ventana (por debajo de 5 s).
        let rapido = vec![1_000_000u64; 20];
        assert!(jittered_beacon(&rapido, &cfg).is_none());
    }

    #[test]
    fn jitter_dentro_del_flujo_con_mediana_y_mad() {
        // Intervalos reales del iniciador (como los calcula el agregador):
        // 60 s ±40% uniforme con una semilla fija → variante con jitter.
        let cfg = PipelineConfig::default();
        let mut rng: u64 = 0x5eed;
        let mut next = || {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (rng >> 33) as f64 / (1u64 << 31) as f64
        };
        let beacon: Vec<u64> = (0..20)
            .map(|_| (60_000_000.0 * (0.6 + 0.8 * next())) as u64)
            .collect();
        let mut f = flujo_basico(6, 45200, 8443);
        f.interval_stats = socshark_core::IntervalStats::from_deltas(&beacon);
        assess(&mut f, ScanSignals::default(), &cfg);
        let b: Vec<_> = f.alerts.iter().filter(|a| a.id == "BEACONING").collect();
        assert_eq!(b.len(), 1, "{:?}", f.alerts);
        assert_eq!(b[0].severity, Severity::Low);
        assert!(b[0].detail.contains("(mediana)"), "{}", b[0].detail);

        // Cola pesada con CV moderado: la media/CV sola la confundiría con un
        // beacon con jitter, pero un 25% de pausas largas la descarta.
        let mut humano = vec![30_000_000u64; 15];
        humano.extend([300_000_000u64; 5]);
        let st = socshark_core::IntervalStats::from_deltas(&humano).unwrap();
        assert!(st.in_band_permille < 900);
        let mut h = flujo_basico(6, 45201, 8443);
        h.interval_stats = Some(st);
        assess(&mut h, ScanSignals::default(), &cfg);
        assert!(
            !h.alerts.iter().any(|a| a.id == "BEACONING"),
            "{:?}",
            h.alerts
        );
    }

    #[test]
    fn jitter_dentro_del_flujo_por_cv_y_la_estricta_gana() {
        let cfg = PipelineConfig::default();
        let con = |intervals: u32, cv: f64, ruido: bool| {
            let mut f = flujo_basico(17, 45100, 8443);
            f.is_background_noise = ruido;
            f.interval_stats = Some(socshark_core::IntervalStats {
                intervals,
                mean_micros: 60_000_000,
                std_micros: (60_000_000.0 * cv) as u64,
                ..Default::default()
            });
            assess(&mut f, ScanSignals::default(), &cfg);
            let b: Vec<(Severity, u8)> = f
                .alerts
                .iter()
                .filter(|a| a.id == "BEACONING")
                .map(|a| (a.severity, f.risk_score))
                .collect();
            b
        };
        // ±40% uniforme → CV ≈ 0.23: variante con jitter, baja, +10.
        assert_eq!(con(20, 0.23, false), [(Severity::Low, 10)]);
        // Regular: solo la estricta (media, +20), sin duplicado.
        assert_eq!(con(20, 0.05, false), [(Severity::Medium, 20)]);
        // Pocos intervalos para la variante con jitter.
        assert!(con(11, 0.23, false).is_empty());
        // Más disperso que ±50% uniforme.
        assert!(con(20, 0.45, false).is_empty());
        // Ruido de fondo (NTP con jitter de poll): excluido.
        assert!(con(20, 0.23, true).is_empty());
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

    #[test]
    fn nombres_y_detalles_en_ingles_sin_tocar_el_contrato() {
        let a = |id: &str, name: &str, detail: &str| Alert {
            id: id.into(),
            name: name.into(),
            severity: Severity::Medium,
            detail: detail.into(),
            mitre: None,
        };
        let cases = [
            a(
                "PORT-SCAN",
                "Posible escaneo de puertos",
                "10.0.0.5 probó 12 puertos distintos de 10.0.0.1 sin establecer conexión",
            ),
            a(
                "NETWORK-SWEEP",
                "Posible barrido de red",
                "10.0.0.5 probó el puerto 445 en 9 hosts distintos sin establecer conexión",
            ),
            a(
                "REPEATED-ATTEMPTS",
                "Intentos de conexión repetidos",
                "7 intentos de 10.0.0.5 a 10.0.0.1:22 sin llegar a establecer conexión",
            ),
            a(
                "INSECURE-PORT",
                "Telnet en texto claro",
                "conexión a telnet (23/tcp) en 10.0.0.1: credenciales sin cifrar",
            ),
            a(
                "EXPOSED-DB",
                "Base de datos expuesta",
                "conexión directa a puerto de base de datos (3306) en 10.0.0.1",
            ),
            a(
                "BEACONING",
                "Comunicación periódica (beacon)",
                "intervalo medio 30.0s con jitter ±0.5% en 9 intervalos",
            ),
            a(
                "BEACONING",
                "Comunicación periódica con jitter (beacon)",
                "intervalo medio 60.0s (mediana) con jitter ~25% en 9 intervalos entre conexiones",
            ),
            a(
                "FILE-MASQUERADING",
                "Archivo transferido con identidad falseada",
                "tipo real ≠ extensión declarada en factura.jpg",
            ),
            a(
                "THREAT-INTEL-FEODO",
                "Destino en lista de C2 (Feodo)",
                "1.2.3.4 aparece en la lista Feodo cargada (--intel-feodo)",
            ),
            a(
                "TOR-USAGE",
                "Conexión a nodo de salida de Tor",
                "1.2.3.4 es un nodo de salida de Tor (lista --intel-tor): posible proxy multi-salto",
            ),
            a(
                "DNS-TUNNELING",
                "Posible túnel DNS",
                "40 subdominios únicos de evil.example en 5 min: volumen propio de un túnel aunque cada nombre parezca inocuo",
            ),
            a(
                "DNS-TUNNELING",
                "Posible túnel DNS",
                "qname 'x.en.y': subdominio de 60 caracteres codificado (etiqueta de 60, entropía 4.10 ≥ 3.50)",
            ),
        ];
        for al in &cases {
            assert_eq!(alert_detail_in(al, Lang::Es), al.detail);
            assert_eq!(alert_name_in(al, Lang::Es), al.name);
            let en = alert_detail_in(al, Lang::En);
            assert_ne!(en, al.detail, "{}", al.id);
            assert!(
                !en.contains(" en ") || en.contains("'x.en.y'"),
                "{} sin traducir: {en}",
                al.id
            );
            assert_ne!(alert_name_in(al, Lang::En), al.name);
        }
        assert_eq!(
            alert_detail_in(&cases[6], Lang::En),
            "mean interval 60.0s (median) with jitter ~25% over 9 intervals between connections"
        );
        assert_eq!(
            alert_detail_in(&cases[11], Lang::En),
            "qname 'x.en.y': encoded subdomain of 60 characters (label of 60, entropy 4.10 ≥ 3.50)"
        );
        // Lo que no reconoce, tal cual.
        let otro = a("PORT-SCAN", "x", "otra cosa");
        assert_eq!(alert_detail_in(&otro, Lang::En), "otra cosa");
    }
}
