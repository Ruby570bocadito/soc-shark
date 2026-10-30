//! Orquestación del enriquecimiento SOC sobre los flujos exportados.

use socshark_core::config::PipelineConfig;
use socshark_core::{EnrichedFlow, L7Protocol};

use crate::beacon::FlowStartTracker;
use crate::dns_volume::DnsVolumeTracker;
use crate::intel::ThreatIntelDb;
use crate::noise;
use crate::passive_dns::PassiveDnsDb;
use crate::risk;
use crate::summarize;
use crate::ScanTracker;

/// Contexto SOC compartido por toda la sesión de captura.
#[derive(Default)]
pub struct SocContext {
    /// Caché dominio ↔ IP construida con las respuestas DNS observadas.
    pub passive_dns: PassiveDnsDb,
    /// Tracker de intentos de conexión fallidos (escaneos) entre flujos.
    pub scan_tracker: ScanTracker,
    /// Threat intel offline (Fase 4): `None` si no se cargó ninguna lista.
    pub intel: Option<ThreatIntelDb>,
    /// Inicios de flujo por servicio: beaconing lento que el timeout de
    /// inactividad parte en flujos sueltos (ver [`crate::beacon`]).
    pub flow_starts: FlowStartTracker,
    /// Subdominios únicos por (cliente, dominio registrable): túnel DNS por
    /// volumen (ver [`crate::dns_volume`]).
    pub dns_volume: DnsVolumeTracker,
}

/// Enriquece todos los flujos: DNS pasivo, ruido, riesgo y resumen humano.
///
/// **Dos pasadas**: primero se alimentan los trackers con el conjunto
/// completo de flujos y después se enriquece cada flujo. Así una señal que
/// solo es visible globalmente (un escaneo repartido en N flujos de un SYN,
/// o el dominio que resuelve una IP vista en un DNS posterior) está
/// disponible para todos los flujos cuando se evalúan las reglas.
pub fn enrich_all(ctx: &mut SocContext, flows: &mut [EnrichedFlow], cfg: &PipelineConfig) {
    // Pasada 1: alimentar estado global.
    for flow in flows.iter() {
        if let Some(dns) = &flow.dns {
            ctx.passive_dns.observe(dns);
        }
        ctx.scan_tracker.observe(flow);
        ctx.flow_starts.observe(flow);
        ctx.dns_volume.observe(flow, cfg);
    }

    // Pasada 2: enriquecer cada flujo con el contexto completo.
    for flow in flows.iter_mut() {
        // resolved_domain: el qname propio si ES un flujo DNS; lookup pasivo
        // si no; como último recurso el SNI que el propio cliente declaró en
        // el ClientHello (Fase 3) — es la fuente más directa de "a qué
        // dominio habla este flujo" cuando no hubo DNS observado.
        if flow.l7_protocol == L7Protocol::Dns {
            if let Some(qname) = flow
                .dns
                .as_ref()
                .and_then(|d| d.queries.first())
                .map(|q| q.name.clone())
            {
                flow.resolved_domain = Some(qname);
            }
        } else if let Some(domain) = ctx.passive_dns.resolve(flow.dst_ip) {
            flow.resolved_domain = Some(domain.clone());
        } else if flow.resolved_domain.is_none() {
            if let Some(sni) = flow.tls_sni.clone() {
                flow.resolved_domain = Some(sni);
            }
        }

        if cfg.detect_noise {
            flow.is_background_noise = noise::is_background_noise(flow);
        }

        // Threat intel offline (Fase 4): etiquetas de cualquiera de los dos
        // extremos (un C2 o una salida Tor también pueden iniciar la
        // conexión). Se evalúa antes del riesgo para que R7 las vea.
        if let Some(db) = &ctx.intel {
            flow.threat_intel = db
                .check_flow(flow.src_ip, flow.dst_ip)
                .into_iter()
                .map(str::to_string)
                .collect();
        }

        let scan = ctx.scan_tracker.signals(flow);
        risk::assess_with_intel(flow, scan, cfg, ctx.intel.as_ref());
        // R1 por volumen: subdominios únicos por (cliente, dominio).
        if let Some(sig) = ctx.dns_volume.signal(flow, cfg) {
            risk::assess_dns_volume(flow, &sig);
        }
        // R5 entre flujos: solo si el propio flujo no alertó ya beacon. La
        // prueba estricta va primero; la de jitter solo si aquella no pasa.
        if !flow.alerts.iter().any(|a| a.id == "BEACONING") {
            if let Some(deltas) = ctx.flow_starts.intervals(flow) {
                let stats = crate::beacon::stats_of(&deltas);
                if !risk::assess_interflow_beacon(flow, &stats, cfg) {
                    risk::assess_interflow_jitter_beacon(flow, &deltas, cfg);
                }
            }
        }
        flow.human_summary = summarize::summarize(flow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::flujo_basico;
    use socshark_core::{DnsAnswerSummary, DnsQuerySummary, DnsSummary};

    #[test]
    fn dns_pasivo_etiqueta_flujos_posteriores() {
        let mut dns = flujo_basico(17, 53001, 53);
        dns.l7_protocol = L7Protocol::Dns;
        dns.dns = Some(DnsSummary {
            is_response: true,
            rcode: Some(0),
            queries: vec![DnsQuerySummary {
                name: "ejemplo.com".into(),
                qtype: 1,
            }],
            answers: vec![DnsAnswerSummary {
                name: "ejemplo.com".into(),
                rtype: 1,
                ttl: 300,
                address: Some("203.0.113.7".parse().unwrap()),
                target: None,
            }],
        });

        let mut web = flujo_basico(6, 51000, 443);
        web.dst_ip = "203.0.113.7".parse().unwrap();

        let mut flows = vec![dns, web];
        let mut ctx = SocContext::default();
        enrich_all(&mut ctx, &mut flows, &PipelineConfig::default());

        assert_eq!(flows[0].resolved_domain.as_deref(), Some("ejemplo.com"));
        assert_eq!(flows[1].resolved_domain.as_deref(), Some("ejemplo.com"));
        assert!(!flows[1].human_summary.is_empty());
    }

    /// Desenlaces de una sonda como contadores (syn, ack, rst) del flujo.
    const FILTRADO: (u32, u32, u32) = (1, 0, 0); // SYN sin respuesta
    const CERRADO: (u32, u32, u32) = (1, 1, 1); // SYN → RST/ACK
    const ABIERTO: (u32, u32, u32) = (2, 1, 1); // SYN → SYN/ACK → RST

    /// Sonda de 10.0.0.9 a `dst:dport` con el desenlace dado.
    fn sonda(dst: &str, sport: u16, dport: u16, (syn, ack, rst): (u32, u32, u32)) -> EnrichedFlow {
        let mut f = flujo_basico(6, sport, dport);
        f.src_ip = "10.0.0.9".parse().unwrap();
        f.dst_ip = dst.parse().unwrap();
        f.tcp_flags.syn = syn;
        f.tcp_flags.ack = ack;
        f.tcp_flags.rst = rst;
        f
    }

    #[test]
    fn escaneo_vertical_alerta_a_todas_las_sondas_sea_cual_sea_la_respuesta() {
        let cfg = PipelineConfig::default(); // umbral 10 puertos
                                             // Como `nmap -sS`: puerto origen fijo; 22 abierto (SYN/ACK + RST),
                                             // 21/25/110 cerrados (RST/ACK) y el resto filtrados (sin respuesta).
        let mut flows: Vec<EnrichedFlow> = [21, 22, 23, 25, 80, 110, 135, 139, 445, 3306]
            .into_iter()
            .map(|p| match p {
                22 => sonda("10.0.0.1", 40001, p, ABIERTO),
                21 | 25 | 110 => sonda("10.0.0.1", 40001, p, CERRADO),
                _ => sonda("10.0.0.1", 40001, p, FILTRADO),
            })
            .collect();
        let mut ctx = SocContext::default();
        enrich_all(&mut ctx, &mut flows, &cfg);

        for f in &flows {
            let ids: Vec<&str> = f.alerts.iter().map(|a| a.id.as_str()).collect();
            assert_eq!(ids, ["PORT-SCAN"], "sonda al {}: {ids:?}", f.dst_port);
        }
    }

    #[test]
    fn barrido_horizontal_entre_lotes_del_daemon() {
        let cfg = PipelineConfig::default(); // umbral 20 hosts
        let mut ctx = SocContext::default();
        // El contexto persiste entre lotes (daemon): 19 hosts no alertan...
        let mut lote1: Vec<EnrichedFlow> = (1..20)
            .map(|h| sonda(&format!("10.0.1.{h}"), 40000 + h, 445, FILTRADO))
            .collect();
        enrich_all(&mut ctx, &mut lote1, &cfg);
        assert!(lote1.iter().all(|f| f.alerts.is_empty()));
        // ...y el vigésimo, en un lote posterior, sí.
        let mut lote2 = vec![sonda("10.0.1.20", 40020, 445, FILTRADO)];
        enrich_all(&mut ctx, &mut lote2, &cfg);
        assert_eq!(lote2[0].alerts[0].id, "NETWORK-SWEEP");
        assert_eq!(lote2[0].alerts[0].mitre.as_deref(), Some("T1046"));
    }

    #[test]
    fn beacon_lento_partido_en_flujos_alerta_entre_lotes() {
        // Un implante que llama cada 5 min: con timeout de 120 s cada
        // llamada es un flujo suelto de un paquete, sin estadística propia.
        let cfg = PipelineConfig::default();
        let mut ctx = SocContext::default();
        let llamada = |i: u64| {
            let mut f = flujo_basico(6, 40000 + i as u16, 443);
            f.dst_ip = "203.0.113.50".parse().unwrap();
            f.first_seen_micros = 1_000_000_000 + i * 300_000_000 + (i % 2) * 2_000_000;
            f.tcp_flags.syn = 1;
            f.tcp_flags.ack = 3;
            f.tcp_flags.psh = 1;
            f.tcp_flags.fin = 2;
            f
        };
        let mut ultima = Vec::new();
        for i in 0..8u64 {
            let mut lote = vec![llamada(i)];
            enrich_all(&mut ctx, &mut lote, &cfg);
            ultima = lote;
        }
        let a = ultima[0]
            .alerts
            .iter()
            .find(|a| a.id == "BEACONING")
            .expect("beacon entre flujos");
        assert!(a.detail.contains("entre conexiones"), "{}", a.detail);
        assert_eq!(a.mitre.as_deref(), Some("T1071"));

        // Conexiones irregulares al mismo servicio: nada.
        let mut ctx = SocContext::default();
        let mut flows: Vec<EnrichedFlow> = [0u64, 7, 90, 95, 400, 1300, 1310, 5000]
            .iter()
            .enumerate()
            .map(|(i, &t)| {
                let mut f = llamada(i as u64);
                f.first_seen_micros = t * 1_000_000;
                f
            })
            .collect();
        enrich_all(&mut ctx, &mut flows, &cfg);
        assert!(flows
            .iter()
            .all(|f| !f.alerts.iter().any(|a| a.id == "BEACONING")));
    }

    #[test]
    fn reintentos_al_mismo_puerto_no_son_escaneo() {
        let cfg = PipelineConfig::default();
        // 5 SYNs al 22 con puertos origen distintos: un cliente que insiste
        // contra un servicio caído, no un escaneo de puertos.
        let mut flows: Vec<EnrichedFlow> = (0..5u16)
            .map(|i| sonda("10.0.0.1", 40000 + i, 22, FILTRADO))
            .collect();
        let mut ctx = SocContext::default();
        enrich_all(&mut ctx, &mut flows, &cfg);
        for f in &flows {
            assert!(!f.alerts.iter().any(|a| a.id == "PORT-SCAN"));
            assert_eq!(f.alerts[0].id, "REPEATED-ATTEMPTS");
            assert_eq!(f.alerts[0].severity, socshark_core::Severity::Low);
        }
    }

    // ------------------------------------------- hoja de ruta 0.8: evasión

    /// Paquetes por disector + agregador (timeout de inactividad `idle`):
    /// los flujos exportados, ordenados por inicio, aún sin enriquecer.
    fn flujos_de(packets: Vec<(u64, Vec<u8>)>, idle: u64) -> Vec<EnrichedFlow> {
        use socshark_core::{LinkType, RawPacket};
        use socshark_dissectors::DissectorPipeline;
        use socshark_flow::FlowAggregator;

        let pipe = DissectorPipeline::new();
        let mut agg = FlowAggregator::new(100_000, idle, false);
        for (ts, data) in packets {
            let pkt = RawPacket {
                ts_micros: ts,
                orig_len: data.len() as u32,
                data,
            };
            if let Some(dp) = pipe.dissect(&pkt, LinkType::Ethernet) {
                agg.on_packet(pkt.ts_micros, pkt.data.len(), &dp);
            }
        }
        let mut flows = agg.finish();
        flows.sort_by_key(|f| f.first_seen_micros);
        flows
    }

    fn por_el_motor(packets: Vec<(u64, Vec<u8>)>) -> Vec<EnrichedFlow> {
        let mut flows = flujos_de(packets, 120);
        enrich_all(
            &mut SocContext::default(),
            &mut flows,
            &PipelineConfig::default(),
        );
        flows
    }

    fn alertas<'a>(flows: &'a [EnrichedFlow], id: &str) -> Vec<&'a socshark_core::Alert> {
        flows
            .iter()
            .flat_map(|f| f.alerts.iter())
            .filter(|a| a.id == id)
            .collect()
    }

    #[test]
    fn tunel_dns_de_baja_entropia_alerta_por_volumen() {
        use socshark_testgen::evasion::*;
        // Ningún nombre suelto parece un túnel...
        assert!(risk::dns_tunnel_suspect("a0001.t.evil.com", &PipelineConfig::default()).is_none());
        // ...pero 200 subdominios únicos de evil.com en 7 min sí.
        let flows = por_el_motor(dns_low_entropy_tunnel_packets());
        assert_eq!(flows.len(), 200);
        let a = alertas(&flows, "DNS-TUNNELING");
        assert_eq!(a.len(), 200, "todas las consultas del túnel");
        assert!(
            a[0].detail
                .contains("50 subdominios únicos de evil.com en 10 min"),
            "{}",
            a[0].detail
        );
        assert_eq!(a[0].mitre.as_deref(), Some("T1071.004"));
        assert_eq!(a[0].severity, socshark_core::Severity::High);
        assert!(flows.iter().all(|f| f.risk_score >= 45));
        let e = crate::explain::explain(&flows[0]);
        assert!(
            e.alerts[0]
                .story
                .contains("50 nombres distintos de evil.com"),
            "{}",
            e.alerts[0].story
        );
    }

    #[test]
    fn navegacion_consultas_repetidas_y_ptr_no_son_tunel() {
        let flows = por_el_motor(socshark_testgen::evasion::dns_benign_packets());
        assert_eq!(flows.len(), 230);
        assert!(alertas(&flows, "DNS-TUNNELING").is_empty());
    }

    #[test]
    fn volumen_dns_entre_lotes_del_daemon() {
        let cfg = PipelineConfig::default(); // umbral 50 únicos
        let flows = flujos_de(
            socshark_testgen::evasion::dns_low_entropy_tunnel_packets(),
            120,
        );
        let mut ctx = SocContext::default();
        let mut alertados = Vec::new();
        for lote in flows.chunks(20) {
            let mut lote = lote.to_vec();
            enrich_all(&mut ctx, &mut lote, &cfg);
            alertados.push(alertas(&lote, "DNS-TUNNELING").len());
        }
        // Lotes 1-2 (40 únicos) nada; el 3.º cruza el umbral en su 10.ª
        // consulta (pasada 1 antes que la 2: alerta el lote entero).
        assert_eq!(alertados[..3], [0, 0, 20]);
        assert!(alertados[3..].iter().all(|&n| n == 20));
        assert!(ctx.dns_volume.len() == 1);
    }

    #[test]
    fn beacon_con_jitter_entre_conexiones_alerta_bajo() {
        use socshark_testgen::evasion::jittered_beacon_packets;
        // Varias semillas: la detección no depende de una tirada afortunada.
        for seed in 0..30 {
            let flows = por_el_motor(jittered_beacon_packets(seed));
            let c2: Vec<&EnrichedFlow> = flows
                .iter()
                .filter(|f| f.dst_ip.to_string() == "198.51.100.23")
                .collect();
            assert_eq!(c2.len(), 21);
            // La prueba estricta (CV ≤ 0.15) no pasa con ±40%...
            let a: Vec<_> = c2
                .iter()
                .flat_map(|f| f.alerts.iter())
                .filter(|a| a.id == "BEACONING")
                .collect();
            assert_eq!(a.len(), 21, "semilla {seed}: una alerta por flujo");
            // ...la de jitter sí, con severidad baja y +10.
            assert_eq!(a[0].severity, socshark_core::Severity::Low, "{seed}");
            assert!(a[0].detail.contains("jitter ~"), "{}", a[0].detail);
            assert!(a[0].detail.contains("entre conexiones"), "{}", a[0].detail);
            assert_eq!(a[0].mitre.as_deref(), Some("T1071"));
        }
    }

    #[test]
    fn beacon_con_jitter_dentro_de_un_flujo_udp() {
        let flows = por_el_motor(socshark_testgen::evasion::jittered_udp_beacon_packets(42));
        assert_eq!(flows.len(), 1);
        let a = alertas(&flows, "BEACONING");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].severity, socshark_core::Severity::Low);
        // Con los intervalos del agregador va por mediana + MAD, no por CV.
        assert!(a[0].detail.contains("(mediana)"), "{}", a[0].detail);
        let e = crate::explain::explain(&flows[0]);
        assert!(
            e.alerts[0].story.contains("variaciones al azar"),
            "{}",
            e.alerts[0].story
        );
        assert_eq!(flows[0].risk_score, 10);
    }

    #[test]
    fn conexiones_interactivas_de_cola_pesada_no_son_beacon() {
        let flows = por_el_motor(socshark_testgen::evasion::interactive_sessions_packets());
        assert_eq!(flows.len(), 21);
        assert!(alertas(&flows, "BEACONING").is_empty());
    }

    #[test]
    fn beacon_regular_gana_a_la_variante_con_jitter() {
        // 20 intervalos de 60 s exactos (±0%): pasan las dos pruebas y solo
        // debe salir la estricta (media, +20), una vez por flujo.
        let mut flows: Vec<EnrichedFlow> = socshark_testgen::evasion::jittered_times(1, 60, 0, 20)
            .into_iter()
            .enumerate()
            .map(|(i, t)| {
                let mut f = flujo_basico(6, 41000 + i as u16, 443);
                f.first_seen_micros = t;
                f
            })
            .collect();
        enrich_all(
            &mut SocContext::default(),
            &mut flows,
            &PipelineConfig::default(),
        );
        for f in &flows {
            let b: Vec<_> = f.alerts.iter().filter(|a| a.id == "BEACONING").collect();
            assert_eq!(b.len(), 1);
            assert_eq!(b[0].severity, socshark_core::Severity::Medium);
            assert_eq!(f.risk_score, 20);
        }
    }
}
