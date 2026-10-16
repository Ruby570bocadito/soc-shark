//! Orquestación del enriquecimiento SOC sobre los flujos exportados.

use socshark_core::config::PipelineConfig;
use socshark_core::{EnrichedFlow, L7Protocol};

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
    /// Tracker de escaneos SYN entre flujos.
    pub scan_tracker: ScanTracker,
    /// Threat intel offline (Fase 4): `None` si no se cargó ninguna lista.
    pub intel: Option<ThreatIntelDb>,
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

        // Threat intel offline: etiquetas del destino (Fase 4). Se evalúa
        // antes del riesgo para que la regla R7 vea las etiquetas.
        if let Some(db) = &ctx.intel {
            flow.threat_intel = db
                .check(flow.dst_ip)
                .into_iter()
                .map(str::to_string)
                .collect();
        }

        let scan_hits = ctx
            .scan_tracker
            .hits(&(flow.src_ip, flow.dst_ip, flow.dst_port));
        risk::assess(flow, scan_hits, cfg);
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

    #[test]
    fn escaneo_entre_flujos_alerta_a_todos_los_involucrados() {
        let cfg = PipelineConfig::default(); // umbral 4 SYNs
        let mut flows: Vec<EnrichedFlow> = (0..5u16)
            .map(|i| {
                let mut f = flujo_basico(6, 40000 + i, 22);
                f.dst_ip = "10.0.0.1".parse().unwrap();
                f.src_ip = "10.0.0.9".parse().unwrap();
                f.tcp_flags.syn = 1;
                f
            })
            .collect();
        let mut ctx = SocContext::default();
        enrich_all(&mut ctx, &mut flows, &cfg);

        for f in &flows {
            assert!(
                f.alerts.iter().any(|a| a.id == "PORT-SCAN"),
                "cada SYN del escaneo debe llevar alerta"
            );
        }
    }
}
