//! **Inteligencia Blue Team** de soc-shark.
//!
//! Módulos:
//! - [`file_carver`]: extrae archivos de HTTP, calcula SHA-256 y verifica
//!   magic bytes (Masquerading, MITRE T1036).
//! - [`anomaly_detector`]: port mismatch, DNS tunneling, conexión directa
//!   por IP sin DNS previo.
//! - [`beacon_detect`]: análisis estadístico de intervalos (C2 beaconing).
//! - [`threat_intel`]: listas offline de IOCs (IPs/CIDRs/dominios).
//! - [`rules_eval`]: composición de alertas y mapeo MITRE ATT&CK.
//! - [`siem_exporter`]: exportación ECS (Wazuh/Elastic) y regla Suricata.
//!
//! Flujo de trabajo: [`SocEngine::observe_packet`] durante el barrido de la
//! captura (passive DNS, eventos DNS, carving) y [`SocEngine::enrich`] al
//! final, cuando la tabla de sesiones está completa.

pub mod anomaly_detector;
pub mod beacon_detect;
pub mod file_carver;
pub mod rules_eval;
pub mod siem_exporter;
pub mod threat_intel;

use file_carver::FileCarver;
use socshark_common::ipaddr::IpAddr;
use socshark_common::soc_types::Artifact;
use socshark_flow_aggregator::model::FlowKey;
use socshark_flow_aggregator::passive_dns::PassiveDns;
use socshark_flow_aggregator::session_table::SessionTable;
use std::collections::HashMap;

/// Evento DNS observado (para heurística de tunneling).
#[derive(Debug, Clone)]
pub struct DnsEvent {
    pub ts_us: u64,
    pub src: IpAddr,
    pub qname: String,
    pub qtype: u16,
    /// Longitud de la etiqueta más larga del qname.
    pub max_label_len: usize,
    /// Entropía de Shannon del qname completo.
    pub entropy: f64,
}

const MAX_DNS_EVENTS: usize = 20_000;

/// Motor SOC: acumula observaciones y enriquece la tabla de sesiones.
pub struct SocEngine {
    pub passive_dns: PassiveDns,
    dns_events: Vec<DnsEvent>,
    carver: FileCarver,
    /// Artefactos pendientes de adjuntar, por clave de flujo.
    pending_artifacts: HashMap<FlowKey, Vec<Artifact>>,
}

/// Resumen del enriquecimiento.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnrichStats {
    pub flows: usize,
    pub alerts: usize,
    pub artifacts: usize,
    pub beacon_flows: usize,
    pub passive_dns_pairs: usize,
}

impl Default for SocEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SocEngine {
    pub fn new() -> Self {
        SocEngine {
            passive_dns: PassiveDns::new(),
            dns_events: Vec::new(),
            carver: FileCarver::new(),
            pending_artifacts: HashMap::new(),
        }
    }

    /// Fase de streaming: se llama por cada paquete diseccionado.
    pub fn observe_packet(&mut self, dp: &socshark_dissectors::view::DissectedPacket) {
        // 1. Passive DNS.
        self.passive_dns.observe(dp);
        // 2. Eventos DNS para tunneling.
        if let Some(socshark_dissectors::view::AppInfo::Dns(d)) = dp.app.as_ref() {
            if !d.is_response {
                if let Some(q) = d.qname() {
                    if self.dns_events.len() < MAX_DNS_EVENTS {
                        let max_label = q.split('.').map(|l| l.len()).max().unwrap_or(0);
                        self.dns_events.push(DnsEvent {
                            ts_us: dp.ts_us,
                            src: dp.src_ip().unwrap_or(IpAddr::V4([0, 0, 0, 0])),
                            qname: q.to_string(),
                            qtype: d.questions.first().map(|x| x.qtype).unwrap_or(0),
                            max_label_len: max_label,
                            entropy: socshark_common::entropy::str_entropy(q),
                        });
                    }
                }
            }
        }
        // 3. Carving HTTP.
        self.carver.observe(dp, &mut self.pending_artifacts);
    }

    /// Fase final: enriquece todos los flujos con contexto SOC.
    pub fn enrich(
        &mut self,
        table: &mut SessionTable,
        ti: &threat_intel::ThreatIntel,
    ) -> EnrichStats {
        let stats_src = self.passive_dns.total_pairs();
        // 1. Beaconing: agrupa flujos por (src, dst, dport, proto).
        let beacon_map = beacon_detect::detect(table);
        let beacon_flows = beacon_map.len();
        // 2. DNS tunneling: alertas por IP origen.
        let tunnel_map = anomaly_detector::dns_tunneling(&self.dns_events);

        let mut alerts_total = 0usize;
        let mut artifacts_total = 0usize;
        for i in 0..table.flows_mut().len() {
            let flow = &mut table.flows_mut()[i];
            // Ruido de fondo PRIMERO: las reglas no deben dispararse sobre
            // mDNS/SSDP/NTP/DHCP (p. ej. "DNS en puerto no estándar 5353").
            flow.is_background_noise =
                socshark_flow_aggregator::noise_classifier::flow_is_background_noise(&flow.key);
            let mut alerts = rules_eval::apply_flow_rules(flow);

            // Beaconing.
            if let Some(b) = beacon_map.get(&i) {
                alerts.push(b.clone());
            }
            // DNS tunneling: solo en flujos DNS cuyo qname caiga bajo el
            // dominio base de la alerta (evidence = dominio base).
            if flow.l7_protocol == "DNS" {
                if let Some(t) = tunnel_map.get(&flow.key.src) {
                    if let Some(base) = &t.evidence {
                        if flow.dns_queries.iter().any(|q| q.ends_with(base.as_str())) {
                            alerts.push(t.clone());
                        }
                    }
                }
            }
            // Threat intel offline.
            if ti.check_ip(&flow.key.dst) {
                alerts.push(socshark_common::soc_types::SocAlert {
                    id: "IOC-MATCH",
                    severity: socshark_common::soc_types::Severity::Critical,
                    title: format!("Destino {} en lista de IOCs ({})", flow.key.dst, ti.note()),
                    detail: format!(
                        "La IP destino {} coincide con las listas locales cargadas.",
                        flow.key.dst
                    ),
                    mitre: None,
                    evidence: Some(flow.key.dst.to_string()),
                });
            }

            // Artefactos extraídos de este flujo (clave directa o invertida).
            let mut arts = self.pending_artifacts.remove(&flow.key).unwrap_or_default();
            if arts.is_empty() {
                arts = self
                    .pending_artifacts
                    .remove(&flow.key.reversed())
                    .unwrap_or_default();
            }
            for a in &arts {
                alerts.extend(rules_eval::artifact_alerts(a));
            }
            artifacts_total += arts.len();
            flow.extracted_files = arts;

            // Atribución de dominio (Passive DNS → Host → SNI → nada).
            if flow.resolved_domain.is_none() {
                if let Some(seen) = self.passive_dns.lookup(&flow.key.dst, flow.first_seen_us) {
                    flow.resolved_domain = Some(seen.domain.clone());
                    flow.domain_source = socshark_flow_aggregator::model::DomainSource::PassiveDns;
                } else if let Some(h) = flow.http_host.clone() {
                    flow.resolved_domain = Some(h);
                    flow.domain_source = socshark_flow_aggregator::model::DomainSource::HttpHost;
                } else if let Some(s) = flow.tls_sni.clone() {
                    flow.resolved_domain = Some(s);
                    flow.domain_source = socshark_flow_aggregator::model::DomainSource::TlsSni;
                } else if flow.key.dst.is_global_candidate() && flow.l7_protocol != "DNS" {
                    // Conexión directa por IP: típico de C2 y exfiltración.
                    alerts.push(anomaly_detector::direct_ip_alert(flow));
                }
            }

            // Resumen humano + riesgo.
            flow.human_summary = socshark_flow_aggregator::human_summary::summarize(flow);
            flow.risk_score = socshark_common::soc_types::risk_score(&alerts);
            flow.alerts = alerts;
            alerts_total += flow.alerts.len();
        }

        EnrichStats {
            flows: table.len(),
            alerts: alerts_total,
            artifacts: artifacts_total,
            beacon_flows,
            passive_dns_pairs: stats_src,
        }
    }

    /// Acceso de solo lectura al passive DNS (para informes).
    pub fn passive_dns(&self) -> &PassiveDns {
        &self.passive_dns
    }

    /// Número de eventos DNS recolectados.
    pub fn dns_events(&self) -> &[DnsEvent] {
        &self.dns_events
    }
}
