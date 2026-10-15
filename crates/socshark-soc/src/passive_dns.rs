//! DNS pasivo: cachea asociaciones dominio ↔ IP observadas en respuestas DNS
//! y las reutiliza para etiquetar el resto de flujos (`resolved_domain`).
//!
//! Es la primera pieza del módulo "Passive DNS" del diseño SOC. En Fase 4
//! persistirá en disco (DuckDB/SQLite) y alimentará la vista de la UI
//! "¿quién resuelve qué?" en tiempo real.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use socshark_core::DnsSummary;

/// Base de DNS pasivo de la sesión.
#[derive(Default)]
pub struct PassiveDnsDb {
    /// IP → dominios que la han devuelto (BTree para orden determinista).
    ip_to_domains: HashMap<IpAddr, BTreeMap<String, ()>>,
    /// Dominio → IPs que respondieron las consultas.
    domain_to_ips: HashMap<String, BTreeMap<IpAddr, ()>>,
}

impl PassiveDnsDb {
    /// Registra las respuestas de un intercambio DNS.
    ///
    /// Solo las respuestas (`is_response`) aportan asociaciones; las
    /// consultas sueltas no etiquetan nada (la pregunta no implica que la IP
    /// pertenezca al dominio).
    pub fn observe(&mut self, dns: &DnsSummary) {
        if !dns.is_response {
            return;
        }
        for answer in &dns.answers {
            if let Some(ip) = answer.address {
                self.ip_to_domains
                    .entry(ip)
                    .or_default()
                    .insert(answer.name.clone(), ());
                self.domain_to_ips
                    .entry(answer.name.clone())
                    .or_default()
                    .insert(ip, ());
            }
            // Los CNAME/NS/PTR crean relaciones dominio→dominio: se registran
            // como dominios conocidos aunque no haya IP directa.
            if let Some(target) = &answer.target {
                self.domain_to_ips.entry(target.clone()).or_default();
            }
        }
    }

    /// Primer dominio conocido para una IP (orden lexicográfico: resultado
    /// determinista entre ejecuciones).
    pub fn resolve(&self, ip: IpAddr) -> Option<&String> {
        self.ip_to_domains
            .get(&ip)
            .and_then(|set| set.keys().next())
    }

    /// Todos los dominios conocidos para una IP.
    pub fn domains_for(&self, ip: IpAddr) -> Vec<&String> {
        self.ip_to_domains
            .get(&ip)
            .map(|set| set.keys().collect())
            .unwrap_or_default()
    }

    /// IPs conocidas para un dominio.
    pub fn ips_for(&self, domain: &str) -> Vec<&IpAddr> {
        self.domain_to_ips
            .get(domain)
            .map(|set| set.keys().collect())
            .unwrap_or_default()
    }

    /// Número de IPs con al menos un dominio asociado.
    pub fn len(&self) -> usize {
        self.ip_to_domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ip_to_domains.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_core::{DnsAnswerSummary, DnsQuerySummary};

    fn respuesta(addr: IpAddr, dominio: &str) -> DnsSummary {
        DnsSummary {
            is_response: true,
            rcode: Some(0),
            queries: vec![DnsQuerySummary {
                name: dominio.into(),
                qtype: 1,
            }],
            answers: vec![DnsAnswerSummary {
                name: dominio.into(),
                rtype: 1,
                ttl: 300,
                address: Some(addr),
                target: None,
            }],
        }
    }

    #[test]
    fn resuelve_ip_dominio() {
        let mut db = PassiveDnsDb::default();
        db.observe(&respuesta("93.184.216.34".parse().unwrap(), "example.com"));
        assert_eq!(
            db.resolve("93.184.216.34".parse().unwrap())
                .map(String::as_str),
            Some("example.com")
        );
        assert_eq!(db.ips_for("example.com").len(), 1);
    }

    #[test]
    fn consultas_sin_respuesta_no_etiquetan() {
        let mut db = PassiveDnsDb::default();
        let mut q = respuesta("1.2.3.4".parse().unwrap(), "ejemplo.test");
        q.is_response = false;
        db.observe(&q);
        assert!(db.is_empty());
    }
}
