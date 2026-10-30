//! DNS pasivo: cachea asociaciones dominio ↔ IP observadas en respuestas DNS
//! y las reutiliza para etiquetar el resto de flujos (`resolved_domain`).
//!
//! Es la primera pieza del módulo "Passive DNS" del diseño SOC. En Fase 4
//! persistirá en disco (DuckDB/SQLite) y alimentará la vista de la UI
//! "¿quién resuelve qué?" en tiempo real.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use socshark_core::DnsSummary;

use crate::evict_oldest_half;

/// Cota de IPs y de dominios recordados (cada mapa). El daemon vive semanas
/// y ve millones de respuestas: al superarla se olvida la mitad menos
/// recientemente vista.
pub const MAX_PDNS_ENTRIES: usize = 65_536;
/// Cota de dominios por IP (CDN compartidas) y de IPs por dominio.
pub const MAX_PDNS_PER_ENTRY: usize = 64;

/// Base de DNS pasivo de la sesión.
#[derive(Default)]
pub struct PassiveDnsDb {
    /// IP → dominios que la han devuelto (BTree para orden determinista)
    /// y reloj lógico de la última vez que se vio.
    ip_to_domains: HashMap<IpAddr, (BTreeMap<String, ()>, u64)>,
    /// Dominio → IPs que respondieron las consultas (+ reloj lógico).
    domain_to_ips: HashMap<String, (BTreeMap<IpAddr, ()>, u64)>,
    tick: u64,
}

/// Normaliza un nombre DNS para compararlo (minúsculas, sin punto final).
fn norm(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Inserta en un conjunto acotado.
fn insert_capped<K: Ord>(set: &mut BTreeMap<K, ()>, key: K) {
    if set.len() < MAX_PDNS_PER_ENTRY || set.contains_key(&key) {
        set.insert(key, ());
    }
}

impl PassiveDnsDb {
    /// Registra las respuestas de un intercambio DNS.
    ///
    /// Solo las respuestas (`is_response`) aportan asociaciones; las
    /// consultas sueltas no etiquetan nada (la pregunta no implica que la IP
    /// pertenezca al dominio).
    ///
    /// Solo se confía en los registros A/AAAA cuyo propietario es el nombre
    /// preguntado o se alcanza desde él siguiendo la cadena de CNAME de la
    /// propia respuesta. Un servidor malicioso (o una respuesta forjada)
    /// puede colar registros adicionales del tipo «a.microsoft.com → IP del
    /// C2»: sin esta comprobación la IP del C2 quedaría etiquetada con un
    /// dominio legítimo.
    pub fn observe(&mut self, dns: &DnsSummary) {
        if !dns.is_response {
            return;
        }
        // Nombres alcanzables: las preguntas y, por cierre transitivo, los
        // destinos de CNAME cuyo propietario ya es alcanzable.
        let mut chain: HashSet<String> = dns.queries.iter().map(|q| norm(&q.name)).collect();
        loop {
            let before = chain.len();
            for a in &dns.answers {
                if a.rtype == 5 && chain.contains(&norm(&a.name)) {
                    if let Some(t) = &a.target {
                        chain.insert(norm(t));
                    }
                }
            }
            if chain.len() == before {
                break;
            }
        }

        self.tick += 1;
        let tick = self.tick;
        for answer in &dns.answers {
            let owner = norm(&answer.name);
            if !chain.contains(&owner) {
                continue;
            }
            if let Some(ip) = answer.address.filter(|_| matches!(answer.rtype, 1 | 28)) {
                self.make_room();
                let e = self.ip_to_domains.entry(ip).or_default();
                insert_capped(&mut e.0, answer.name.clone());
                e.1 = tick;
                let e = self.domain_to_ips.entry(answer.name.clone()).or_default();
                insert_capped(&mut e.0, ip);
                e.1 = tick;
            }
            // Los CNAME de la cadena crean relaciones dominio→dominio: se
            // registran como dominios conocidos aunque no haya IP directa.
            if let Some(target) = answer.target.as_ref().filter(|_| answer.rtype == 5) {
                self.make_room();
                self.domain_to_ips.entry(target.clone()).or_default().1 = tick;
            }
        }
    }

    /// Desaloja la mitad menos reciente de cada mapa que haya llegado a la
    /// cota [`MAX_PDNS_ENTRIES`].
    fn make_room(&mut self) {
        if self.ip_to_domains.len() >= MAX_PDNS_ENTRIES {
            evict_oldest_half(&mut self.ip_to_domains, |v| v.1);
        }
        if self.domain_to_ips.len() >= MAX_PDNS_ENTRIES {
            evict_oldest_half(&mut self.domain_to_ips, |v| v.1);
        }
    }

    /// Número de dominios conocidos (con o sin IP).
    pub fn domain_count(&self) -> usize {
        self.domain_to_ips.len()
    }

    /// Primer dominio conocido para una IP (orden lexicográfico: resultado
    /// determinista entre ejecuciones).
    pub fn resolve(&self, ip: IpAddr) -> Option<&String> {
        self.ip_to_domains
            .get(&ip)
            .and_then(|set| set.0.keys().next())
    }

    /// Todos los dominios conocidos para una IP.
    pub fn domains_for(&self, ip: IpAddr) -> Vec<&String> {
        self.ip_to_domains
            .get(&ip)
            .map(|set| set.0.keys().collect())
            .unwrap_or_default()
    }

    /// IPs conocidas para un dominio.
    pub fn ips_for(&self, domain: &str) -> Vec<&IpAddr> {
        self.domain_to_ips
            .get(domain)
            .map(|set| set.0.keys().collect())
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

    fn registro(
        name: &str,
        rtype: u16,
        addr: Option<&str>,
        target: Option<&str>,
    ) -> DnsAnswerSummary {
        DnsAnswerSummary {
            name: name.into(),
            rtype,
            ttl: 60,
            address: addr.map(|a| a.parse().unwrap()),
            target: target.map(String::from),
        }
    }

    #[test]
    fn registros_fuera_de_la_cadena_no_etiquetan() {
        // Regresión: un registro extra «a.microsoft.com → IP del C2» dentro
        // de la respuesta a evil.test etiquetaba el C2 como Microsoft.
        let mut db = PassiveDnsDb::default();
        let mut r = respuesta("203.0.113.9".parse().unwrap(), "evil.test");
        r.answers
            .push(registro("a.microsoft.com", 1, Some("203.0.113.66"), None));
        db.observe(&r);
        assert!(db.resolve("203.0.113.66".parse().unwrap()).is_none());
        assert_eq!(
            db.resolve("203.0.113.9".parse().unwrap())
                .map(String::as_str),
            Some("evil.test")
        );
    }

    #[test]
    fn cadena_cname_si_se_sigue() {
        let mut db = PassiveDnsDb::default();
        db.observe(&DnsSummary {
            is_response: true,
            rcode: Some(0),
            queries: vec![DnsQuerySummary {
                name: "WWW.Example.com.".into(),
                qtype: 1,
            }],
            answers: vec![
                registro("www.example.com", 5, None, Some("edge.cdn.test")),
                registro("edge.cdn.test", 5, None, Some("e1.cdn.test")),
                registro("e1.cdn.test", 1, Some("198.51.100.7"), None),
                registro("otro.test", 1, Some("198.51.100.8"), None),
            ],
        });
        assert_eq!(
            db.resolve("198.51.100.7".parse().unwrap())
                .map(String::as_str),
            Some("e1.cdn.test")
        );
        assert!(db.resolve("198.51.100.8".parse().unwrap()).is_none());
    }

    #[test]
    fn base_acotada_en_el_daemon() {
        let mut db = PassiveDnsDb::default();
        for i in 0..(MAX_PDNS_ENTRIES as u32 + 500) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            db.observe(&respuesta(ip, &format!("h{i}.example.com")));
        }
        assert!(db.len() <= MAX_PDNS_ENTRIES);
        assert!(db.domain_count() <= MAX_PDNS_ENTRIES);
        let last = IpAddr::V4(std::net::Ipv4Addr::from(
            0x0a00_0000 + MAX_PDNS_ENTRIES as u32 + 499,
        ));
        assert!(db.resolve(last).is_some(), "lo reciente se conserva");
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
