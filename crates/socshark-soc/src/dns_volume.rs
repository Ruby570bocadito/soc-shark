//! Túnel DNS **por volumen**: subdominios únicos por cliente y dominio.
//!
//! La regla R1 mira cada consulta por separado (longitud + entropía). Un
//! túnel que codifica con poca entropía o en etiquetas cortas (dnscat2 o
//! iodine con alfabetos reducidos, contadores secuenciales `a0001`,
//! `a0002`...) la esquiva, pero no puede esconder su volumen: para mover
//! datos necesita **muchos subdominios distintos del mismo dominio**, porque
//! cada respuesta cacheada no le sirve. Un navegador resuelve muchos nombres,
//! pero repartidos entre muchos dominios y repitiendo los mismos.
//!
//! Se cuenta, por (cliente, dominio registrable), cuántos subdominios únicos
//! se consultaron dentro de una ventana deslizante (`dns_volume_window_secs`)
//! y se alerta al alcanzar `dns_volume_threshold`. Se excluyen:
//! - PTR y demás `.arpa` (resolución inversa) y mDNS (`.local`);
//! - consultas DNSBL (IPv4 invertida o nibbles IPv6 delante de la lista):
//!   un servidor de correo pregunta por cada IP que le escribe;
//! - subdominios más cortos que `dns_volume_min_subdomain_len`: `www`,
//!   `api` o `img1` no transportan datos útiles.
//!
//! Estado acotado para el daemon: [`MAX_DNS_VOLUME_KEYS`] claves con
//! desalojo de la mitad menos reciente; por clave se guardan solo hashes de
//! 64 bits (no los nombres) y se deja de contar al llegar al umbral.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

use socshark_core::config::PipelineConfig;
use socshark_core::{EnrichedFlow, L7Protocol};

use crate::domain::{registrable_domain, subdomain_labels};
use crate::evict_oldest_half;

/// Claves (cliente, dominio registrable) recordadas como máximo.
pub const MAX_DNS_VOLUME_KEYS: usize = 8192;
/// Tope duro de hashes por clave, aunque el umbral configurado sea mayor.
pub const MAX_SUBDOMAINS_PER_KEY: usize = 1024;

type Key = (IpAddr, String);

#[derive(Default)]
struct Entry {
    /// hash del subdominio → último instante (µs) en que se consultó.
    subs: HashMap<u64, u64>,
    /// Instante más reciente visto en la clave: referencia de la ventana
    /// (las capturas pueden entregar los flujos desordenados).
    newest: u64,
    /// Máximo de subdominios únicos simultáneos dentro de la ventana.
    peak: u32,
    /// Reloj lógico de la última actualización (desalojo).
    tick: u64,
}

/// Señal de túnel por volumen para un flujo DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsVolumeSignal {
    /// Dominio registrable afectado.
    pub base_domain: String,
    /// Subdominios únicos dentro de la ventana (pico; tope = umbral).
    pub unique_subdomains: u32,
    /// Ventana de conteo, en segundos.
    pub window_secs: u64,
}

/// Contador de subdominios únicos por (cliente, dominio registrable).
#[derive(Default)]
pub struct DnsVolumeTracker {
    keys: HashMap<Key, Entry>,
    tick: u64,
}

/// Cliente de la consulta: el extremo que no es el puerto 53 (los flujos
/// capturados a mitad pueden tener al servidor como origen).
fn client(flow: &EnrichedFlow) -> IpAddr {
    if flow.src_port == 53 && flow.dst_port != 53 {
        flow.dst_ip
    } else {
        flow.src_ip
    }
}

/// (dominio registrable, subdominio) si el qname cuenta para el volumen.
fn candidate(qname: &str, cfg: &PipelineConfig) -> Option<(String, String)> {
    let name = qname.trim_end_matches('.').to_ascii_lowercase();
    if name.ends_with(".arpa") || name.ends_with(".local") || name == "local" {
        return None;
    }
    let labels = subdomain_labels(&name);
    if labels.is_empty() {
        return None;
    }
    let chars: usize = labels.iter().map(|l| l.len()).sum();
    if chars < cfg.dns_volume_min_subdomain_len {
        return None;
    }
    // DNSBL: `4.3.2.1.zen.spamhaus.org` (IPv4 invertida delante de la zona
    // de la lista) o 32 nibbles IPv6.
    let octet = |l: &&str| (1..=3).contains(&l.len()) && l.bytes().all(|b| b.is_ascii_digit());
    let nibble = |l: &&str| l.len() == 1 && l.as_bytes()[0].is_ascii_hexdigit();
    let reversed_v4 = labels.len() >= 4 && labels[..4].iter().all(octet);
    let reversed_v6 = labels.len() >= 32 && labels[..32].iter().all(nibble);
    if reversed_v4 || reversed_v6 {
        return None;
    }
    Some((registrable_domain(&name).to_string(), labels.join(".")))
}

fn hash_of(s: &str) -> u64 {
    // DefaultHasher::new() usa claves fijas: determinista entre ejecuciones.
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// Qnames de un flujo DNS (vacío si no es DNS).
fn qnames(flow: &EnrichedFlow) -> impl Iterator<Item = &str> {
    flow.dns
        .as_ref()
        .filter(|_| flow.l7_protocol == L7Protocol::Dns)
        .into_iter()
        .flat_map(|d| d.queries.iter().map(|q| q.name.as_str()))
}

impl DnsVolumeTracker {
    /// Registra las consultas de un flujo DNS exportado.
    pub fn observe(&mut self, flow: &EnrichedFlow, cfg: &PipelineConfig) {
        if cfg.dns_volume_threshold == 0 {
            return;
        }
        let cap = (cfg.dns_volume_threshold as usize).min(MAX_SUBDOMAINS_PER_KEY);
        let window = cfg.dns_volume_window_secs.saturating_mul(1_000_000);
        let t = flow.first_seen_micros;
        let who = client(flow);
        for qname in qnames(flow) {
            let Some((base, sub)) = candidate(qname, cfg) else {
                continue;
            };
            self.tick += 1;
            let k = (who, base);
            if self.keys.len() >= MAX_DNS_VOLUME_KEYS && !self.keys.contains_key(&k) {
                evict_oldest_half(&mut self.keys, |e| e.tick);
            }
            let e = self.keys.entry(k).or_default();
            e.tick = self.tick;
            e.newest = e.newest.max(t);
            let h = hash_of(&sub);
            if let Some(last) = e.subs.get_mut(&h) {
                *last = (*last).max(t);
                continue;
            }
            // Subdominio nuevo: primero se olvida lo que salió de la ventana.
            let cutoff = e.newest.saturating_sub(window);
            e.subs.retain(|_, last| *last >= cutoff);
            if e.subs.len() < cap && t >= cutoff {
                e.subs.insert(h, t);
            }
            e.peak = e.peak.max(e.subs.len() as u32);
        }
    }

    /// Señal para un flujo DNS cuyo (cliente, dominio) alcanzó el umbral.
    pub fn signal(&self, flow: &EnrichedFlow, cfg: &PipelineConfig) -> Option<DnsVolumeSignal> {
        if cfg.dns_volume_threshold == 0 {
            return None;
        }
        let who = client(flow);
        qnames(flow).find_map(|qname| {
            let (base, _) = candidate(qname, cfg)?;
            let peak = self.keys.get(&(who, base.clone()))?.peak;
            let threshold = cfg.dns_volume_threshold.min(MAX_SUBDOMAINS_PER_KEY as u32);
            (peak >= threshold).then_some(DnsVolumeSignal {
                base_domain: base,
                unique_subdomains: peak,
                window_secs: cfg.dns_volume_window_secs,
            })
        })
    }

    /// Claves recordadas (para métricas y tests).
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::flujo_basico;
    use socshark_core::{DnsQuerySummary, DnsSummary};

    fn consulta(name: &str, t_secs: u64) -> EnrichedFlow {
        let mut f = flujo_basico(17, 40000, 53);
        f.l7_protocol = L7Protocol::Dns;
        f.first_seen_micros = t_secs * 1_000_000;
        f.dns = Some(DnsSummary {
            is_response: false,
            rcode: None,
            queries: vec![DnsQuerySummary {
                name: name.into(),
                qtype: 16,
            }],
            answers: vec![],
        });
        f
    }

    #[test]
    fn candidatos_excluyen_ptr_mdns_dnsbl_y_cortos() {
        let cfg = PipelineConfig::default();
        assert_eq!(
            candidate("a0001.t.evil.com.", &cfg),
            Some(("evil.com".into(), "a0001.t".into()))
        );
        for n in [
            "34.216.184.93.in-addr.arpa",
            "b.6.5.4.3.2.1.0.0.0.0.0.0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            "HP-OfficeJet.local",
            "4.3.2.1.zen.spamhaus.org",
            "www.example.com",
            "img1.example.com",
            "example.com",
        ] {
            assert_eq!(candidate(n, &cfg), None, "{n}");
        }
    }

    #[test]
    fn ventana_deslizante_olvida_lo_antiguo() {
        let cfg = PipelineConfig {
            dns_volume_threshold: 10,
            dns_volume_window_secs: 60,
            ..PipelineConfig::default()
        };
        let mut t = DnsVolumeTracker::default();
        // 9 únicos por minuto durante 10 minutos: nunca 10 en la ventana.
        for i in 0..90u64 {
            t.observe(&consulta(&format!("a{i:04}.t.evil.com"), i * 7), &cfg);
        }
        assert!(t.signal(&consulta("a0000.t.evil.com", 0), &cfg).is_none());
        // 10 seguidos en 10 s: alerta.
        for i in 0..10u64 {
            t.observe(&consulta(&format!("b{i:04}.t.evil.com"), 1000 + i), &cfg);
        }
        let s = t.signal(&consulta("b0000.t.evil.com", 0), &cfg).unwrap();
        assert_eq!(s.unique_subdomains, 10);
        assert_eq!(s.base_domain, "evil.com");
    }

    #[test]
    fn estado_acotado_en_claves_y_subdominios() {
        let cfg = PipelineConfig::default();
        let mut t = DnsVolumeTracker::default();
        for i in 0..(MAX_DNS_VOLUME_KEYS as u32 + 100) {
            t.observe(&consulta(&format!("host-{i}.dom{i}.com"), 1), &cfg);
        }
        assert!(t.len() <= MAX_DNS_VOLUME_KEYS);
        for i in 0..5000u64 {
            t.observe(&consulta(&format!("x{i:06}.evil.com"), 2), &cfg);
        }
        let e = t
            .keys
            .get(&(client(&consulta("x.evil.com", 0)), "evil.com".into()))
            .unwrap();
        assert_eq!(e.subs.len(), cfg.dns_volume_threshold as usize);
    }
}
