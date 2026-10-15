//! Passive DNS: correlación IP → dominio a partir de respuestas DNS vistas.
//!
//! El problema de Wireshark: si filtras por una IP, pierdes la consulta DNS
//! previa y solo ves números. Aquí el motor guarda cada respuesta (A/AAAA/
//! CNAME) para que cualquier flujo posterior hacia esa IP muestre el dominio
//! — y si un proceso se conecta a una IP **sin** haberla visto en DNS, es
//! señal clásica de C2/malware (la alerta la dispara `soc-engine`).

use socshark_common::ipaddr::IpAddr;
use socshark_dissectors::view::DissectedPacket;
use std::collections::HashMap;

/// Un avistamiento de dominio para una IP.
#[derive(Debug, Clone)]
pub struct DnsSeen {
    pub domain: String,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
}

/// Caché passive DNS en memoria (fase 2: volcado a SQLite/DuckDB).
#[derive(Default)]
pub struct PassiveDns {
    records: HashMap<IpAddr, Vec<DnsSeen>>,
    /// Número total de pares observados (estadística).
    total: usize,
}

const MAX_RECORDS_PER_IP: usize = 8;
const MAX_TOTAL: usize = 100_000;

impl PassiveDns {
    pub fn new() -> Self {
        PassiveDns::default()
    }

    /// Registra los pares IP→dominio de una respuesta DNS.
    pub fn observe(&mut self, dp: &DissectedPacket) {
        if self.total >= MAX_TOTAL {
            return;
        }
        let Some(AppInfo::Dns(d)) = dp.app.as_ref() else {
            return;
        };
        if !d.is_response {
            return;
        }
        for (ip_str, domain) in d.passive_dns_pairs() {
            // Solo nos interesan IPs (los CNAME se encadenan solos vía sus
            // propios registros A).
            let Some(ip) = IpAddr::parse(&ip_str) else {
                continue;
            };
            let list = self.records.entry(ip).or_default();
            self.total += 1;
            if let Some(existing) = list.iter_mut().find(|r| r.domain == domain) {
                existing.last_seen_us = dp.ts_us;
                continue;
            }
            if list.len() >= MAX_RECORDS_PER_IP {
                // Reemplaza el más antiguo (rotación simple).
                let oldest = list
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, r)| r.first_seen_us)
                    .map(|(i, _)| i);
                if let Some(i) = oldest {
                    list[i] = DnsSeen {
                        domain,
                        first_seen_us: dp.ts_us,
                        last_seen_us: dp.ts_us,
                    };
                }
                continue;
            }
            list.push(DnsSeen {
                domain,
                first_seen_us: dp.ts_us,
                last_seen_us: dp.ts_us,
            });
        }
    }

    /// Dominio conocido para `ip` en el instante `at_us` (el más reciente
    /// cuyo primer avistamiento sea anterior o igual).
    pub fn lookup(&self, ip: &IpAddr, at_us: u64) -> Option<&DnsSeen> {
        let list = self.records.get(ip)?;
        let mut best: Option<&DnsSeen> = None;
        for r in list {
            if r.first_seen_us <= at_us {
                best = match best {
                    Some(b) if b.first_seen_us > r.first_seen_us => Some(b),
                    _ => Some(r),
                };
            }
        }
        best
    }

    /// ¿Se ha visto esta IP en alguna respuesta DNS (en cualquier momento)?
    pub fn has_any(&self, ip: &IpAddr) -> bool {
        self.records.contains_key(ip)
    }

    pub fn total_pairs(&self) -> usize {
        self.total
    }

    pub fn unique_ips(&self) -> usize {
        self.records.len()
    }
}

use socshark_dissectors::view::AppInfo;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_con_ventana_temporal() {
        let mut pd = PassiveDns::new();
        let ip = IpAddr::parse("185.220.101.4").unwrap();
        pd.records.entry(ip).or_default().push(DnsSeen {
            domain: "old.example.com".into(),
            first_seen_us: 1_000,
            last_seen_us: 1_500,
        });
        pd.records.entry(ip).or_default().push(DnsSeen {
            domain: "new.example.com".into(),
            first_seen_us: 5_000,
            last_seen_us: 5_000,
        });

        assert_eq!(pd.lookup(&ip, 2_000).unwrap().domain, "old.example.com");
        assert_eq!(pd.lookup(&ip, 6_000).unwrap().domain, "new.example.com");
        assert!(pd.lookup(&ip, 500).is_none());
        assert!(pd.has_any(&ip));
        let other = IpAddr::parse("1.2.3.4").unwrap();
        assert!(!pd.has_any(&other));
    }
}
