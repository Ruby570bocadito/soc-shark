//! Threat Intel offline-first: listas locales de IOCs.
//!
//! Formato del archivo (una entrada por línea, `#` comentarios):
//! ```text
//! # IPs y rangos (CIDR) o dominios
//! 185.220.101.0/24        # Tor exit nodes (ejemplo)
//! 185.22.1.9              # C2 demo
//! evil-cdn.ru             # dominio (fase 3: correlación con passive DNS)
//! ```
//!
//! Fase 3: MMDB de MaxMind/DB-IP para GeoIP/ASN offline + feeds Feodo/
//! Tor/AbuseIPDB con actualización programada.

use socshark_common::ipaddr::IpAddr;
use std::path::Path;

/// Lista de IOCs en memoria.
#[derive(Debug, Clone, Default)]
pub struct ThreatIntel {
    /// Rangos IPv4 como (inicio, fin) en u32.
    v4_ranges: Vec<(u32, u32)>,
    /// Rangos IPv6 como (inicio, fin) lexicográficos sobre 16 bytes.
    v6_ranges: Vec<([u8; 16], [u8; 16])>,
    note: String,
    count: usize,
}

impl ThreatIntel {
    /// Lista vacía (no marca nada).
    pub fn empty() -> Self {
        ThreatIntel {
            note: "sin listas".into(),
            ..Default::default()
        }
    }

    /// Carga una lista desde disco; ignora líneas inválidas con aviso.
    pub fn load(path: &Path) -> Result<ThreatIntel, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("no se pudo leer la lista de IOCs {:?}: {e}", path))?;
        let mut ti = ThreatIntel {
            note: format!(
                "{}",
                path.file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "iocs".into())
            ),
            ..Default::default()
        };
        for line in raw.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.contains(':') {
                // IPv6 (con o sin prefijo)
                if let Some((start, end)) = v6_range(line) {
                    ti.v6_ranges.push((start, end));
                    ti.count += 1;
                }
            } else if let Some((start, end)) = v4_range(line) {
                ti.v4_ranges.push((start, end));
                ti.count += 1;
            }
            // Dominios: fase 3 (requiere correlación con passive DNS).
        }
        Ok(ti)
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn note(&self) -> &str {
        &self.note
    }

    /// ¿La IP está en alguna lista?
    pub fn check_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(b) => {
                let v = u32::from_be_bytes(*b);
                self.v4_ranges.iter().any(|(s, e)| v >= *s && v <= *e)
            }
            IpAddr::V6(b) => self
                .v6_ranges
                .iter()
                .any(|(s, e)| b.as_slice() >= s.as_slice() && b.as_slice() <= e.as_slice()),
        }
    }
}

/// "1.2.3.4" o "1.2.3.0/24" → (inicio, fin).
fn v4_range(s: &str) -> Option<(u32, u32)> {
    let (addr, plen) = match s.split_once('/') {
        Some((a, p)) => (a, p.parse::<u32>().ok()?),
        None => (s, 32),
    };
    if plen > 32 {
        return None;
    }
    let base = IpAddr::parse_v4(addr)?;
    let v = u32::from_be_bytes(*base.v4_bytes());
    let mask = if plen == 0 {
        0u32
    } else {
        u32::MAX << (32 - plen)
    };
    let start = v & mask;
    let end = start | !mask;
    Some((start, end))
}

/// "x::y" o "x::y/n" → rango lexicográfico de 16 bytes.
fn v6_range(s: &str) -> Option<([u8; 16], [u8; 16])> {
    let (addr, plen) = match s.split_once('/') {
        Some((a, p)) => (a, p.parse::<u32>().ok()?),
        None => (s, 128),
    };
    if plen > 128 {
        return None;
    }
    let base = IpAddr::parse_v6(addr)?;
    let IpAddr::V6(bytes) = base else { return None };
    let mut start = bytes;
    let mut end = bytes;
    let full = (plen / 8) as usize;
    for i in full..16 {
        if i * 8 < plen as usize {
            let rem = plen as usize - i * 8;
            let mask = 0xffu8 << (8 - rem);
            start[i] &= mask;
            end[i] |= !mask;
        } else {
            start[i] = 0;
            end[i] = 0xff;
        }
    }
    Some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Escribe un archivo temporal std-only y lo borra al final.
    fn with_temp_list(body: &str, f: impl FnOnce(&Path)) {
        let path = std::env::temp_dir().join(format!(
            "socshark_iocs_test_{}_{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::write(&path, body).unwrap();
        f(&path);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn carga_y_verifica() {
        with_temp_list(
            "# lista demo\n185.220.101.0/24   # tor\n185.22.1.9\n2001:db8:dead::/48\nesto-no-es-una-ip\n",
            |path| {
        let ti = ThreatIntel::load(path).unwrap();
        assert_eq!(ti.count(), 3);
        assert!(ti.check_ip(&IpAddr::parse("185.220.101.4").unwrap()));
        assert!(ti.check_ip(&IpAddr::parse("185.220.101.255").unwrap()));
        assert!(!ti.check_ip(&IpAddr::parse("185.220.102.1").unwrap()));
        assert!(ti.check_ip(&IpAddr::parse("185.22.1.9").unwrap()));
        assert!(!ti.check_ip(&IpAddr::parse("185.22.1.10").unwrap()));
        assert!(ti.check_ip(&IpAddr::parse("2001:db8:dead::1").unwrap()));
        assert!(!ti.check_ip(&IpAddr::parse("2001:db8:beef::1").unwrap()));
            },
        );
    }

    #[test]
    fn vacia_no_marca_nada() {
        let ti = ThreatIntel::empty();
        assert!(!ti.check_ip(&IpAddr::parse("8.8.8.8").unwrap()));
    }

    #[test]
    fn rangos_v4_por_prefijo() {
        let (s, e) = v4_range("10.0.0.0/8").unwrap();
        assert_eq!(s, 0x0a00_0000);
        assert_eq!(e, 0x0aff_ffff);
        let (s, e) = v4_range("192.168.1.5").unwrap();
        assert_eq!(s, e);
    }
}
