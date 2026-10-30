//! Threat intel offline: listas de indicadores cargadas de ficheros locales.
//!
//! Cubre la parte de la Fase 4 que no exige datos binarios propietarios:
//! listas de texto plano de IPs/CIDR de C2 (formato Feodo Tracker) y de
//! nodos de salida de Tor (formato Bulk Exit List). Cada línea válida aporta
//! una IP exacta o un CIDR v4/v6; los comentarios (`#`), las líneas vacías,
//! las que no contienen IP y las que no son UTF-8 válido se toleran sin
//! error (las listas públicas cambian de formato con frecuencia y un parser
//! estricto rompería el pipeline). Las redes demasiado amplias (`0.0.0.0/0`,
//! prefijos más cortos que /8 en IPv4 o /16 en IPv6) se rechazan con un
//! aviso en [`ThreatIntelDb::warnings`]: una sola línea así marcaría media
//! Internet como C2.
//!
//! El enriquecimiento marca `EnrichedFlow::threat_intel` con las etiquetas
//! coincidentes (`FEODO-C2`, `TOR-EXIT`) de **cualquiera de los dos
//! extremos** (un C2 o una salida Tor también pueden iniciar la conexión
//! hacia dentro) y la regla `R7` del mini-IDS las convierte en alertas. GeoIP/ASN (`.mmdb`) queda pendiente de un lector
//! propio sin dependencias (ver roadmap, Fase 4).
//!
//! Este módulo no hace red: las listas se descargan fuera (cron, curl, el
//! propio SOC) y se alimentan por `--intel-feodo` / `--intel-tor`.

use std::collections::HashSet;
use std::io::BufRead;
use std::net::IpAddr;
use std::path::Path;

/// Etiqueta aplicada a los flujos cuyo destino está en la lista Feodo.
pub const TAG_FEODO: &str = "FEODO-C2";
/// Etiqueta aplicada a los flujos cuyo destino es un nodo de salida Tor.
pub const TAG_TOR: &str = "TOR-EXIT";

/// Prefijo IPv4 más corto aceptado en una lista (más amplio = rechazado).
pub const MIN_PREFIX_V4: u8 = 8;
/// Prefijo IPv6 más corto aceptado en una lista.
pub const MIN_PREFIX_V6: u8 = 16;
/// Tope de avisos guardados (una lista corrupta no llena la memoria).
const MAX_WARNINGS: usize = 32;

/// Base de indicadores en memoria: IPs exactas por lista y redes CIDR.
#[derive(Debug, Default, Clone)]
pub struct ThreatIntelDb {
    feodo_ips: HashSet<IpAddr>,
    feodo_nets: Vec<(IpAddr, u8)>,
    tor_ips: HashSet<IpAddr>,
    tor_nets: Vec<(IpAddr, u8)>,
    /// Contadores de carga: útil para verificar en CLI que la lista se leyó.
    pub feodo_entries: usize,
    pub tor_entries: usize,
    /// Avisos de carga (redes demasiado amplias rechazadas). La CLI debería
    /// mostrarlos tras cargar las listas.
    pub warnings: Vec<String>,
}

impl ThreatIntelDb {
    /// Carga una lista tipo Feodo Tracker (ipblocklist): una IP o CIDR por
    /// línea, `#` para comentarios. Devuelve el número de entradas válidas.
    pub fn load_feodo(&mut self, path: &Path) -> std::io::Result<usize> {
        let added = Self::load_into(
            &mut self.feodo_ips,
            &mut self.feodo_nets,
            &mut self.warnings,
            path,
        )?;
        self.feodo_entries += added;
        Ok(added)
    }

    /// Carga una lista tipo Tor Bulk Exit List: líneas `ExitAddress <ip>`
    /// (se extrae la primera IP de cada línea). Devuelve entradas válidas.
    pub fn load_tor(&mut self, path: &Path) -> std::io::Result<usize> {
        let added = Self::load_into(
            &mut self.tor_ips,
            &mut self.tor_nets,
            &mut self.warnings,
            path,
        )?;
        self.tor_entries += added;
        Ok(added)
    }

    /// Construye la base desde las dos rutas de la configuración, tolerando
    /// rutas ausentes (`None`).
    pub fn from_paths(feodo: Option<&Path>, tor: Option<&Path>) -> std::io::Result<Self> {
        let mut db = Self::default();
        if let Some(p) = feodo {
            db.load_feodo(p)?;
        }
        if let Some(p) = tor {
            db.load_tor(p)?;
        }
        Ok(db)
    }

    /// Número total de entradas cargadas (IPs + redes).
    pub fn len(&self) -> usize {
        self.feodo_entries + self.tor_entries
    }

    /// True si no se cargó nada (base vacía).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Etiquetas que coinciden con una IP destino.
    pub fn check(&self, ip: IpAddr) -> Vec<&'static str> {
        let mut tags = Vec::with_capacity(2);
        if Self::match_list(ip, &self.feodo_ips, &self.feodo_nets) {
            tags.push(TAG_FEODO);
        }
        if Self::match_list(ip, &self.tor_ips, &self.tor_nets) {
            tags.push(TAG_TOR);
        }
        tags
    }

    /// Etiquetas que coinciden con cualquiera de los dos extremos de un
    /// flujo (sin duplicados, orden estable: Feodo antes que Tor).
    pub fn check_flow(&self, src: IpAddr, dst: IpAddr) -> Vec<&'static str> {
        let mut tags = self.check(dst);
        for t in self.check(src) {
            if !tags.contains(&t) {
                tags.push(t);
            }
        }
        tags.sort_by_key(|t| usize::from(*t != TAG_FEODO));
        tags
    }

    /// Extremo del flujo que figura en la lista de `tag`: el destino si
    /// está listado (caso habitual), si no el origen. `None` si ninguno.
    pub fn listed_endpoint(&self, src: IpAddr, dst: IpAddr, tag: &str) -> Option<IpAddr> {
        if self.check(dst).contains(&tag) {
            Some(dst)
        } else if self.check(src).contains(&tag) {
            Some(src)
        } else {
            None
        }
    }

    fn match_list(ip: IpAddr, ips: &HashSet<IpAddr>, nets: &[(IpAddr, u8)]) -> bool {
        if ips.contains(&ip) {
            return true;
        }
        nets.iter()
            .any(|(base, prefix)| in_network(ip, *base, *prefix))
    }

    fn load_into(
        ips: &mut HashSet<IpAddr>,
        nets: &mut Vec<(IpAddr, u8)>,
        warnings: &mut Vec<String>,
        path: &Path,
    ) -> std::io::Result<usize> {
        let f = std::fs::File::open(path)?;
        let mut reader = std::io::BufReader::new(f);
        let mut added = 0usize;
        // Dedup O(1) de redes (antes `nets.contains` hacía la carga O(n²)).
        let mut seen_nets: HashSet<(IpAddr, u8)> = nets.iter().copied().collect();
        let mut raw = Vec::new();
        let mut line_no = 0usize;
        loop {
            raw.clear();
            // Bytes crudos: una línea no UTF-8 no aborta la carga.
            if reader.read_until(b'\n', &mut raw)? == 0 {
                break;
            }
            line_no += 1;
            let line = String::from_utf8_lossy(&raw);
            // Quita el comentario de cola y busca el primer token que sea
            // IP o CIDR (Feodo pone la IP al principio; el Bulk Exit List de
            // Tor la pone tras "ExitAddress").
            let sin_comentario = line.split('#').next().unwrap_or("");
            for token in sin_comentario.split([' ', '\t', ',']) {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                if let Ok(ip) = token.parse::<IpAddr>() {
                    if ips.insert(ip) {
                        added += 1;
                    }
                    break;
                }
                if let Some((base, prefix)) = parse_cidr(token) {
                    let min = match base {
                        IpAddr::V4(_) => MIN_PREFIX_V4,
                        IpAddr::V6(_) => MIN_PREFIX_V6,
                    };
                    if prefix < min {
                        if warnings.len() < MAX_WARNINGS {
                            warnings.push(format!(
                                "{}:{line_no}: red {base}/{prefix} demasiado amplia (mínimo /{min}), ignorada",
                                path.display()
                            ));
                        }
                        break;
                    }
                    // Las listas públicas repiten redes a veces.
                    if seen_nets.insert((base, prefix)) {
                        nets.push((base, prefix));
                        added += 1;
                    }
                    break;
                }
                // Token sin IP (p. ej. "ExitAddress" o una fecha): sigue.
            }
            // Línea sin ninguna IP interpretable: se ignora deliberadamente.
        }
        Ok(added)
    }
}

/// Parsea un CIDR `a.b.c.d/nn` (v4 o v6). Devuelve la base normalizada
/// (bits de host a cero) y el prefijo.
fn parse_cidr(token: &str) -> Option<(IpAddr, u8)> {
    let (addr_str, prefix_str) = token.split_once('/')?;
    let addr: IpAddr = addr_str.parse().ok()?;
    let prefix: u8 = prefix_str.parse().ok()?;
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return None;
    }
    let base = normalize_network(addr, prefix);
    Some((base, prefix))
}

/// Pone a cero los bits de host de `addr` según `prefix` (v4 y v6).
fn normalize_network(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let masked = if prefix == 0 {
                0
            } else {
                bits & (u32::MAX << (32 - prefix as u32))
            };
            IpAddr::V4(masked.into())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let masked = if prefix == 0 {
                0
            } else {
                bits & (u128::MAX << (128 - prefix as u32))
            };
            IpAddr::V6(masked.into())
        }
    }
}

/// True si `ip` cae dentro de `base/prefix`.
fn in_network(ip: IpAddr, base: IpAddr, prefix: u8) -> bool {
    match (ip, base) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let max = 32u8;
            if prefix > max {
                return false;
            }
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix as u32)
            };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let max = 128u8;
            if prefix > max {
                return false;
            }
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix as u32)
            };
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false, // familias distintas no coinciden
    }
}

// --------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn write_temp(name: &str, content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("socshark-intel-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn lista_feodo_con_comentarios_cidr_y_basura() {
        let p = write_temp(
            "feodo.txt",
            "# Feodo Tracker recommended blocklist\n\
             185.222.57.24\n\
             45.133.1.0/24\n\
             \n\
             basura-sin-ip\n\
             192.168.5.7 # comentario inline\n",
        );
        let mut db = ThreatIntelDb::default();
        let n = db.load_feodo(&p).unwrap();
        assert_eq!(n, 3, "3 entradas válidas (IP, CIDR, IP)");
        assert!(db
            .check("185.222.57.24".parse().unwrap())
            .contains(&TAG_FEODO));
        assert!(
            db.check("45.133.1.200".parse().unwrap())
                .contains(&TAG_FEODO),
            "CIDR /24 cubre el rango"
        );
        assert!(!db
            .check("45.134.1.200".parse().unwrap())
            .contains(&TAG_FEODO));
        assert!(db
            .check("192.168.5.7".parse().unwrap())
            .contains(&TAG_FEODO));
        assert!(!db.check("8.8.8.8".parse().unwrap()).contains(&TAG_FEODO));
    }

    #[test]
    fn lista_tor_formato_bulk_exit_list() {
        let p = write_temp(
            "tor.txt",
            "ExitAddress 51.15.59.198 2024-01-15 12:00:00\n\
             ExitAddress 199.249.230.101 2024-01-16 08:30:00\n\
             DegenerateLine\n",
        );
        let mut db = ThreatIntelDb::default();
        let n = db.load_tor(&p).unwrap();
        assert_eq!(n, 2, "solo las líneas con IP cuentan");
        assert!(db.check("51.15.59.198".parse().unwrap()).contains(&TAG_TOR));
        assert!(db
            .check("199.249.230.101".parse().unwrap())
            .contains(&TAG_TOR));
        assert!(!db.check("8.8.8.8".parse().unwrap()).contains(&TAG_TOR));
    }

    #[test]
    fn las_dos_listas_coinciden_en_orden_estable() {
        let p = write_temp("ambas.txt", "203.0.113.66\n");
        let mut db = ThreatIntelDb::default();
        db.load_feodo(&p).unwrap();
        db.load_tor(&p).unwrap();
        assert_eq!(
            db.check("203.0.113.66".parse().unwrap()),
            vec![TAG_FEODO, TAG_TOR]
        );
    }

    #[test]
    fn familias_distintas_y_prefijos_limite() {
        assert!(!in_network(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            128
        ));
        // /0 lo cubre todo; /32 es IP exacta.
        assert!(in_network(
            "1.2.3.4".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
            0
        ));
        assert!(in_network(
            "1.2.3.4".parse().unwrap(),
            "1.2.3.4".parse().unwrap(),
            32
        ));
        assert!(!in_network(
            "1.2.3.5".parse().unwrap(),
            "1.2.3.4".parse().unwrap(),
            32
        ));
        // Normalización: la base con bits de host no debe romper el matching.
        assert!(in_network(
            "10.1.2.3".parse().unwrap(),
            normalize_network("10.1.2.200".parse().unwrap(), 16),
            16
        ));
    }

    #[test]
    fn parse_cidr_valida_prefijos_imposibles() {
        assert!(parse_cidr("1.2.3.4/33").is_none());
        assert!(parse_cidr("2001:db8::/129").is_none());
        assert!(parse_cidr("no-es-ip/24").is_none());
        assert_eq!(
            parse_cidr("10.0.0.0/8").map(|(b, p)| (b.to_string(), p)),
            Some(("10.0.0.0".into(), 8))
        );
    }

    #[test]
    fn redes_demasiado_amplias_se_rechazan_con_aviso() {
        let p = write_temp(
            "amplias.txt",
            "0.0.0.0/0\n1.0.0.0/7\n::/0\n2001::/15\n10.0.0.0/8\n2001:db8::/16\n",
        );
        let mut db = ThreatIntelDb::default();
        let n = db.load_feodo(&p).unwrap();
        assert_eq!(n, 2, "solo /8 v4 y /16 v6");
        assert_eq!(db.warnings.len(), 4, "{:?}", db.warnings);
        assert!(db.check("8.8.8.8".parse().unwrap()).is_empty());
    }

    #[test]
    fn lineas_no_utf8_se_saltan_sin_abortar() {
        let dir = std::env::temp_dir().join(format!("socshark-intel-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("binaria.txt");
        std::fs::write(
            &p,
            b"\xff\xfe basura\n185.222.57.24\n\xc3\x28\n45.133.1.0/24\n",
        )
        .unwrap();
        let mut db = ThreatIntelDb::default();
        assert_eq!(db.load_feodo(&p).unwrap(), 2);
        assert!(!db.check("185.222.57.24".parse().unwrap()).is_empty());
    }

    #[test]
    fn redes_repetidas_se_cuentan_una_vez() {
        let mut txt = String::new();
        for i in 0..2000u32 {
            txt.push_str(&format!("10.{}.{}.0/24\n", i / 256, i % 256));
        }
        txt.push_str(&txt.clone());
        let p = write_temp("repetidas.txt", &txt);
        let mut db = ThreatIntelDb::default();
        assert_eq!(db.load_feodo(&p).unwrap(), 2000);
    }

    #[test]
    fn ambos_extremos_del_flujo_se_comprueban() {
        let p = write_temp("c2.txt", "203.0.113.66\n");
        let mut db = ThreatIntelDb::default();
        db.load_feodo(&p).unwrap();
        let c2: IpAddr = "203.0.113.66".parse().unwrap();
        let lan: IpAddr = "192.168.1.10".parse().unwrap();
        // Conexión entrante desde el C2: antes no se etiquetaba.
        assert_eq!(db.check_flow(c2, lan), vec![TAG_FEODO]);
        assert_eq!(db.listed_endpoint(c2, lan, TAG_FEODO), Some(c2));
        assert_eq!(db.listed_endpoint(lan, c2, TAG_FEODO), Some(c2));
        assert!(db.check_flow(lan, lan).is_empty());
    }

    #[test]
    fn fichero_inexistente_devuelve_error_limpio() {
        let mut db = ThreatIntelDb::default();
        assert!(db.load_feodo(Path::new("/no/existe/feodo.txt")).is_err());
    }

    #[test]
    fn from_paths_tolera_opciones_vacias() {
        let db = ThreatIntelDb::from_paths(None, None).unwrap();
        assert!(db.is_empty());
        assert!(db.check("1.1.1.1".parse().unwrap()).is_empty());
    }
}
