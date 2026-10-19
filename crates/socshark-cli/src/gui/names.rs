//! Apodos que la persona pone a sus equipos («Portátil de Ana»).
//!
//! Se guardan en un JSON en la carpeta de configuración del usuario
//! (`%APPDATA%\socshark\apodos.json`, `~/.config/socshark/apodos.json` o
//! `~/Library/Application Support/socshark/apodos.json`) para que duren
//! entre sesiones y entre capturas. La clave es la MAC del equipo si se
//! conoce (no cambia aunque cambie su IP), si no la IP.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

use socshark_soc::hosts::HostDirectory;

/// Longitud máxima de un apodo.
const MAX_LEN: usize = 40;
/// Apodos como mucho (el archivo no puede crecer sin límite).
const MAX_ENTRIES: usize = 2_000;

pub struct Nicknames {
    path: Option<PathBuf>,
    map: HashMap<String, String>,
}

/// Carpeta de configuración del usuario según el sistema.
fn config_dir() -> Option<PathBuf> {
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if cfg!(windows) {
        env("APPDATA")
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|h| h.join("Library/Application Support"))
    } else {
        env("XDG_CONFIG_HOME").or_else(|| env("HOME").map(|h| h.join(".config")))
    }
}

/// Apodo limpio: sin controles ni espacios sobrantes, acotado. Vacío = quitar.
pub fn clean_nickname(raw: &str) -> Option<String> {
    let s: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_LEN)
        .collect();
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

impl Nicknames {
    /// Solo en memoria (tests): no toca el disco del usuario.
    pub fn in_memory() -> Self {
        Self {
            path: None,
            map: HashMap::new(),
        }
    }

    /// Los apodos guardados; si el archivo falta o está roto, empieza vacío.
    pub fn load() -> Self {
        let path = config_dir().map(|d| d.join("socshark").join("apodos.json"));
        let map = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| serde_json::from_str::<HashMap<String, String>>(&t).ok())
            .map(|m| {
                m.into_iter()
                    .filter_map(|(k, v)| Some((HostDirectory::valid_key(&k)?, clean_nickname(&v)?)))
                    .take(MAX_ENTRIES)
                    .collect()
            })
            .unwrap_or_default();
        Self { path, map }
    }

    pub fn map(&self) -> &HashMap<String, String> {
        &self.map
    }

    /// Pone (o quita, con `None`) un apodo y lo guarda. `key` ya validada.
    pub fn set(&mut self, key: String, nickname: Option<String>) -> io::Result<()> {
        match nickname {
            Some(n) => {
                if !self.map.contains_key(&key) && self.map.len() >= MAX_ENTRIES {
                    return Err(io::Error::other("demasiados apodos guardados"));
                }
                self.map.insert(key, n);
            }
            None => {
                self.map.remove(&key);
            }
        }
        self.save()
    }

    /// Escritura atómica: archivo temporal + renombrado.
    fn save(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_string_pretty(&self.map).map_err(io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apodos_limpios_y_persistentes() {
        assert_eq!(
            clean_nickname("  Portátil\nde Ana  ").as_deref(),
            Some("Portátilde Ana")
        );
        assert_eq!(clean_nickname("   "), None);
        assert_eq!(clean_nickname(&"x".repeat(100)).unwrap().len(), MAX_LEN);

        let dir = std::env::temp_dir().join(format!("socshark-apodos-{}", std::process::id()));
        let path = dir.join("socshark").join("apodos.json");
        let mut n = Nicknames {
            path: Some(path.clone()),
            map: HashMap::new(),
        };
        n.set("mac:aa:bb:cc:00:11:22".into(), Some("Tele".into()))
            .unwrap();
        n.set("ip:192.168.1.5".into(), Some("Impresora".into()))
            .unwrap();
        n.set("ip:192.168.1.5".into(), None).unwrap();
        let saved: HashMap<String, String> =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved["mac:aa:bb:cc:00:11:22"], "Tele");
        std::fs::remove_dir_all(dir).ok();
    }
}
