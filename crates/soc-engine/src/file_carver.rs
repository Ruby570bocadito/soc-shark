//! Live File Carving: extrae archivos de cuerpos HTTP y verifica magic bytes.
//!
//! Fase 1: cuerpos completos dentro de un solo paquete (el caso dominante
//! para ejecutables pequeños de C2). El reensamblado de streams TCP llega en
//! fase 4 (`docs/11-hoja-de-ruta.md`) y sustituirá esta limitación.
//!
//! Cada artefacto lleva SHA-256 (para VirusTotal/_feed lookup futuro) y la
//! detección de **Masquerading** (MITRE T1036): si `factura.pdf` empieza por
//! `MZ`, es un ejecutable disfrazado.

use socshark_common::soc_types::Artifact;
use socshark_common::{base64, hex, sha256};
use socshark_dissectors::view::{AppInfo, DissectedPacket};
use socshark_flow_aggregator::model::FlowKey;
use std::collections::HashMap;

/// Magic bytes conocidos (nombre, prefijo, extensiones esperadas).
const MAGICS: &[(&str, &[u8], &[&str])] = &[
    ("MZ", &[0x4d, 0x5a], &["exe", "dll", "sys", "scr", "com"]),
    (
        "ELF",
        &[0x7f, 0x45, 0x4c, 0x46],
        &["elf", "so", "bin", "axf"],
    ),
    ("PDF", &[0x25, 0x50, 0x44, 0x46], &["pdf"]),
    ("PNG", &[0x89, 0x50, 0x4e, 0x47], &["png"]),
    ("JPEG", &[0xff, 0xd8, 0xff], &["jpg", "jpeg"]),
    (
        "ZIP",
        &[0x50, 0x4b, 0x03, 0x04],
        &["zip", "docx", "xlsx", "pptx", "jar", "apk", "odt"],
    ),
    ("GZIP", &[0x1f, 0x8b], &["gz", "tgz"]),
    ("WASM", &[0x00, 0x61, 0x73, 0x6d], &["wasm"]),
    ("RAR", &[0x52, 0x61, 0x72, 0x21], &["rar"]),
    ("7Z", &[0x37, 0x7a, 0xbc, 0xaf], &["7z"]),
];

/// Detecta el magic byte de un buffer.
pub fn detect_magic(data: &[u8]) -> Option<&'static str> {
    for (name, prefix, _) in MAGICS {
        if data.len() >= prefix.len() && &data[..prefix.len()] == *prefix {
            return Some(name);
        }
    }
    None
}

/// Estado del carver por flujo.
#[derive(Default)]
pub struct FileCarver {
    /// Última URI solicitada por flujo (para nombrar artefactos).
    last_request: HashMap<FlowKey, String>,
    artifacts: usize,
}

const MAX_FLOWS_TRACKED: usize = 4096;
const MAX_ARTIFACTS_TOTAL: usize = 128;
const MAX_ARTIFACTS_PER_FLOW: usize = 8;
/// Tamaño mínimo de cuerpo para considerar carving (evita GIFs de 1x1).
const MIN_BODY: usize = 64;

impl FileCarver {
    pub fn new() -> Self {
        FileCarver::default()
    }

    /// Observa un paquete: guarda requests (para nombrar) y carveda responses.
    pub fn observe(&mut self, dp: &DissectedPacket, sink: &mut HashMap<FlowKey, Vec<Artifact>>) {
        let Some(AppInfo::Http(_)) = dp.app.as_ref() else {
            return;
        };
        let Some(tuple) = &dp.five_tuple else { return };
        let key = FlowKey {
            src: tuple.src,
            sport: tuple.src_port,
            dst: tuple.dst,
            dport: tuple.dst_port,
            proto: tuple.proto,
        };
        match dp.app.as_ref().unwrap() {
            AppInfo::Http(socshark_dissectors::layer7::http::HttpMessage::Request(r)) => {
                if self.last_request.len() >= MAX_FLOWS_TRACKED {
                    self.last_request.clear(); // rotación simple
                }
                self.last_request.insert(key, r.target.clone());
            }
            AppInfo::Http(socshark_dissectors::layer7::http::HttpMessage::Response(resp)) => {
                let mut body = resp.body;
                let _dechunked;
                if resp.is_chunked() {
                    _dechunked = socshark_dissectors::layer7::http::dechunk(body);
                    body = &_dechunked;
                }
                if body.len() < MIN_BODY {
                    return;
                }
                if self.artifacts >= MAX_ARTIFACTS_TOTAL {
                    return;
                }
                let already = sink.get(&key).map(|v| v.len()).unwrap_or(0);
                if already >= MAX_ARTIFACTS_PER_FLOW {
                    return;
                }
                let target = self
                    .last_request
                    .get(&key.reversed())
                    .or_else(|| self.last_request.get(&key))
                    .cloned()
                    .unwrap_or_else(|| format!("body_{}.bin", dp.index));
                let name = target
                    .rsplit('/')
                    .next()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(&target)
                    .to_string();
                let magic = detect_magic(body).unwrap_or("desconocido");
                let ext = name
                    .rsplit_once('.')
                    .map(|(_, e)| e.to_ascii_lowercase())
                    .unwrap_or_default();
                let expected = MAGICS
                    .iter()
                    .find(|(_, _, exts)| exts.contains(&ext.as_str()))
                    .map(|(m, _, _)| *m);
                let masquerade = matches!((magic, expected.as_deref()), (m, Some(e)) if m != e);
                let art = Artifact {
                    name,
                    size: body.len() as u64,
                    sha256: sha256::sha256_hex(body),
                    magic,
                    masquerade,
                    source: "HTTP",
                };
                sink.entry(key).or_default().push(art);
                self.artifacts += 1;
            }
            _ => {}
        }
    }

    pub fn artifacts_seen(&self) -> usize {
        self.artifacts
    }
}

/// Utilidad para la futura TUI: muestra un buffer en base64 (decodificador
/// estilo CyberChef, fase de UI).
pub fn body_base64(data: &[u8]) -> String {
    base64::encode(data)
}

/// Resumen hex corto de los primeros bytes (para evidencia).
pub fn magic_evidence(data: &[u8]) -> String {
    let head = &data[..data.len().min(8)];
    format!(
        "{} ({:?})",
        hex::to_hex(head),
        String::from_utf8_lossy(head)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magics_basicos() {
        assert_eq!(detect_magic(&[0x4d, 0x5a, 0x90, 0x00]), Some("MZ"));
        assert_eq!(detect_magic(&[0x7f, b'E', b'L', b'F']), Some("ELF"));
        assert_eq!(detect_magic(b"%PDF-1.7 ..."), Some("PDF"));
        assert_eq!(detect_magic(b"\x89PNG"), Some("PNG"));
        assert_eq!(detect_magic(b"PK\x03\x04"), Some("ZIP"));
        assert_eq!(detect_magic(b"texto plano normal"), None);
    }

    #[test]
    fn masquerade_pdf_con_mz() {
        // factura.pdf con contenido PE → masquerade
        let ext = "pdf";
        let magic = "MZ";
        let expected = MAGICS
            .iter()
            .find(|(_, _, exts)| exts.contains(&ext))
            .map(|(m, _, _)| *m);
        assert!(matches!((magic, expected.as_deref()), (m, Some(e)) if m != e));
    }
}
