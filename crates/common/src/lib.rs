//! Utilidades compartidas del workspace **soc-shark**.
//!
//! Este crate es std-only por diseño (ver `docs/adr/ADR-0001-std-only.md`):
//! ninguna dependencia externa entra en el árbol de builds del motor, lo que
//! minimiza la superficie de auditoría de la cadena de suministro, una
//! propiedad deseable en una herramienta de seguridad.
//!
//! Contenido:
//! - [`json`]: serializador JSON propio (solo escritura, sin parseo).
//! - [`sha256`]: implementación pura de SHA-256 (artefactos, JA4-like).
//! - [`base64`] / [`hex`]: códecs usados por el decodificador estilo CyberChef.
//! - [`entropy`]: entropía de Shannon para detección de exfiltración/túneles.
//! - [`ipaddr`]: direcciones IP v4/v6, clasificación y matching CIDR.
//! - [`timefmt`]: formateo de timestamps de captura y duraciones.
//! - [`ansi`]: colores semánticos para la salida de terminal (respeta NO_COLOR).
//! - [`soc_types`]: tipos compartidos del dominio SOC (`SocAlert`, `Artifact`).

pub mod ansi;
pub mod base64;
pub mod entropy;
pub mod hex;
pub mod ipaddr;
pub mod json;
pub mod sha256;
pub mod soc_types;
pub mod timefmt;
