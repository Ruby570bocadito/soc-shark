//! Capa de salida: tabla resumen legible y volcado JSONL.

use std::borrow::Cow;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use anyhow::{bail, Result};
use socshark_core::{EnrichedFlow, VersionedFlow};
use socshark_soc::summarize::fmt_bytes;

use crate::pipeline::CaptureOutput;

/// Neutraliza texto derivado de paquetes (qnames, SNI, nombres de host,
/// detalles de alertas...) antes de llevarlo al terminal.
///
/// Quien genera el tráfico controla esas cadenas: un `\x1b` permitiría
/// inyectar secuencias de escape (cambiar el título, borrar la pantalla,
/// ocultar líneas) y los controles bidi de Unicode (`U+202E`...) reordenar
/// visualmente el texto. Se sustituyen por su forma escapada (`\x1b`,
/// `\u{202e}`). El JSON no lo necesita: serde ya escapa.
pub fn sanitize_terminal(s: &str) -> Cow<'_, str> {
    fn dangerous(c: char) -> bool {
        c.is_control()
            || matches!(
                c,
                '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            )
    }
    if !s.chars().any(dangerous) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if !dangerous(c) {
            out.push(c);
        } else if (c as u32) <= 0xff {
            out.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        }
    }
    Cow::Owned(out)
}

/// `true` si el error (o alguna de sus causas) es una tubería rota: el
/// lector de stdout se fue (`| head -1`). No es un fallo del análisis.
pub fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain().any(|e| {
        e.downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
    })
}

/// Se niega a escribir una salida que es uno de los archivos de entrada
/// (la captura, las listas de intel): `File::create` la truncaría y se
/// perdería la evidencia original. Solo se comprueba si la salida ya
/// existe; `-` (stdout) siempre es válido.
///
/// Se compara la identidad del archivo (dispositivo + inodo en unix,
/// número de serie del volumen + índice de archivo en Windows), que
/// detecta también enlaces duros; la ruta canónica queda como respaldo
/// si no se puede obtener la identidad.
pub fn refuse_overwrite(output: &Path, inputs: &[&Path]) -> Result<()> {
    if output.as_os_str() == "-" || !output.exists() {
        return Ok(());
    }
    let out_id = file_identity(output);
    let out_canon = std::fs::canonicalize(output).ok();
    for input in inputs {
        let same_id = out_id.is_some() && file_identity(input) == out_id;
        let same_path = out_canon
            .as_ref()
            .is_some_and(|o| std::fs::canonicalize(input).is_ok_and(|i| &i == o));
        if same_id || same_path {
            bail!(
                "la salida {} es el archivo de entrada {}: se sobrescribiría la evidencia original",
                output.display(),
                input.display()
            );
        }
    }
    Ok(())
}

/// Identidad física de un archivo: `(dispositivo, inodo)`. Dos rutas con
/// la misma identidad son el mismo archivo (enlace duro incluido).
#[cfg(unix)]
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some((m.dev(), m.ino()))
}

/// Windows: `(número de serie del volumen, índice de archivo)` vía
/// `GetFileInformationByHandle` (el `file_index` de std no es estable).
#[cfg(windows)]
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    /// `BY_HANDLE_FILE_INFORMATION`.
    #[repr(C)]
    struct ByHandleFileInformation {
        attributes: u32,
        creation: FileTime,
        last_access: FileTime,
        last_write: FileTime,
        volume_serial: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(file: *mut c_void, info: *mut ByHandleFileInformation)
            -> i32;
    }

    // Abrir para lectura: las entradas se leen de todos modos y la salida
    // ya existe. Si falla (permisos), queda el respaldo por ruta canónica.
    let file = std::fs::File::open(path).ok()?;
    // SAFETY: estructura POD inicializada a ceros; el handle es válido
    // mientras `file` viva.
    let mut info: ByHandleFileInformation = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if ok == 0 {
        return None;
    }
    let index = (u64::from(info.index_high) << 32) | u64::from(info.index_low);
    Some((u64::from(info.volume_serial), index))
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_path: &Path) -> Option<(u64, u64)> {
    None
}

/// Escribe los flujos como JSONL (un `EnrichedFlow` por línea, con su
/// `schema_version`: ver [`socshark_core::JSONL_SCHEMA_VERSION`]).
///
/// JSONL y no un array JSON: permite `jq`, `grep` y lectura en streaming
/// sin cargar todo el archivo; es también el formato que consumirán los
/// exportadores SIEM (ECS) de Fase 4.
pub fn write_jsonl(path: &Path, flows: &[EnrichedFlow]) -> Result<()> {
    let file = File::create(path)?;
    let mut w = BufWriter::new(file);
    write_jsonl_to(&mut w, flows)?;
    Ok(())
}

/// JSONL a cualquier destino (stdout incluido) con vaciado final.
pub fn write_jsonl_to(w: &mut impl Write, flows: &[EnrichedFlow]) -> io::Result<()> {
    for flow in flows {
        serde_json::to_writer(&mut *w, &VersionedFlow::new(flow))?;
        w.write_all(b"\n")?;
    }
    w.flush()
}

/// Imprime la tabla resumen en stdout (ver [`write_summary`]).
pub fn print_summary(out: &CaptureOutput, top: usize) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    write_summary(&mut stdout, out, top)?;
    stdout.flush()
}

/// Escribe la tabla resumen de los `top` flujos más voluminosos y la
/// sección de alertas SOC ordenada por riesgo. Devuelve el error de
/// escritura (p. ej. tubería rota) en vez de entrar en pánico como
/// `println!`.
pub fn write_summary(w: &mut impl Write, out: &CaptureOutput, top: usize) -> io::Result<()> {
    let mut sorted: Vec<&EnrichedFlow> = out.flows.iter().collect();
    sorted.sort_by_key(|f| std::cmp::Reverse(f.bytes + f.bytes_rev));

    writeln!(w)?;
    writeln!(
        w,
        "═══ soc-shark · {} flujos ({}) ═══",
        out.flows.len(),
        sanitize_terminal(&out.pcap_path.display().to_string())
    )?;
    writeln!(
        w,
        "{:<60} {:<5} {:>7} {:>10} {:>7}  ALERTAS",
        "FLUJO", "L7", "PAQ", "BYTES", "RIESGO"
    )?;
    for flow in sorted.iter().take(top) {
        writeln!(
            w,
            "{:<60} {:<5} {:>7} {:>10} {:>7}  {}",
            truncate(&sanitize_terminal(&flow.flow_id.0), 60),
            flow.l7_protocol.as_str(),
            flow.packets + flow.packets_rev,
            fmt_bytes(flow.bytes + flow.bytes_rev),
            flow.risk_score,
            sanitize_terminal(&alerts_cell(flow)),
        )?;
    }
    if sorted.len() > top {
        writeln!(
            w,
            "… y {} flujos más (usa --json para el volcado completo)",
            sorted.len() - top
        )?;
    }

    let mut alerted: Vec<&EnrichedFlow> =
        out.flows.iter().filter(|f| !f.alerts.is_empty()).collect();
    alerted.sort_by_key(|f| std::cmp::Reverse(f.risk_score));
    if !alerted.is_empty() {
        writeln!(w)?;
        writeln!(w, "─── Alertas SOC ───")?;
        for flow in alerted {
            for alert in &flow.alerts {
                let line = format!(
                    "▸ ({}) {} · {} · {}{}",
                    alert.severity.as_str(),
                    alert.name,
                    flow.flow_id.0,
                    alert.detail,
                    alert
                        .mitre
                        .as_ref()
                        .map(|m| format!(" · MITRE {m}"))
                        .unwrap_or_default()
                );
                writeln!(w, "{}", sanitize_terminal(&line))?;
            }
        }
    }

    writeln!(w)?;
    writeln!(w, "Estadísticas: {}", out.stats.summary())?;
    writeln!(w, "DNS pasivo: {} entradas", out.passive_dns_entries)
}

fn alerts_cell(flow: &EnrichedFlow) -> String {
    if flow.alerts.is_empty() {
        "-".to_string()
    } else {
        flow.alerts
            .iter()
            .map(|a| a.id.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Recorta una cadena para la tabla (respetando límites de caracteres, no
/// bytes, para no partir UTF-8).
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!(
            "{}…",
            s.chars().take(max.saturating_sub(1)).collect::<String>()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutraliza_escapes_y_bidi() {
        assert!(matches!(
            sanitize_terminal("evil.example"),
            Cow::Borrowed("evil.example")
        ));
        assert_eq!(
            sanitize_terminal("a\x1b]0;pwned\x07b"),
            "a\\x1b]0;pwned\\x07b"
        );
        assert_eq!(sanitize_terminal("x\ny\r"), "x\\x0ay\\x0d");
        assert_eq!(sanitize_terminal("\u{9b}31m"), "\\x9b31m");
        assert_eq!(sanitize_terminal("gpj.\u{202E}exe"), "gpj.\\u{202e}exe");
        assert_eq!(sanitize_terminal("\u{2066}\u{200F}"), "\\u{2066}\\u{200f}");
        // Texto no latino legítimo intacto.
        assert_eq!(sanitize_terminal("ñandú.例え"), "ñandú.例え");
    }

    #[test]
    fn no_sobrescribe_la_entrada() {
        let dir = std::env::temp_dir();
        let input = dir.join(format!("socshark-refuse-{}.pcap", std::process::id()));
        std::fs::write(&input, b"x").unwrap();
        // Misma ruta, o la misma por otro camino (`dir/./archivo`).
        assert!(refuse_overwrite(&input, &[&input]).is_err());
        let alias = dir.join(".").join(input.file_name().unwrap());
        assert!(refuse_overwrite(&alias, &[Path::new("otra"), &input]).is_err());
        // Salidas distintas, inexistentes o stdout: bien.
        let other = dir.join(format!("socshark-refuse-{}.jsonl", std::process::id()));
        assert!(refuse_overwrite(&other, &[&input]).is_ok());
        assert!(refuse_overwrite(Path::new("-"), &[&input]).is_ok());
        std::fs::remove_file(&input).ok();
    }

    #[test]
    fn no_sobrescribe_la_entrada_por_enlace_duro() {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let input = dir.join(format!("socshark-hardlink-{pid}.pcap"));
        let link = dir.join(format!("socshark-hardlink-{pid}.jsonl"));
        std::fs::remove_file(&link).ok();
        std::fs::write(&input, b"x").unwrap();
        std::fs::hard_link(&input, &link).unwrap();
        // Rutas canónicas distintas, mismo archivo: hay que negarse.
        assert!(refuse_overwrite(&link, &[&input]).is_err());
        // Un archivo distinto con el mismo contenido no es la entrada.
        std::fs::remove_file(&link).unwrap();
        std::fs::write(&link, b"x").unwrap();
        assert!(refuse_overwrite(&link, &[&input]).is_ok());
        std::fs::remove_file(&link).ok();
        std::fs::remove_file(&input).ok();
    }

    #[test]
    fn tuberia_rota_se_reconoce_en_la_cadena() {
        let e = anyhow::Error::new(io::Error::from(io::ErrorKind::BrokenPipe))
            .context("error escribiendo JSONL");
        assert!(is_broken_pipe(&e));
        assert!(!is_broken_pipe(&anyhow::anyhow!("otro")));
    }
}
