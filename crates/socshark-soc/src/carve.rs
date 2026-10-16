//! File carving HTTP: extracción de archivos de respuestas HTTP
//! reensambladas y detección de encubrimiento (MITRE ATT&CK T1036).
//!
//! Entrada: los streams TCP reensamblados por [`socshark_flow`] (hasta 1 MiB
//! por dirección) y los flujos exportados por el agregador. Salida: el campo
//! `extracted_files` de [`EnrichedFlow`] relleno con nombre declarado, tamaño,
//! SHA-256 (ADR-011), firma magic y la sospecha de encubrimiento.
//!
//! Decisiones de diseño:
//! - **Solo HTTP detectado**: se talla únicamente en flujos cuyo L7 fue
//!   clasificado como HTTP (heurística de payload), lo que excluye de paso
//!   los streams TLS y evita falsos positivos sobre binarios aleatorios.
//! - **Keep-alive**: un stream puede contener varias parejas
//!   petición/respuesta; se emparejan en orden (HTTP/1.1 serializa las
//!   respuestas en el orden de las peticiones).
//! - **Cuerpos acotados**: Content-Length exacto o Transfer-Encoding chunked;
//!   si el stream se corta antes (captura truncada o tope de 1 MiB), se talla
//!   lo disponible — el hash deja de ser el del archivo original, pero la
//!   firma magic (cabecera) sigue siendo válida para el detector.
//! - **Selección conservadora**: no se talla toda respuesta 200; solo las que
//!   aportan nombre (Content-Disposition o ruta de la petición) o cuya
//!   cabecera/cuerpo sugiere binario (application/*, firma magic conocida).
//!   Así las páginas HTML normales no inundan `extracted_files`.
//! - **T1036 por dos vías**: magic ≠ extensión declarada (un "PE32" llamado
//!   `.jpg`) y doble extensión ejecutable (`informe.pdf.exe`).

use std::borrow::Cow;
use std::collections::HashMap;

use socshark_core::hash::{sha256, to_hex};
use socshark_core::{EnrichedFlow, ExtractedFile, L7Protocol};
use socshark_flow::ReassembledStream;

/// Máximo de archivos tallados por flujo: cota dura contra streams
/// patológicos con cientos de respuestas encadenadas.
const MAX_FILES_PER_FLOW: usize = 8;

/// Talla archivos de todas las respuestas HTTP de los flujos con stream.
///
/// `streams` es el mapa `flow_id → stream` que devuelve
/// [`socshark_flow::FlowAggregator::finish_with_streams`]. Los flujos sin
/// entrada en el mapa (UDP, TCP sin stream, carving desactivado) no se tocan.
pub fn carve_all(flows: &mut [EnrichedFlow], streams: &HashMap<String, ReassembledStream>) {
    for flow in flows.iter_mut() {
        if flow.l7_protocol != L7Protocol::Http {
            continue;
        }
        let Some(stream) = streams.get(&flow.flow_id.0) else {
            continue;
        };
        let files = carve_http(&stream.client, &stream.server);
        flow.extracted_files = files;
    }
}

/// Extrae los archivos de un intercambio HTTP (stream del cliente = peticiones,
/// stream del servidor = respuestas), emparejando en orden.
pub fn carve_http(client: &[u8], server: &[u8]) -> Vec<ExtractedFile> {
    let mut files = Vec::new();
    let mut request_paths = RequestPaths::new(client);

    let mut pos = 0usize;
    while files.len() < MAX_FILES_PER_FLOW {
        let Some((_head_start, head, body_start)) = next_response(server, pos) else {
            break;
        };
        let status = parse_status_code(head);
        let headers = parse_headers(head);

        // 1xx son respuestas provisionales sin cuerpo (y 101 cambia de
        // protocolo): no tallan nada, seguimos buscando la siguiente.
        let code = status.unwrap_or(0);
        if (100..200).contains(&code) {
            pos = body_start;
            continue;
        }

        let chunked = headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
        });
        let content_length = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.trim().parse::<u64>().ok());

        let (body, body_end): (Cow<'_, [u8]>, Option<usize>) = if chunked {
            // Reensamblado propio (los separadores de chunk no son datos).
            let (content, end) = dechunk(server, body_start);
            (Cow::Owned(content), end)
        } else {
            match content_length {
                Some(len) => {
                    let end = body_start.saturating_add(len as usize);
                    let avail = &server[body_start.min(server.len())..end.min(server.len())];
                    let done = end <= server.len();
                    (Cow::Borrowed(avail), done.then_some(end))
                }
                // Sin Content-Length ni chunked: cuerpo hasta el final del
                // stream (lo que HTTP/1.0 hacía al cerrar la conexión).
                None if code == 200 || code == 201 => {
                    (Cow::Borrowed(&server[body_start.min(server.len())..]), None)
                }
                _ => (Cow::Borrowed(&[]), None),
            }
        };

        // 204/304 y códigos de error sin cuerpo no tallan.
        if !body.is_empty() && code != 204 && code != 304 {
            let disposition = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-disposition"))
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            let content_type = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            let name = file_name(disposition, request_paths.next().unwrap_or_default());
            if relevant(&name, content_type, &body) {
                files.push(build_file(&name, &body));
            }
        }

        // Con Content-Length exacto o chunk terminado sabemos dónde acaba la
        // respuesta; si el cuerpo se truncó (stream cortado), no hay más.
        match body_end {
            Some(end) => pos = end,
            None => break,
        }
    }
    files
}

// -------------------------------------------------------------- respuesta

/// Localiza la siguiente cabecera de respuesta HTTP/1.x en el stream.
/// Devuelve (inicio del head, head completo, inicio del cuerpo).
fn next_response(server: &[u8], from: usize) -> Option<(usize, &[u8], usize)> {
    let mut pos = from;
    while pos + 8 <= server.len() {
        let idx = find(&server[pos..], b"HTTP/1.")?;
        let head_end_rel = find(&server[pos + idx..], b"\r\n\r\n")?;
        let head_start = pos + idx;
        let head_end = head_start + head_end_rel;
        // Validación mínima de línea de estado: "HTTP/1.x NNN".
        let line = &server[head_start..(head_start + head_end_rel).min(server.len())];
        let first_line_end = find(line, b"\r\n").unwrap_or(line.len());
        if !valid_status_line(&line[..first_line_end.min(line.len())]) {
            pos = head_start + 7; // rebusca tras el falso positivo
            continue;
        }
        let head = &server[head_start..head_end];
        return Some((head_start, head, head_end + 4));
    }
    None
}

/// Comprueba el formato `HTTP/1.[01] <3 dígitos> [razón]`.
fn valid_status_line(line: &[u8]) -> bool {
    if line.len() < 12 || !line.starts_with(b"HTTP/1.") {
        return false;
    }
    let ver = line[7];
    if !ver.is_ascii_digit() {
        return false;
    }
    line[8] == b' ' && line[9..12].iter().all(|b| b.is_ascii_digit())
}

fn parse_status_code(head: &[u8]) -> Option<u16> {
    let line_end = find(head, b"\r\n").unwrap_or(head.len());
    if line_end < 12 {
        return None;
    }
    std::str::from_utf8(&head[9..12]).ok()?.parse().ok()
}

/// Cabeceras como pares (nombre, valor) en minúscula-preservada; los valores
/// se recortan. Tolera cabeceras malformadas saltándolas.
fn parse_headers(head: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let text = std::str::from_utf8(head).unwrap_or("");
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

/// Decodifica un cuerpo `Transfer-Encoding: chunked` desde `pos`.
/// Reensambla los chunks en un buffer propio (los separadores no son datos)
/// y devuelve también la posición donde termina la respuesta (`None` si el
/// stream se cortó antes del chunk terminador).
fn dechunk(server: &[u8], mut pos: usize) -> (Vec<u8>, Option<usize>) {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = find(&server[pos..], b"\r\n") else {
            return (out, None);
        };
        let size_str = std::str::from_utf8(&server[pos..pos + line_end]).unwrap_or("");
        let size =
            usize::from_str_radix(size_str.trim().split(';').next().unwrap_or(""), 16).unwrap_or(0);
        pos += line_end + 2;
        if size == 0 {
            // Chunk final: el reensamblado acaba aquí (pos queda tras "0\r\n").
            return (out, Some(pos));
        }
        if pos + size > server.len() {
            // Cuerpo truncado: talla lo disponible.
            out.extend_from_slice(&server[pos.min(server.len())..]);
            return (out, None);
        }
        out.extend_from_slice(&server[pos..pos + size]);
        pos += size;
        // Salta el CRLF tras el chunk (tolerante si falta).
        if server.get(pos) == Some(&b'\r') {
            pos += 1;
        }
        if server.get(pos) == Some(&b'\n') {
            pos += 1;
        }
    }
}

/// Busca la primera ocurrencia de `needle` en `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

// ------------------------------------------------------------- nombres

/// Itera las rutas de las peticiones del stream del cliente, en orden.
struct RequestPaths {
    paths: Vec<String>,
    cursor: usize,
}

impl RequestPaths {
    fn new(client: &[u8]) -> Self {
        let mut paths = Vec::new();
        // Línea de petición: "GET /ruta HTTP/1.x". Se aceptan los métodos
        // comunes; el resto de líneas se ignora.
        for line in client.split(|&b| b == b'\n') {
            let line = trim_crlf(line);
            if let Ok(text) = std::str::from_utf8(line) {
                let mut parts = text.split_whitespace();
                let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
                    continue;
                };
                if matches!(method, "GET" | "POST" | "HEAD" | "PUT") {
                    paths.push(path.to_string());
                }
            }
        }
        Self { paths, cursor: 0 }
    }

    fn next(&mut self) -> Option<String> {
        let p = self.paths.get(self.cursor).cloned();
        self.cursor += 1;
        p
    }
}

fn trim_crlf(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && (b[end - 1] == b'\r' || b[end - 1] == b'\n' || b[end - 1] == b' ') {
        end -= 1;
    }
    &b[..end]
}

/// Decide el nombre del archivo: gana `Content-Disposition`, y si no hay,
/// el basename de la ruta de la petición (si lleva extensión). Sin nombre
/// devuelve cadena vacía (la relevancia la decidirá el tipo de contenido).
fn file_name(disposition: &str, request_path: String) -> String {
    if let Some(idx) = disposition.to_ascii_lowercase().find("filename") {
        let after = &disposition[idx + "filename".len()..];
        let after = after.strip_prefix('*').unwrap_or(after); // filename*=
        let after = after.trim_start_matches(['=', ' ']);
        // RFC 5987: filename*=UTF-8''nombre
        let after = after.rsplit("''").next().unwrap_or(after);
        let value = after
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_string();
        if !value.is_empty() {
            return value;
        }
    }
    let base = request_path.rsplit('/').next().unwrap_or("").to_string();
    if base.contains('.') {
        base
    } else {
        String::new()
    }
}

// --------------------------------------------------- magic y masquerading

/// Firma "magic bytes" del contenido (subconjunto relevante para SOC).
pub fn detect_magic(body: &[u8]) -> Option<&'static str> {
    if body.starts_with(b"MZ") {
        return Some("PE32");
    }
    if body.starts_with(b"\x7fELF") {
        return Some("ELF");
    }
    // Mach-O de 32/64 bits y fat binario (ambos endianness).
    if body.len() >= 4
        && matches!(
            &body[..4],
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
        )
    {
        return Some("Mach-O");
    }
    if body.starts_with(b"%PDF") {
        return Some("PDF");
    }
    if body.starts_with(b"PK\x03\x04") {
        return Some("ZIP");
    }
    if body.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        return Some("OLE2");
    }
    if body.starts_with(b"\x1f\x8b") {
        return Some("GZIP");
    }
    if body.starts_with(b"Rar!") {
        return Some("RAR");
    }
    if body.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return Some("7Z");
    }
    if body.starts_with(b"\x89PNG") {
        return Some("PNG");
    }
    if body.starts_with(b"\xff\xd8\xff") {
        return Some("JPEG");
    }
    if body.starts_with(b"GIF8") {
        return Some("GIF");
    }
    if body.starts_with(b"#!") {
        return Some("SCRIPT");
    }
    None
}

/// Extensiones legítimas por firma (minúscula, sin punto).
fn magic_extensions(magic: &str) -> &'static [&'static str] {
    match magic {
        "PE32" => &["exe", "dll", "sys", "scr", "ocx", "cpl", "efi", "com"],
        "ELF" => &["so", "elf", "bin", "axf", "ko"],
        "Mach-O" => &["dylib", "bin", "o"],
        "PDF" => &["pdf"],
        "ZIP" => &[
            "zip", "docx", "xlsx", "pptx", "jar", "apk", "odt", "ods", "epub",
        ],
        "OLE2" => &["doc", "xls", "ppt", "msi", "dot", "xla"],
        "GZIP" => &["gz", "tgz", "svgz"],
        "RAR" => &["rar"],
        "7Z" => &["7z"],
        "PNG" => &["png"],
        "JPEG" => &["jpg", "jpeg", "jpe"],
        "GIF" => &["gif"],
        "SCRIPT" => &["sh", "py", "pl", "rb", "php"],
        _ => &[],
    }
}

/// Extensiones ejecutables en Windows: base de la detección de doble
/// extensión ("informe.pdf.exe").
fn is_executable_extension(ext: &str) -> bool {
    matches!(
        ext,
        "exe"
            | "dll"
            | "sys"
            | "scr"
            | "com"
            | "pif"
            | "cpl"
            | "bat"
            | "cmd"
            | "js"
            | "vbs"
            | "ps1"
    )
}

/// True si el nombre declara una extensión que no corresponde al tipo real
/// (magic) o si usa la técnica de doble extensión ejecutable.
pub fn masquerading_suspect(name: &str, magic: Option<&str>) -> bool {
    let Some(ext) = name.rsplit('.').next().map(|e| e.to_ascii_lowercase()) else {
        return false;
    };
    if name.is_empty() || !name.contains('.') {
        return false;
    }
    // Doble extensión: "informe.pdf.exe" declara ejecutable pero aparenta
    // ser el documento de antes (T1036, variante clásica).
    if is_executable_extension(&ext) {
        if let Some(prev) = name[..name.len() - ext.len() - 1].rsplit('.').next() {
            let prev = prev.to_ascii_lowercase();
            if !prev.is_empty() && !is_executable_extension(&prev) && prev.len() <= 5 {
                return true;
            }
        }
    }
    match magic {
        Some(m) => !magic_extensions(m).contains(&ext.as_str()),
        None => false,
    }
}

/// Construye el `ExtractedFile` final: hash, magic y veredicto.
fn build_file(name: &str, body: &[u8]) -> ExtractedFile {
    let magic = detect_magic(body);
    ExtractedFile {
        name: if name.is_empty() {
            "<sin nombre>".into()
        } else {
            name.to_string()
        },
        size: body.len() as u64,
        sha256: Some(to_hex(&sha256(body))),
        magic: magic.map(str::to_string),
        masquerading_suspect: masquerading_suspect(name, magic),
    }
}

/// Decide si una respuesta merece tallarse (evita llenar el modelo con
/// páginas HTML y contenido textual rutinario).
fn relevant(name: &str, content_type: &str, body: &[u8]) -> bool {
    // Firma conocida: siempre interesa, incluso disfrazada (T1036).
    if detect_magic(body).is_some() {
        return true;
    }
    let ct = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    const TEXT_EXTS: &[&str] = &[
        "html", "htm", "txt", "css", "js", "json", "xml", "svg", "md", "csv",
    ];
    // Texto declarado o con extensión de texto: contenido web normal.
    if ct.starts_with("text/") || ct.contains("json") || ct.contains("xml") {
        return false;
    }
    if let Some(ext) = name.rsplit('.').next() {
        if name.contains('.') && TEXT_EXTS.contains(&ext.to_ascii_lowercase().as_str()) {
            return false;
        }
    }
    // Lo demás: con nombre (disposición/ruta) o binario declarado, talla.
    !name.is_empty() || ct.starts_with("application/")
}

// --------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn response(head: &str, body: &[u8]) -> Vec<u8> {
        // El head llega SIN el CRLF final: aquí se añade el separador
        // "\r\n\r\n" entre cabeceras y cuerpo.
        let mut v = format!(
            "HTTP/1.1 200 OK\r\n{}\r\n\r\n",
            head.trim_end_matches("\r\n")
        )
        .into_bytes();
        v.extend_from_slice(body);
        v
    }

    /// Un PE ejecutable de muestra: cabecera MZ + relleno.
    fn pe_bytes(n: usize) -> Vec<u8> {
        let mut v = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00".to_vec();
        v.resize(n.max(64), 0xab);
        v
    }

    #[test]
    fn talla_content_disposition_con_hash_y_magic() {
        let body = pe_bytes(1024);
        let srv = response(
            "Server: nginx\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"update.exe\"\r\nContent-Length: 1024\r\n",
            &body,
        );
        let files = carve_http(b"GET /update.exe HTTP/1.1\r\nHost: x\r\n\r\n", &srv);
        assert_eq!(files.len(), 1);
        let f = &files[0];
        assert_eq!(f.name, "update.exe");
        assert_eq!(f.size, 1024);
        assert_eq!(f.magic.as_deref(), Some("PE32"));
        assert!(f.sha256.as_deref().is_some_and(|h| h.len() == 64));
        assert!(
            !f.masquerading_suspect,
            "exe con contenido PE no encubre nada"
        );
    }

    #[test]
    fn pe_llamado_jpg_dispara_t1036() {
        let body = pe_bytes(512);
        let srv = response("Content-Type: image/jpeg\r\nContent-Length: 512\r\n", &body);
        // La ruta de la petición aporta el nombre.
        let files = carve_http(b"GET /img/banner.jpg HTTP/1.1\r\nHost: x\r\n\r\n", &srv);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "banner.jpg");
        assert_eq!(files[0].magic.as_deref(), Some("PE32"));
        assert!(files[0].masquerading_suspect, "un PE llamado .jpg es T1036");
    }

    #[test]
    fn doble_extension_ejecutiva_es_sospechosa() {
        let body = pe_bytes(256);
        let srv = response(
            "Content-Disposition: attachment; filename=\"informe.pdf.exe\"\r\nContent-Length: 256\r\n",
            &body,
        );
        let files = carve_http(b"", &srv);
        assert_eq!(files.len(), 1);
        assert!(
            files[0].masquerading_suspect,
            "informe.pdf.exe es doble extensión"
        );
    }

    #[test]
    fn chunked_se_reensambla_completo() {
        let pe = pe_bytes(300);
        let mut srv = response(
            "Content-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nContent-Disposition: attachment; filename=\"payload.bin\"\r\n",
            &[],
        );
        // Chunk A (0x100 = 256 bytes) + chunk B (resto) + chunk final.
        srv.extend_from_slice(b"100\r\n");
        srv.extend_from_slice(&pe[..256]);
        srv.extend_from_slice(b"\r\n");
        srv.extend_from_slice(&format!("{:x}\r\n", pe.len() - 256).into_bytes());
        srv.extend_from_slice(&pe[256..]);
        srv.extend_from_slice(b"\r\n0\r\n\r\n");

        let files = carve_http(b"", &srv);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].size, 300);
        assert_eq!(files[0].magic.as_deref(), Some("PE32"));
    }

    #[test]
    fn keep_alive_emparea_peticiones_y_respuestas_en_orden() {
        let pe = pe_bytes(128);
        let mut client = b"GET /a.html HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        client.extend_from_slice(b"GET /soft/tool.exe HTTP/1.1\r\nHost: x\r\n\r\n");
        let mut server = response("Content-Type: text/html\r\nContent-Length: 5\r\n", b"hello");
        server.extend_from_slice(&response(
            "Content-Type: application/octet-stream\r\nContent-Length: 128\r\n",
            &pe,
        ));
        let files = carve_http(&client, &server);
        assert_eq!(
            files.len(),
            1,
            "a.html (sin nombre relevante, text/html) no talla"
        );
        assert_eq!(files[0].name, "tool.exe");
        assert_eq!(files[0].magic.as_deref(), Some("PE32"));
    }

    #[test]
    fn html_normal_no_se_talla() {
        let srv = response(
            "Content-Type: text/html; charset=utf-8\r\nContent-Length: 84\r\n",
            b"<html><head><title>Ejemplo</title></head><body>Hola mundo del ejemplo</body></html>",
        );
        let files = carve_http(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", &srv);
        assert!(
            files.is_empty(),
            "una página HTML sin nombre no interesa: {files:?}"
        );
    }

    #[test]
    fn cuerpo_truncado_talla_lo_disponible_y_mantiene_magic() {
        let mut body = pe_bytes(2000);
        body.truncate(100); // el stream se cortó a los 100 bytes
        let srv = response(
            "Content-Disposition: attachment; filename=\"tool.exe\"\r\nContent-Length: 2000\r\n",
            &body,
        );
        let files = carve_http(b"", &srv);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].size, 100, "se talla lo que llegó");
        assert_eq!(files[0].magic.as_deref(), Some("PE32"));
    }

    #[test]
    fn respuestas_1xx_se_saltan_sin_perder_la_siguiente() {
        let pe = pe_bytes(64);
        let mut srv = b"HTTP/1.1 100 Continue\r\n\r\n".to_vec();
        srv.extend_from_slice(&response(
            "Content-Type: application/octet-stream\r\nContent-Length: 64\r\n",
            &pe,
        ));
        let files = carve_http(
            b"POST /up HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n\r\n",
            &srv,
        );
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].magic.as_deref(), Some("PE32"));
    }

    #[test]
    fn magic_deteccion_basica() {
        assert_eq!(detect_magic(b"MZxxxx"), Some("PE32"));
        assert_eq!(detect_magic(b"\x7fELFxxxx"), Some("ELF"));
        assert_eq!(detect_magic(b"%PDF-1.7"), Some("PDF"));
        assert_eq!(detect_magic(b"PK\x03\x04xxxx"), Some("ZIP"));
        assert_eq!(detect_magic(b"\x89PNG\r\n\x1a\n"), Some("PNG"));
        assert_eq!(detect_magic(b"#!/bin/sh\n"), Some("SCRIPT"));
        assert_eq!(detect_magic(b"random text"), None);
    }

    #[test]
    fn masquerading_tabla_de_casos() {
        assert!(masquerading_suspect("foto.jpg", Some("PE32")));
        assert!(masquerading_suspect("doc.pdf", Some("ELF")));
        assert!(!masquerading_suspect("foto.jpg", Some("JPEG")));
        assert!(!masquerading_suspect("doc.pdf", Some("PDF")));
        // PDF dentro de .exe: la extensión declara PE y el contenido no es PE.
        assert!(masquerading_suspect("setup.exe", Some("PDF")));
        // Sin extensión no hay encubrimiento declarado.
        assert!(!masquerading_suspect("payload", Some("PE32")));
        // Doble extensión.
        assert!(masquerading_suspect("informe.docx.scr", Some("PE32")));
        // Ejecutivo aparentando ser instalador legítimo: el tramo intermedio
        // "msi" es exactamente la máscara clásica → sospechoso.
        assert!(masquerading_suspect("setup.msi.exe", Some("PE32")));
    }

    #[test]
    fn sin_panic_con_entradas_hostiles() {
        // Streams truncados, basura y límites exactos no deben colgar ni asustar.
        let _ = carve_http(b"", b"");
        let _ = carve_http(b"GET", b"HTTP");
        let _ = carve_http(
            b"GET /x HTTP/1.1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\ncorto",
        );
        let _ = carve_http(
            b"",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzzzz\r\n",
        );
        let _ = carve_http(b"", b"HTTP/1.1 xx\r\n\r\n");
        let mut grande = vec![0u8; 4096];
        grande[..7].copy_from_slice(b"HTTP/1.");
        let _ = carve_http(b"", &grande);
    }
}
