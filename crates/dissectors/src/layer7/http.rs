//! HTTP/1.1: peticiones y respuestas con cabeceras y cuerpo.
//!
//! Detectado por *sniffing de contenido* (métodos conocidos / línea de
//! estado), lo que permite encontrar HTTP en puertos no estándar — clave
//! para el detector de Port Mismatch de `soc-engine`.

/// Mensaje HTTP/1.x diseccionado.
#[derive(Debug, Clone)]
pub enum HttpMessage<'a> {
    Request(HttpRequest<'a>),
    Response(HttpResponse<'a>),
}

#[derive(Debug, Clone)]
pub struct HttpRequest<'a> {
    pub method: String,
    pub target: String,
    pub version: String,
    /// Cabeceras en orden, nombre en minúsculas.
    pub headers: Vec<(String, String)>,
    pub body: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct HttpResponse<'a> {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: &'a [u8],
}

impl<'a> HttpRequest<'a> {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    /// Extensión del target (`.exe`, `.pdf`...), minúsculas.
    pub fn target_extension(&self) -> Option<String> {
        let path = self.target.split('?').next().unwrap_or("");
        let file = path.rsplit('/').next().unwrap_or("");
        file.rsplit_once('.')
            .map(|(_, ext)| ext.to_ascii_lowercase())
    }
}

impl<'a> HttpResponse<'a> {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn content_length(&self) -> Option<u64> {
        self.header("content-length")
            .and_then(|v| v.trim().parse().ok())
    }

    pub fn is_chunked(&self) -> bool {
        self.header("transfer-encoding")
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false)
    }
}

const MAX_HEADERS: usize = 128;
const MAX_LINE: usize = 16 * 1024;

const METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

/// Intenta parsear HTTP/1.x; `None` si no lo parece (barato: comprueba el
/// inicio de la línea antes de escanear nada).
pub fn parse_http(data: &[u8]) -> Option<HttpMessage<'_>> {
    if data.len() < 16 {
        return None;
    }
    if starts_with_method(data) {
        parse_request(data).map(HttpMessage::Request)
    } else if data.starts_with(b"HTTP/") {
        parse_response(data).map(HttpMessage::Response)
    } else {
        None
    }
}

fn starts_with_method(data: &[u8]) -> bool {
    for m in METHODS {
        if data.len() > m.len() + 2
            && data[..m.len()].eq_ignore_ascii_case(m.as_bytes())
            && data[m.len()] == b' '
        {
            return true;
        }
    }
    false
}

fn find_header_end(data: &[u8]) -> Option<(usize, usize)> {
    // Devuelve (inicio del cuerpo, fin de la zona de cabeceras).
    let limit = data.len().min(256 * 1024);
    let window = &data[..limit];
    let pos = memchr_slice(b"\r\n\r\n", window)?;
    Some((pos + 4, pos))
}

fn memchr_slice(needle: &[u8], hay: &[u8]) -> Option<usize> {
    if hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_headers(data: &[u8], end: usize) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < end && out.len() < MAX_HEADERS {
        let line_end = match memchr_slice(b"\r\n", &data[pos..end]) {
            Some(p) => pos + p,
            None => end,
        };
        let line = &data[pos..line_end];
        if !line.is_empty() {
            if let Some(c) = line.iter().position(|&b| b == b':') {
                let name = String::from_utf8_lossy(&line[..c])
                    .trim()
                    .to_ascii_lowercase();
                let value = String::from_utf8_lossy(&line[c + 1..]).trim().to_string();
                if name.len() < 64 && value.len() < 4096 {
                    out.push((name, value));
                }
            }
        }
        if line_end + 2 > end {
            break;
        }
        pos = line_end + 2;
    }
    out
}

fn parse_request(data: &[u8]) -> Option<HttpRequest<'_>> {
    let line_end = memchr_slice(b"\r\n", &data[..data.len().min(MAX_LINE)])?;
    let line = std::str::from_utf8(&data[..line_end]).ok()?;
    let mut parts = line.split(' ').filter(|p| !p.is_empty());
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.0").to_string();
    if !version.starts_with("HTTP/") {
        return None;
    }
    let (body_start, hdr_end) = find_header_end(data)?;
    Some(HttpRequest {
        method,
        target,
        version,
        headers: parse_headers(&data[line_end + 2..], hdr_end - line_end - 2),
        body: &data[body_start..],
    })
}

fn parse_response(data: &[u8]) -> Option<HttpResponse<'_>> {
    let line_end = memchr_slice(b"\r\n", &data[..data.len().min(MAX_LINE)])?;
    let line = std::str::from_utf8(&data[..line_end]).ok()?;
    let mut parts = line.splitn(3, ' ');
    let version = parts.next()?.to_string();
    if !version.starts_with("HTTP/") {
        return None;
    }
    let status: u16 = parts.next()?.parse().ok()?;
    let reason = parts.next().unwrap_or("").to_string();
    let (body_start, hdr_end) = find_header_end(data)?;
    Some(HttpResponse {
        version,
        status,
        reason,
        headers: parse_headers(&data[line_end + 2..], hdr_end - line_end - 2),
        body: &data[body_start..],
    })
}

/// Descodifica un cuerpo `Transfer-Encoding: chunked` (fase 1: básico).
pub fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < body.len() && out.len() < 32 * 1024 * 1024 {
        let line_end = match memchr_slice(b"\r\n", &body[pos..]) {
            Some(p) => pos + p,
            None => break,
        };
        let size_str = String::from_utf8_lossy(&body[pos..line_end]);
        let size = usize::from_str_radix(size_str.trim().split(';').next().unwrap_or("0"), 16)
            .unwrap_or(0);
        pos = line_end + 2;
        if size == 0 || pos + size > body.len() {
            break;
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos += size + 2; // salta el CRLF final del chunk
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peticion_y_respuesta() {
        let req = b"POST /gate.php HTTP/1.1\r\nHost: c2.evil.ru\r\nUser-Agent: \r\nContent-Length: 4\r\n\r\nABCD";
        match parse_http(req).unwrap() {
            HttpMessage::Request(r) => {
                assert_eq!(r.method, "POST");
                assert_eq!(r.target, "/gate.php");
                assert_eq!(r.header("host"), Some("c2.evil.ru"));
                assert_eq!(r.header("USER-AGENT"), Some(""));
                assert_eq!(r.body, b"ABCD");
                assert_eq!(r.target_extension(), Some("php".into()));
            }
            _ => panic!("esperaba request"),
        }

        let res = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 3\r\n\r\nMZ\x90";
        match parse_http(res).unwrap() {
            HttpMessage::Response(r) => {
                assert_eq!(r.status, 200);
                assert_eq!(r.content_length(), Some(3));
                assert_eq!(r.body, b"MZ\x90");
            }
            _ => panic!("esperaba response"),
        }
    }

    #[test]
    fn rechaza_no_http() {
        assert!(parse_http(b"\x16\x03\x01\x00\x05hello-plaintext").is_none());
        assert!(parse_http(b"GETX /no-space").is_none());
        assert!(parse_http(b"").is_none());
    }

    #[test]
    fn dechunk_basico() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(dechunk(body), b"Wikipedia");
    }

    #[test]
    fn truncados_sin_panic() {
        let s = b"GET /a/b HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n12345";
        for n in 0..s.len() {
            let _ = parse_http(&s[..n]);
        }
    }
}
