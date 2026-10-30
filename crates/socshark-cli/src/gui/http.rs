//! HTTP/1.1 mínimo para la GUI local (ADR-013): sin dependencias nuevas.
//!
//! Solo lo que necesita una página servida en `127.0.0.1` a un único
//! usuario: `GET`/`POST`, cabeceras, cuerpo por `Content-Length` y una
//! respuesta por conexión (`Connection: close`). Todo está acotado: tamaño
//! de cabeceras, de cuerpo y tiempo de lectura.

#[cfg(test)]
use std::io::BufReader;
use std::io::{self, BufRead, Read, Write};

/// Cota de la línea de petición más las cabeceras.
const MAX_HEAD: usize = 16 * 1024;

/// Petición ya leída.
#[derive(Debug, Default)]
pub struct Request {
    pub method: String,
    /// Ruta sin la query (`/api/flows`).
    pub path: String,
    /// Query cruda, sin `?` (`filter=tcp.port%20%3D%3D%20443`).
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// Cabecera por nombre, sin distinguir mayúsculas.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Parámetro de la query ya decodificado.
    pub fn query_param(&self, name: &str) -> Option<String> {
        self.query.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(k) == name).then(|| percent_decode(v))
        })
    }
}

/// Error al leer una petición, con el código HTTP que merece.
#[derive(Debug)]
pub enum ReadError {
    /// El cliente cerró o tardó demasiado: no se responde.
    Io,
    /// Petición mal formada o fuera de límites: se responde con `status`.
    Bad(u16, &'static str),
}

impl From<io::Error> for ReadError {
    fn from(_: io::Error) -> Self {
        ReadError::Io
    }
}

/// Lee una petición completa; el cuerpo se limita a `max_body` bytes.
#[cfg(test)]
pub fn read_request(stream: impl Read, max_body: usize) -> Result<Request, ReadError> {
    let mut reader = BufReader::new(stream);
    let mut req = read_head(&mut reader)?;
    read_body(&mut reader, &mut req, max_body)?;
    Ok(req)
}

/// Lee solo la línea de petición y las cabeceras (el cuerpo queda vacío y
/// sin leer). El servidor valida Host, token y ruta con esto ANTES de
/// aceptar un cuerpo: un cliente sin token no puede hacerle reservar nada.
pub fn read_head<R: BufRead>(reader: &mut R) -> Result<Request, ReadError> {
    let mut head_len = 0usize;
    let mut line = String::new();

    let mut read_line = |reader: &mut R, line: &mut String| -> Result<(), ReadError> {
        line.clear();
        let n = reader
            .by_ref()
            .take((MAX_HEAD - head_len.min(MAX_HEAD)) as u64 + 1)
            .read_line(line)?;
        head_len += n;
        if head_len > MAX_HEAD {
            return Err(ReadError::Bad(431, "cabeceras demasiado grandes"));
        }
        if n == 0 || !line.ends_with('\n') {
            // El cliente cerró a mitad de la cabecera.
            return Err(ReadError::Io);
        }
        Ok(())
    };

    read_line(reader, &mut line)?;
    let mut parts = line.trim_end().splitn(3, ' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(ReadError::Bad(400, "línea de petición inválida"));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(ReadError::Bad(505, "solo HTTP/1.x"));
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut req = Request {
        method: method.to_string(),
        path: path.to_string(),
        query: query.to_string(),
        ..Request::default()
    };

    loop {
        read_line(reader, &mut line)?;
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        let Some((k, v)) = l.split_once(':') else {
            return Err(ReadError::Bad(400, "cabecera inválida"));
        };
        req.headers
            .push((k.trim().to_string(), v.trim().to_string()));
    }

    Ok(req)
}

/// Lee el cuerpo anunciado por `Content-Length` (como mucho `max_body`).
///
/// No reserva de golpe lo que diga la cabecera: el búfer crece a medida que
/// llegan los datos (con `try_reserve`, sin abortar si falta memoria), así
/// que anunciar 512 MiB sin enviarlos no cuesta nada al servidor.
pub fn read_body(
    reader: &mut impl Read,
    req: &mut Request,
    max_body: usize,
) -> Result<(), ReadError> {
    let Some(len) = req.header("content-length") else {
        if req.header("transfer-encoding").is_some() {
            return Err(ReadError::Bad(411, "se requiere Content-Length"));
        }
        return Ok(());
    };
    let len: usize = len
        .parse()
        .map_err(|_| ReadError::Bad(400, "Content-Length inválido"))?;
    if len > max_body {
        return Err(ReadError::Bad(413, "archivo demasiado grande"));
    }
    let mut body = Vec::new();
    let mut chunk = vec![0u8; len.min(64 * 1024)];
    while body.len() < len {
        let want = (len - body.len()).min(chunk.len());
        let n = reader.read(&mut chunk[..want])?;
        if n == 0 {
            // El cliente cerró antes de enviar todo lo anunciado.
            return Err(ReadError::Io);
        }
        body.try_reserve(n)
            .map_err(|_| ReadError::Bad(503, "memoria insuficiente"))?;
        body.extend_from_slice(&chunk[..n]);
    }
    req.body = body;
    Ok(())
}

/// Decodifica `%XX` y `+` (espacio) de una query; secuencias inválidas se
/// dejan tal cual y los bytes no UTF-8 se sustituyen.
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = |c: &u8| (*c as char).to_digit(16);
                match (b.get(i + 1).and_then(hex), b.get(i + 2).and_then(hex)) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Respuesta a enviar.
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    /// Nombre de archivo si la respuesta es una descarga.
    pub attachment: Option<String>,
}

impl Response {
    pub fn new(status: u16, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type,
            body: body.into(),
            attachment: None,
        }
    }

    /// Descarga con nombre de archivo (solo ASCII seguro en la cabecera).
    pub fn download(filename: &str, content_type: &'static str, body: Vec<u8>) -> Self {
        let safe: String = filename
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        Self {
            attachment: Some(safe),
            ..Self::new(200, content_type, body)
        }
    }

    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        Self::new(status, "application/json; charset=utf-8", value.to_string())
    }

    pub fn error(status: u16, message: &str) -> Self {
        Self::json(status, &serde_json::json!({ "error": message }))
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Payload Too Large",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

/// Escribe la respuesta con las cabeceras de seguridad fijas de la GUI: la
/// página no se puede incrustar, no carga nada de fuera y no se cachea.
pub fn write_response(mut stream: impl Write, resp: &Response) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; \
         img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; \
         frame-ancestors 'none'\r\n",
        resp.status,
        reason(resp.status),
        resp.content_type,
        resp.body.len()
    );
    stream.write_all(head.as_bytes())?;
    if let Some(name) = &resp.attachment {
        write!(
            stream,
            "Content-Disposition: attachment; filename=\"{name}\"\r\n"
        )?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(&resp.body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(raw: &str) -> Result<Request, ReadError> {
        read_request(raw.as_bytes(), 1024)
    }

    #[test]
    fn lee_get_con_query_y_cabeceras() {
        let r = req("GET /api/flows?filter=tcp.port+%3D%3D+443&x=1 HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nX-Socshark-Token: abc\r\n\r\n").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/api/flows");
        assert_eq!(r.query_param("filter").as_deref(), Some("tcp.port == 443"));
        assert_eq!(r.query_param("x").as_deref(), Some("1"));
        assert_eq!(r.query_param("nada"), None);
        assert_eq!(r.header("host"), Some("127.0.0.1:8787"));
        assert_eq!(r.header("X-SOCSHARK-TOKEN"), Some("abc"));
    }

    #[test]
    fn lee_post_con_cuerpo_y_respeta_el_limite() {
        let r = req("POST /api/open HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd").unwrap();
        assert_eq!(r.body, b"abcd");
        assert!(matches!(
            req("POST /x HTTP/1.1\r\nContent-Length: 4096\r\n\r\n"),
            Err(ReadError::Bad(413, _))
        ));
        assert!(matches!(
            req("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(ReadError::Bad(411, _))
        ));
    }

    #[test]
    fn el_cuerpo_no_se_reserva_por_adelantado() {
        // Antes se hacía vec![0; Content-Length]: anunciar 1 TiB (sin
        // enviarlo) abortaba el proceso por falta de memoria.
        let raw = "POST /api/open HTTP/1.1\r\nContent-Length: 1099511627776\r\n\r\nabcd";
        assert!(matches!(
            read_request(raw.as_bytes(), usize::MAX),
            Err(ReadError::Io)
        ));
        // La cabecera se puede leer sin tocar el cuerpo.
        let mut r = BufReader::new(raw.as_bytes());
        let head = read_head(&mut r).unwrap();
        assert!(head.body.is_empty());
        assert_eq!(head.path, "/api/open");
    }

    #[test]
    fn rechaza_peticiones_malformadas_o_enormes() {
        assert!(matches!(req("BASURA\r\n\r\n"), Err(ReadError::Bad(400, _))));
        assert!(matches!(
            req("GET / SPDY/3\r\n\r\n"),
            Err(ReadError::Bad(505, _))
        ));
        let huge = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
        assert!(matches!(req(&huge), Err(ReadError::Bad(431, _))));
        assert!(matches!(req("GET / HTTP/1.1\r\n"), Err(ReadError::Io)));
    }

    #[test]
    fn decodificacion_de_query_tolera_basura() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
        assert_eq!(percent_decode("%C3%B1"), "ñ");
        assert_eq!(percent_decode("%FF"), "\u{fffd}");
    }
}
