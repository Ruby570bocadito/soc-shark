//! TLS: parser de ClientHello y huella JA4 (Fase 3).
//!
//! Implementa el estándar **JA4** de FoxIO (https://github.com/FoxIO-LLC/ja4)
//! sobre el ClientHello de TLS sobre TCP (`t` como primer carácter; QUIC y
//! DTLS quedan para fases posteriores). La huella permite identificar la
//! librería/binario cliente aunque el tráfico esté cifrado, y es la base del
//! hunting por huella contra bases públicas (ja4db).
//!
//! Decisiones de implementación:
//! - **SHA-256 propio** (en `socshark-core::hash`, ADR-011): el proyecto no
//!   añade dependencias criptográficas para un hash (ADR-003); el algoritmo
//!   es determinista y se valida contra los vectores de prueba oficiales de
//!   NIST y del propio spec JA4.
//! - **Sin panics**: todo acceso a bytes está acotado; un ClientHello
//!   malformado produce `None`, nunca un crash (mismo contrato que el resto
//!   de dissectors: los bytes son controlables por un atacante).
//! - **Captura acotada**: [`ClientHelloCapture`] acumula como máximo
//!   [`MAX_HELLO_BYTES`] por flujo; lo que exceda aborta la captura.
//!
//! Reglas del spec implementadas al pie de la letra:
//! - GREASE se ignora en todas partes (`(v & 0x0f0f) == 0x0a0a`).
//! - Versión: la mayor de `supported_versions` (0x002b) sin GREASE; si no
//!   existe, la `legacy_version` del cuerpo. El mapeo incluye `s3`, `s2` y
//!   DTLS (`d1`/`d2`/`d3`); desconocido = `00`.
//! - Recuento de ciphers y extensiones: sin GREASE, con SNI y ALPN incluidos,
//!   saturando a 99.
//! - Hash de ciphers: hex de 4 dígitos con ceros, minúsculas, orden hex;
//!   SCSV (0x00ff, 0x5600) y experimentales (0xfe00-0xfeff) se conservan.
//! - Hash de extensiones: igual, PERO sin SNI (0x0000) ni ALPN (0x0010);
//!   los signature algorithms se añaden al final **en el orden en que
//!   aparecen** (sin ordenar) tras un `_`.
//! - ALPN: primer y último carácter del primer valor si ambos son ASCII
//!   alfanumérico; en caso contrario, primer y último carácter del hex del
//!   valor completo; vacío o ausente = `00`.
//! - Lista vacía en un hash = `000000000000` (no sha256 de nada).

use std::fmt::Write as _;

/// Tope de bytes acumulados para capturar un ClientHello (los reales rondan
/// los 300-800 B; 16 KiB cubre con holgura los extremos legítimos).
pub const MAX_HELLO_BYTES: usize = 16 * 1024;

use socshark_core::hash::sha256;

/// Primeros 12 caracteres hex (minúscula) del SHA-256 de `data`.
fn sha256_12(data: &str) -> String {
    let digest = sha256(data.as_bytes());
    let mut hex = String::with_capacity(64);
    for b in digest {
        let _ = write!(hex, "{b:02x}");
    }
    hex.truncate(12);
    hex
}

// ------------------------------------------------------------ GREASE

/// Detecta un valor GREASE (RFC 8701 / draft-davidben-tls-grease): el patrón
/// `0x?a?a` (p. ej. 0x0a0a, 0x1a1a, ... 0xfafa). El spec JA4 manda ignorar
/// GREASE en todas partes.
fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a
}

// ------------------------------------------------------------ ClientHello

/// ClientHello analizado, con los campos que alimenta JA4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Campo `legacy_version` del cuerpo (0x0303 en clientes modernos).
    pub legacy_version: [u8; 2],
    /// Cipher suites en el orden ofrecido.
    pub cipher_suites: Vec<u16>,
    /// Extensiones en el orden ofrecido como `(tipo, datos crudos)`.
    pub extensions: Vec<(u16, Vec<u8>)>,
    /// Nombre del servidor (SNI, extensión 0x0000), si va indicado.
    pub sni: Option<String>,
    /// Primer valor del ALPN (extensión 0x0010), si existe.
    pub alpn: Option<Vec<u8>>,
    /// Signature algorithms (extensión 0x000d) en el orden ofrecido.
    pub sig_algs: Vec<u16>,
    /// Versiones de `supported_versions` (extensión 0x002b).
    pub supported_versions: Vec<u16>,
}

impl ClientHello {
    /// True si el cliente envió la extensión SNI (0x0000). Es lo único que
    /// mira el spec JA4 para la bandera `d`/`i`: no importa si el nombre es
    /// UTF-8 válido ni si la lista está bien formada.
    pub fn has_sni_extension(&self) -> bool {
        self.sni.is_some() || self.extensions.iter().any(|(t, _)| *t == 0x0000)
    }

    /// Extrae el SNI y el ALPN de los datos crudos de las extensiones.
    fn populate_extras(&mut self) {
        for (etype, data) in &self.extensions {
            match *etype {
                0x0000 if self.sni.is_none() => self.sni = parse_sni(data),
                0x0010 if self.alpn.is_none() => self.alpn = parse_alpn(data),
                0x000d if self.sig_algs.is_empty() => {
                    self.sig_algs = parse_u16_list_be(data, 2);
                }
                0x002b if self.supported_versions.is_empty() => {
                    self.supported_versions = parse_u16_list_be(data, 1);
                }
                _ => {}
            }
        }
    }

    /// Versión TLS normalizada del spec: 2 caracteres (`13`, `12`, `s3`, ...).
    fn tls_version_str(&self) -> String {
        // La mayor supported_versions sin GREASE manda; si no hay, la legacy.
        let chosen = {
            let best = self
                .supported_versions
                .iter()
                .copied()
                .filter(|v| !is_grease(*v))
                .max();
            match best {
                Some(v) => v,
                None => u16::from_be_bytes(self.legacy_version),
            }
        };
        match chosen {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            0x0300 => "s3",
            0x0002 => "s2",
            0xfeff => "d1",
            0xfefd => "d2",
            0xfefc => "d3",
            _ => "00",
        }
        .to_string()
    }

    /// Primer y último carácter del primer valor ALPN según el spec.
    fn alpn_str(&self) -> String {
        let Some(alpn) = self.alpn.as_deref().filter(|a| !a.is_empty()) else {
            return "00".into();
        };
        let first = alpn[0];
        let last = alpn[alpn.len() - 1];
        let alnum = |b: u8| b.is_ascii_alphanumeric();
        if alnum(first) && alnum(last) {
            [(first as char), (last as char)].iter().collect()
        } else {
            // Fallback: primer y último carácter del hex del valor completo.
            let hex: String = alpn.iter().map(|b| format!("{b:02x}")).collect();
            match (hex.chars().next(), hex.chars().last()) {
                (Some(a), Some(b)) => format!("{a}{b}"),
                _ => "00".into(),
            }
        }
    }

    /// Calcula la huella JA4 completa, p. ej.
    /// `t13d1516h2_8daaf6152771_e5627efa2ab1`.
    pub fn ja4(&self) -> String {
        // ---- Parte a: proto + versión + SNI + recuentos + ALPN ----
        let n_ciphers = self
            .cipher_suites
            .iter()
            .filter(|c| !is_grease(**c))
            .count();
        let n_exts = self
            .extensions
            .iter()
            .filter(|(t, _)| !is_grease(*t))
            .count();
        let part_a = format!(
            "t{}{}{:02}{:02}{}",
            self.tls_version_str(),
            if self.has_sni_extension() { "d" } else { "i" },
            n_ciphers.min(99),
            n_exts.min(99),
            self.alpn_str(),
        );

        // ---- Parte b: hash de ciphers (sin GREASE; SCSV/reservados sí) ----
        let mut ciphers: Vec<String> = self
            .cipher_suites
            .iter()
            .filter(|c| !is_grease(**c))
            .map(|c| format!("{c:04x}"))
            .collect();
        ciphers.sort();
        let part_b = if ciphers.is_empty() {
            "000000000000".to_string()
        } else {
            sha256_12(&ciphers.join(","))
        };

        // ---- Parte c: hash de extensiones (sin GREASE/SNI/ALPN) + sig algs ----
        let mut exts: Vec<String> = self
            .extensions
            .iter()
            .filter(|(t, _)| !is_grease(*t) && *t != 0x0000 && *t != 0x0010)
            .map(|(t, _)| format!("{t:04x}"))
            .collect();
        exts.sort();
        let part_c = if exts.is_empty() {
            "000000000000".to_string()
        } else {
            let mut s = exts.join(",");
            if !self.sig_algs.is_empty() {
                // Los sig algs van EN EL ORDEN EN QUE APARECEN, sin ordenar.
                s.push('_');
                let list = self
                    .sig_algs
                    .iter()
                    .map(|a| format!("{a:04x}"))
                    .collect::<Vec<_>>()
                    .join(",");
                s.push_str(&list);
            }
            sha256_12(&s)
        };

        format!("{part_a}_{part_b}_{part_c}")
    }
}

/// Parsea la extensión SNI: devuelve el host_name del primer entrada tipo 0.
fn parse_sni(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let end = (list_len + 2).min(data.len());
    let mut p = &data[2..end];
    while p.len() >= 3 {
        let ntype = p[0];
        let nlen = u16::from_be_bytes([p[1], p[2]]) as usize;
        if p.len() < 3 + nlen {
            return None;
        }
        if ntype == 0 {
            return String::from_utf8(p[3..3 + nlen].to_vec()).ok();
        }
        p = &p[3 + nlen..];
    }
    None
}

/// Parsea la lista ALPN: devuelve el primer nombre de protocolo.
fn parse_alpn(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let end = (list_len + 2).min(data.len());
    let p = &data[2..end];
    if p.is_empty() {
        return None;
    }
    let plen = p[0] as usize;
    if p.len() < 1 + plen {
        return None;
    }
    Some(p[1..1 + plen].to_vec())
}

/// Parsea una lista de u16 big-endian tras una longitud inicial de
/// `hdr_bytes` bytes (2 para sig_algs, 1 para supported_versions).
fn parse_u16_list_be(data: &[u8], hdr_bytes: usize) -> Vec<u16> {
    if data.len() < hdr_bytes {
        return Vec::new();
    }
    let p = &data[hdr_bytes..];
    // as_chunks es de Rust 1.88; el MSRV del workspace es 1.75 (ADR-001).
    #[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
    p.chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

/// Parsea un ClientHello desde los bytes del mensaje handshake (incluida la
/// cabecera de 4 bytes: tipo 0x01 + longitud de 3 bytes).
///
/// Devuelve `None` si el mensaje está truncado o malformado (contrato
/// sin-panics del proyecto).
pub fn parse_client_hello(data: &[u8]) -> Option<ClientHello> {
    if data.len() < 4 || data[0] != 0x01 {
        return None;
    }
    let hs_len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | data[3] as usize;
    if data.len() < 4 + hs_len || hs_len < 34 {
        return None; // truncado o sin sitio para versión+random
    }
    let body = &data[4..4 + hs_len];

    // cuerpo: version(2) random(32) sid_len(1) sid... cs_len(2) ciphers...
    let mut p = &body[34..]; // version + random
    if p.is_empty() {
        return None;
    }
    let sid_len = p[0] as usize;
    p = &p[1..];
    if p.len() < sid_len + 2 {
        return None;
    }
    p = &p[sid_len..];
    let cs_len = u16::from_be_bytes([p[0], p[1]]) as usize;
    p = &p[2..];
    // is_multiple_of es de Rust 1.87; el MSRV del workspace es 1.75 (ADR-001).
    #[allow(clippy::manual_is_multiple_of)]
    if cs_len < 2 || cs_len % 2 != 0 || p.len() < cs_len {
        return None;
    }
    let cipher_suites: Vec<u16> = {
        // as_chunks es de Rust 1.88; el MSRV del workspace es 1.75 (ADR-001).
        #[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
        let pairs = p[..cs_len].chunks_exact(2);
        pairs.map(|c| u16::from_be_bytes([c[0], c[1]])).collect()
    };
    p = &p[cs_len..];

    // compression methods: al menos 1 (null).
    if p.is_empty() {
        return None;
    }
    let comp_len = p[0] as usize;
    p = &p[1..];
    if p.len() < comp_len {
        return None;
    }
    p = &p[comp_len..];
    // El bloque de extensiones es opcional en TLS 1.0/1.1 (RFC 4346 §7.4.1.2):
    // si el cuerpo termina tras la compresión, son cero extensiones (JA4
    // cuenta `00`). Un único byte suelto sí es un mensaje malformado.
    let ext_len = match p.len() {
        0 => 0,
        1 => return None,
        _ => {
            let l = u16::from_be_bytes([p[0], p[1]]) as usize;
            p = &p[2..];
            l
        }
    };
    if p.len() < ext_len {
        return None;
    }

    let mut extensions = Vec::new();
    let mut ep = &p[..ext_len];
    while ep.len() >= 4 {
        let etype = u16::from_be_bytes([ep[0], ep[1]]);
        let elen = u16::from_be_bytes([ep[2], ep[3]]) as usize;
        if ep.len() < 4 + elen {
            return None; // extensión truncada
        }
        extensions.push((etype, ep[4..4 + elen].to_vec()));
        ep = &ep[4 + elen..];
    }

    let mut ch = ClientHello {
        legacy_version: [body[0], body[1]],
        cipher_suites,
        extensions,
        sni: None,
        alpn: None,
        sig_algs: Vec::new(),
        supported_versions: Vec::new(),
    };
    ch.populate_extras();
    Some(ch)
}

// ------------------------------------------------------------ captura por flujo

/// Estado de la captura del ClientHello de un flujo.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HelloState {
    /// Aún no se ve el primer payload del iniciador.
    Idle,
    /// Acumulando bytes del handshake.
    Accumulating,
    /// ClientHello completo y parseado.
    Complete,
    /// No es TLS / truncado / no empezó por handshake: no insistir.
    Failed,
}

/// Acumulador acotado que reconstruye el ClientHello de un flujo a partir de
/// los payloads TCP del iniciador (puede venir partido en varios segmentos o
/// incluso en varios registros TLS).
///
/// Uso: [`ClientHelloCapture::feed`] con cada payload en dirección fwd;
/// [`ClientHelloCapture::hello`] devuelve el ClientHello cuando está completo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloCapture {
    buf: Vec<u8>,
    state: HelloState,
    hello: Option<ClientHello>,
}

impl Default for ClientHelloCapture {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            state: HelloState::Idle,
            hello: None,
        }
    }
}

impl ClientHelloCapture {
    /// Alimenta con el siguiente payload en dirección iniciador→servidor.
    /// Los payloads que no empiezan por un registro handshake TLS marcan la
    /// captura como fallida de forma permanente (el CH es lo primero que
    /// envía un cliente TLS legítimo). Un primer segmento de un solo byte
    /// `0x16` no basta para decidir: se acumula y se espera al siguiente.
    ///
    /// Los payloads deben llegar **en orden de secuencia TCP y sin
    /// duplicados** (retransmisiones descartadas): ordenar es tarea del
    /// agregador de flujos, este acumulador solo concatena.
    pub fn feed(&mut self, payload: &[u8]) {
        match self.state {
            HelloState::Complete | HelloState::Failed => {}
            HelloState::Idle => match payload {
                [] => {}
                [0x16] | [0x16, 0x03, ..] => {
                    self.state = HelloState::Accumulating;
                    self.push(payload);
                }
                _ => self.state = HelloState::Failed,
            },
            HelloState::Accumulating => self.push(payload),
        }
    }

    fn push(&mut self, payload: &[u8]) {
        if self.buf.len().saturating_add(payload.len()) > MAX_HELLO_BYTES {
            self.state = HelloState::Failed;
            return;
        }
        self.buf.extend_from_slice(payload);
        self.try_finish();
    }

    /// Intenta completar: recorre los registros TLS acumulados (cabecera de
    /// 5 B cada uno), concatena sus cuerpos quitando esas cabeceras y espera
    /// a tener el mensaje handshake íntegro (cabecera de 4 B + cuerpo),
    /// aunque cruce varios registros y segmentos.
    fn try_finish(&mut self) {
        // Segundo byte del primer registro: versión mayor 3 (SSL3/TLS).
        if self.buf.len() >= 2 && self.buf[1] != 0x03 {
            self.state = HelloState::Failed;
            return;
        }
        let mut hs: Vec<u8> = Vec::new();
        let mut rest = &self.buf[..];
        while rest.len() >= 5 {
            // Todos los registros que transportan el CH son de handshake.
            if rest[0] != 0x16 || rest[1] != 0x03 {
                self.state = HelloState::Failed;
                return;
            }
            let rec_len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
            if rec_len == 0 {
                // Prohibido por RFC 8446 §5.1 para handshake: no insistir.
                self.state = HelloState::Failed;
                return;
            }
            // Un registro aún incompleto aporta lo que ya haya llegado.
            let body = &rest[5..];
            let take = rec_len.min(body.len());
            hs.extend_from_slice(&body[..take]);
            rest = &body[take..];
        }
        if hs.len() < 4 {
            return; // esperar más segmentos
        }
        if hs[0] != 0x01 {
            self.state = HelloState::Failed;
            return;
        }
        let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
        if hs_len > MAX_HELLO_BYTES {
            self.state = HelloState::Failed;
            return;
        }
        let needed = 4 + hs_len;
        if hs.len() < needed {
            return; // esperar más registros/segmentos
        }
        match parse_client_hello(&hs[..needed]) {
            Some(hello) => {
                self.hello = Some(hello);
                self.state = HelloState::Complete;
            }
            None => self.state = HelloState::Failed,
        }
    }

    /// ClientHello completo, si la captura llegó a buen puerto.
    pub fn hello(&self) -> Option<&ClientHello> {
        self.hello.as_ref()
    }

    /// Huella JA4 si hay ClientHello completo.
    pub fn ja4(&self) -> Option<String> {
        self.hello.as_ref().map(|h| h.ja4())
    }

    /// True si ya no tiene sentido seguir alimentando (éxito o fracaso).
    pub fn is_done(&self) -> bool {
        matches!(self.state, HelloState::Complete | HelloState::Failed)
    }
}

// ------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;

    /// ClientHello canónico del spec FoxIO: 15 ciphers, 16 extensiones,
    /// SNI + ALPN "h2" + supported_versions TLS 1.3 + sig algs.
    /// Debe producir exactamente `t13d1516h2_8daaf6152771_e5627efa2ab1`.
    #[test]
    fn ja4_vector_canonico_del_spec() {
        let ch = ClientHello {
            legacy_version: [0x03, 0x03],
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: vec![
                (0x001b, vec![]),
                (0x0000, vec![0, 0, 0, 3, b'a', b'.', b'b']), // SNI presente
                (0x0033, vec![0, 1, 2, 3]),
                (0x0010, b"h2".to_vec()), // datos sin formato real, suficiente para el test del campo ALPN
                (0x4469, vec![]),
                (0x0017, vec![]),
                (0x002d, vec![1]),
                (0x000d, vec![]),
                (0x0005, vec![]),
                (0x0023, vec![]),
                (0x0012, vec![]),
                (0x002b, vec![4, 0x03, 0x04, 0x03, 0x03]), // supported_versions
                (0xff01, vec![]),
                (0x000b, vec![]),
                (0x000a, vec![]),
                (0x0015, vec![]),
            ],
            sni: Some("a.b".into()),
            alpn: Some(b"h2".to_vec()),
            sig_algs: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            supported_versions: vec![0x0304, 0x0303],
        };
        // Hash de ciphers del spec: "002f,0035,009c,009d,1301,1302,1303,c013,
        // c014,c02b,c02c,c02f,c030,cca8,cca9" -> 8daaf6152771
        assert_eq!(
            sha256_12("002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"),
            "8daaf6152771"
        );
        // Hash de extensiones del spec (sin 0000 ni 0010, con sig algs al final):
        assert_eq!(
            sha256_12(
                "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_\
                 0403,0804,0401,0503,0805,0501,0806,0601"
            ),
            "e5627efa2ab1"
        );
        assert_eq!(ch.ja4(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    /// Construye un registro TLS completo a partir del cuerpo del handshake.
    /// La longitud del registro incluye la cabecera de handshake (4 B).
    fn record(hs_body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x16, 0x03, 0x01];
        let l = hs_body.len();
        out.extend_from_slice(&((l + 4) as u16).to_be_bytes());
        out.push(0x01);
        out.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        out.extend_from_slice(hs_body);
        out
    }

    /// ClientHello binario realista: TLS 1.2 legacy, 2 ciphers, SNI, ALPN h2,
    /// sig algs, supported_versions (1.3) — el del escenario demo.
    pub(crate) fn demo_client_hello(sni: &str, alpn: &[u8]) -> Vec<u8> {
        // Extensiones
        let mut sni_ext = Vec::new();
        let name = sni.as_bytes();
        sni_ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);

        let mut alpn_ext = Vec::new();
        alpn_ext.extend_from_slice(&((alpn.len() + 1) as u16).to_be_bytes());
        alpn_ext.push(alpn.len() as u8);
        alpn_ext.extend_from_slice(alpn);

        let sig: [u8; 16] = [
            0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06,
            0x06, 0x01,
        ];
        let mut sig_ext = Vec::new();
        sig_ext.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        sig_ext.extend_from_slice(&sig);

        let sv_ext = vec![4u8, 0x03, 0x04, 0x03, 0x03]; // TLS 1.3, 1.2

        let groups_ext = vec![4u8, 0x00, 0x1d, 0x00, 0x17]; // x25519, secp256r1
        let ks_ext = vec![64u8, 0x00, 0x1d, 0x00, 0x20]; // key_share cabecera mínima
        let ks: Vec<u8> = {
            // repeat_n es de Rust 1.82; el MSRV del workspace es 1.75 (ADR-001).
            #[allow(clippy::manual_repeat_n)]
            let bytes = std::iter::once(0x20).chain(std::iter::repeat(0x11).take(32));
            bytes.collect()
        };

        let exts: [(u16, Vec<u8>); 8] = [
            (0x0000, sni_ext),
            (0x0010, alpn_ext),
            (0x000d, sig_ext),
            (0x002b, sv_ext.clone()),
            (0x000a, groups_ext),
            (0x0033, [ks_ext, ks].concat()),
            (0x002d, vec![1]),
            (0x0017, vec![]),
        ];
        let mut ext_blob = Vec::new();
        for (t, d) in &exts {
            ext_blob.extend_from_slice(&t.to_be_bytes());
            ext_blob.extend_from_slice(&(d.len() as u16).to_be_bytes());
            ext_blob.extend_from_slice(d);
        }

        // Cuerpo del handshake
        let mut body = vec![0x03, 0x03]; // legacy_version TLS 1.2
        body.extend_from_slice(&[0xaa; 32]); // random
        body.push(0x00); // session_id vacío
        let ciphers: [u8; 4] = [0x13, 0x01, 0xc0, 0x2b]; // TLS_AES_128_GCM, ECDHE-ECDSA-AES128
        body.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
        body.extend_from_slice(&ciphers);
        body.push(0x01);
        body.push(0x00); // compression: null
        body.extend_from_slice(&(ext_blob.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_blob);
        record(&body)
    }

    #[test]
    fn parse_y_huella_del_client_hello_de_demo() {
        let sni = "tienda.ejemplo-corporativo.com";
        let rec = demo_client_hello(sni, b"h2");
        let ch = parse_client_hello(&rec[5..]).expect("ClientHello bien formado");
        assert_eq!(ch.sni.as_deref(), Some(sni));
        assert_eq!(ch.alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(ch.tls_version_str(), "13");
        assert_eq!(ch.cipher_suites, vec![0x1301, 0xc02b]);
        // t + TLS1.3 + dominio + 02 ciphers + 08 extensiones + h2 (10 chars)
        assert_eq!(ch.ja4(), "t13d0208h2_777cda164f4b_af51ac0c444f");
    }

    #[test]
    fn captura_por_segmentos_partidos() {
        let rec = demo_client_hello("partido.example", b"h2");
        let mut cap = ClientHelloCapture::default();
        let (a, b) = rec.split_at(7);
        let (b, c) = b.split_at(30);
        cap.feed(a);
        assert!(cap.hello().is_none());
        cap.feed(b);
        assert!(cap.hello().is_none(), "aún incompleto");
        cap.feed(c);
        assert_eq!(
            cap.ja4().as_deref(),
            Some("t13d0208h2_777cda164f4b_af51ac0c444f")
        );
        // Alimentaciones posteriores se ignoran.
        cap.feed(&[0x16, 0x03]);
        assert_eq!(
            cap.ja4().as_deref(),
            Some("t13d0208h2_777cda164f4b_af51ac0c444f")
        );
    }

    #[test]
    fn primer_segmento_de_un_byte_no_falla() {
        // Regresión: un primer segmento [0x16] marcaba la captura como fallida.
        let rec = demo_client_hello("byte.example", b"h2");
        let mut cap = ClientHelloCapture::default();
        cap.feed(&rec[..1]);
        assert!(!cap.is_done());
        cap.feed(&rec[1..]);
        assert_eq!(cap.hello().unwrap().sni.as_deref(), Some("byte.example"));
    }

    #[test]
    fn client_hello_repartido_en_varios_registros() {
        // Regresión: el CH partido en dos registros TLS fallaba porque la
        // cabecera del segundo registro quedaba en medio del handshake.
        let rec = demo_client_hello("registros.example", b"h2");
        let hs = &rec[5..];
        let (a, b) = hs.split_at(40);
        let mut two = Vec::new();
        for part in [a, b] {
            two.extend_from_slice(&[0x16, 0x03, 0x01]);
            two.extend_from_slice(&(part.len() as u16).to_be_bytes());
            two.extend_from_slice(part);
        }
        // Además partido en segmentos TCP arbitrarios (uno corta la 2ª cabecera).
        let mut cap = ClientHelloCapture::default();
        for chunk in [&two[..3], &two[3..46], &two[46..47], &two[47..]] {
            cap.feed(chunk);
        }
        assert_eq!(
            cap.ja4().as_deref(),
            Some("t13d0208h2_777cda164f4b_af51ac0c444f")
        );
    }

    #[test]
    fn client_hello_sin_extensiones_tls10() {
        // TLS 1.0 sin bloque de extensiones: válido, cero extensiones.
        let mut body = vec![0x03, 0x01];
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
        body.extend_from_slice(&[0x01, 0x00]);
        let rec = record(&body);
        let ch = parse_client_hello(&rec[5..]).expect("extensiones opcionales");
        assert!(ch.extensions.is_empty());
        assert!(ch.ja4().starts_with("t10i010000_"), "{}", ch.ja4());
        let mut cap = ClientHelloCapture::default();
        cap.feed(&rec);
        assert!(cap.hello().is_some());
        // Un byte suelto donde iría la longitud sí es malformado.
        let mut body1 = body.clone();
        body1.push(0x00);
        assert!(parse_client_hello(&record(&body1)[5..]).is_none());
    }

    #[test]
    fn sni_no_utf8_sigue_contando_como_dominio() {
        // La bandera 'd' depende de la presencia de la extensión 0x0000,
        // no de que el nombre sea UTF-8 válido.
        let ch = ClientHello {
            legacy_version: [0x03, 0x03],
            cipher_suites: vec![0x1301],
            extensions: vec![(0x0000, vec![0, 4, 0, 0, 1, 0xff])],
            sni: None,
            alpn: None,
            sig_algs: vec![],
            supported_versions: vec![],
        };
        assert!(ch.ja4().starts_with("t12d0101"), "{}", ch.ja4());
    }

    #[test]
    fn primer_payload_no_tls_falla_permanentemente() {
        let mut cap = ClientHelloCapture::default();
        cap.feed(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        cap.feed(&demo_client_hello("a.example", b"h2"));
        assert!(cap.hello().is_none());
        assert!(cap.is_done());
    }

    #[test]
    fn hello_truncado_por_tope_no_paniquea() {
        let mut cap = ClientHelloCapture::default();
        // Cabecera que declara más de MAX_HELLO_BYTES → Failed, sin alloc.
        cap.feed(&[0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0x00]);
        assert!(cap.is_done());
        assert!(cap.hello().is_none());

        // Fragmentación patológica hasta el tope: también Failed, sin panic.
        let mut cap2 = ClientHelloCapture::default();
        cap2.feed(&[0x16, 0x03, 0x01]);
        let chunk = [0x42u8; 4096];
        for _ in 0..5 {
            cap2.feed(&chunk);
        }
        assert!(cap2.is_done());
    }

    #[test]
    fn alpn_no_alfanumerico_usa_hex() {
        let ch = ClientHello {
            legacy_version: [0x03, 0x03],
            cipher_suites: vec![0x1301],
            extensions: vec![(0x0010, vec![0x20, 0x61]), (0x002b, vec![4, 0x03, 0x04])],
            sni: None,
            alpn: Some(vec![0x20, 0x61]), // ' ' y 'a': el primero no es alfanum
            sig_algs: vec![],
            supported_versions: vec![0x0304],
        };
        // hex "2061" → primer '2', último '1' → "21"
        assert_eq!(ch.alpn_str(), "21");
        assert!(ch.ja4().starts_with("t13i010221_"), "huella: {}", ch.ja4());
    }

    #[test]
    fn sin_sni_sin_alpn_usa_i_y_00() {
        let ch = ClientHello {
            legacy_version: [0x03, 0x03],
            cipher_suites: vec![0x1301, 0x1302],
            extensions: vec![(0x002b, vec![2, 0x03, 0x04]), (0x000a, vec![])],
            sni: None,
            alpn: None,
            sig_algs: vec![],
            supported_versions: vec![0x0304],
        };
        let j = ch.ja4();
        assert!(j.starts_with("t13i020200_"), "huella: {j}");
        // Sin SNI el destino es IP: 'i'. Sin ALPN: "00".
    }
}
