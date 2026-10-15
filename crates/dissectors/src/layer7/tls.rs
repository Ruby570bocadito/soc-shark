//! TLS: capa de registros + ClientHello con fingerprint JA4-like.
//!
//! El JA4-like calcula la misma forma que JA4 (`t13d1516h2_<hash>_<hash>`)
//! pero es una aproximación honesta: la fase 3 lo sustituirá por el cálculo
//! canónico (ver `docs/08-ebpf.md` § atribución y fingerprinting).

/// Registro TLS diseccionado.
#[derive(Debug)]
pub struct TlsRecord<'a> {
    /// 20=change_cipher_spec, 21=alert, 22=handshake, 23=application_data.
    pub content_type: u8,
    /// Versión del registro como (mayor, menor).
    pub version: (u8, u8),
    /// ClientHello si el primer handshake lo es.
    pub client_hello: Option<ClientHello<'a>>,
}

/// ClientHello parseado.
#[derive(Debug)]
pub struct ClientHello<'a> {
    pub version: (u8, u8),
    pub cipher_suites: Vec<u16>,
    /// (tipo, bytes) de cada extensión.
    pub extensions: Vec<(u16, &'a [u8])>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    /// Versión negociada por supported_versions (TLS 1.3 = 0x0304).
    pub supported_version: Option<(u8, u8)>,
}

impl ClientHello<'_> {
    /// Fingerprint JA4-like: `t{ver}{d|i}{ciphers}{exts}{alpn}_c_c`.
    ///
    /// - `ver`: 13 si supported_versions anuncia TLS1.3, 12/11 según registro.
    /// - `d|i`: SNI presente o no.
    /// - `ciphers`/`exts`: recuentos a 2 dígitos (exts sin SNI ni ALPN,
    ///   como JA4 real).
    /// - `alpn`: primer y último carácter del protocolo (`h2` → `h2`... JA4
    ///   usa primero+último; aquí directamente los 2 primeros chars) o `00`.
    /// - Hashes: SHA-256 (12 hex) de cipher suites y de tipos de extensión.
    pub fn ja4_like(&self, record_version: (u8, u8)) -> String {
        let ver = match self.supported_version {
            Some((3, 4)) => "13".to_string(),
            Some((3, minor)) => format!("1{}", minor - 1),
            _ => match record_version.1 {
                3 => "12".to_string(),
                m if m < 3 => format!("1{}", m.saturating_sub(1)),
                _ => "12".to_string(),
            },
        };
        let sni_c = if self.sni.is_some() { 'd' } else { 'i' };
        let ext_count = self
            .extensions
            .iter()
            .filter(|(t, _)| *t != 0x0000 && *t != 0x0010)
            .count();
        let alpn_c = match &self.alpn {
            Some(a) if a.len() >= 2 => a[..2].to_ascii_lowercase(),
            Some(a) if !a.is_empty() => {
                let mut s = a.to_ascii_lowercase();
                s.push('0');
                s
            }
            _ => "00".to_string(),
        };
        let mut cipher_bytes = Vec::with_capacity(self.cipher_suites.len() * 2);
        for c in &self.cipher_suites {
            cipher_bytes.extend_from_slice(&c.to_be_bytes());
        }
        let mut ext_bytes = Vec::new();
        for (t, _) in self
            .extensions
            .iter()
            .filter(|(t, _)| *t != 0 && *t != 0x10)
        {
            ext_bytes.extend_from_slice(&t.to_be_bytes());
        }
        format!(
            "t{}{}{:02}{:02}{}_{}_{}",
            ver,
            sni_c,
            self.cipher_suites.len(),
            ext_count,
            alpn_c,
            &socshark_common::sha256::sha256_hex(&cipher_bytes)[..12],
            &socshark_common::sha256::sha256_hex(&ext_bytes)[..12],
        )
    }
}

/// Parsea un registro TLS (asume un solo registro al inicio del payload).
pub fn parse_tls(data: &[u8]) -> Option<TlsRecord<'_>> {
    if data.len() < 5 {
        return None;
    }
    let content_type = data[0];
    if !matches!(content_type, 20..=23) {
        return None;
    }
    let version = (data[1], data[2]);
    if version.0 != 3 || version.1 > 4 {
        return None;
    }
    let len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if len == 0 || 5 + len > data.len() {
        return None;
    }
    let body = &data[5..5 + len];
    let client_hello = if content_type == 22 && !body.is_empty() && body[0] == 1 {
        parse_client_hello(&body[4..]).map(|(ch, _)| ch)
    } else {
        None
    };
    Some(TlsRecord {
        content_type,
        version,
        client_hello,
    })
}

/// ¿Parece el inicio de un handshake TLS? (para sniffing en puertos raros)
pub fn looks_like_tls(data: &[u8]) -> bool {
    data.len() >= 6 && data[0] == 0x16 && data[1] == 3 && (data[5] == 1 || data[5] == 2)
}

type ChParse<'a> = (ClientHello<'a>, usize);

/// Parsea el cuerpo del ClientHello (después del header de handshake de 4 bytes).
fn parse_client_hello(body: &[u8]) -> Option<ChParse<'_>> {
    if body.len() < 34 {
        return None;
    }
    let version = (body[0], body[1]);
    let mut pos = 34usize; // version(2) + random(32)
                           // session id
    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > body.len() {
        return None;
    }
    // cipher suites
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if cs_len % 2 != 0 || pos + cs_len > body.len() || cs_len > 512 {
        return None;
    }
    let mut ciphers = Vec::with_capacity(cs_len / 2);
    for i in 0..cs_len / 2 {
        ciphers.push(u16::from_be_bytes([
            body[pos + i * 2],
            body[pos + i * 2 + 1],
        ]));
    }
    pos += cs_len;
    // compression methods
    if pos >= body.len() {
        return None;
    }
    let comp_len = body[pos] as usize;
    pos += 1 + comp_len;
    if pos + comp_len > body.len() {
        return None;
    }
    // extensions
    let mut exts = Vec::new();
    let mut sni = None;
    let mut alpn = None;
    let mut supported_version = None;
    if pos + 2 <= body.len() {
        let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        let end = (pos + ext_total).min(body.len());
        let mut p = pos;
        let mut guard = 0;
        while p + 4 <= end && guard < 256 {
            guard += 1;
            let etype = u16::from_be_bytes([body[p], body[p + 1]]);
            let elen = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
            if p + 4 + elen > end {
                break;
            }
            let edata = &body[p + 4..p + 4 + elen];
            match etype {
                0x0000 => sni = parse_sni(edata),
                0x0010 => alpn = parse_alpn(edata),
                0x002b => {
                    if edata.len() >= 3 {
                        // list_len(2) + entries de 2
                        supported_version = Some((edata[2], edata[3]));
                    }
                }
                _ => {}
            }
            exts.push((etype, edata));
            p += 4 + elen;
        }
        pos = p;
    }
    Some((
        ClientHello {
            version,
            cipher_suites: ciphers,
            extensions: exts,
            sni,
            alpn,
            supported_version,
        },
        pos,
    ))
}

fn parse_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }
    let name_type = data[2];
    if name_type != 0 {
        return None;
    }
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if name_len == 0 || 5 + name_len > data.len() || name_len > 255 {
        return None;
    }
    let s = String::from_utf8_lossy(&data[5..5 + name_len]).to_string();
    if s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
    {
        Some(s)
    } else {
        None
    }
}

fn parse_alpn(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if list_len == 0 || data.len() < 2 + list_len {
        return None;
    }
    let l = data[2] as usize;
    if l == 0 || 3 + l > data.len() || l > 64 {
        return None;
    }
    let s = String::from_utf8_lossy(&data[3..3 + l]).to_string();
    if s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"+.-_".contains(&b))
    {
        Some(s)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ClientHello sintético con SNI, ALPN h2 y 2 cipher suites.
    fn sample_client_hello() -> Vec<u8> {
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // legacy version TLS1.2
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0); // session id vacío
        ch.extend_from_slice(&4u16.to_be_bytes()); // 2 suites
        ch.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
        ch.extend_from_slice(&0xc02fu16.to_be_bytes()); // ECDHE_RSA_AES128
        ch.push(1);
        ch.push(0); // compression null
                    // extensions
        let mut exts = Vec::new();
        // SNI: update.evil-cdn.ru
        let name = b"update.evil-cdn.ru";
        let mut sni_body = Vec::new();
        sni_body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni_body.push(0);
        sni_body.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_body.extend_from_slice(name);
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_body);
        // ALPN: h2
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&5u16.to_be_bytes()); // list_len(2)+entry_len(1)+"h2"
        exts.extend_from_slice(&3u16.to_be_bytes()); // lista: 1 entrada
        exts.push(2); // longitud de "h2"
        exts.extend_from_slice(b"h2");
        // supported_versions: TLS1.3
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&4u16.to_be_bytes()); // list_len(2) + entrada(2)
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.extend_from_slice(&[0x03, 0x04]);
        ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        ch.extend_from_slice(&exts);
        // handshake header
        let mut hs = vec![1u8];
        let l = ch.len();
        hs.push(((l >> 16) & 0xff) as u8);
        hs.push(((l >> 8) & 0xff) as u8);
        hs.push((l & 0xff) as u8);
        hs.extend_from_slice(&ch);
        // record header
        let mut rec = vec![0x16u8, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parsea_client_hello_y_ja4() {
        let buf = sample_client_hello();
        let rec = parse_tls(&buf).unwrap();
        assert_eq!(rec.content_type, 22);
        let ch = rec.client_hello.expect("debería haber ClientHello");
        assert_eq!(ch.sni.as_deref(), Some("update.evil-cdn.ru"));
        assert_eq!(ch.alpn.as_deref(), Some("h2"));
        assert_eq!(ch.cipher_suites.len(), 2);
        assert_eq!(ch.supported_version, Some((3, 4)));
        let fp = ch.ja4_like(rec.version);
        assert!(fp.starts_with("t13d0201h2_"), "{fp}");
        assert_eq!(fp.split('_').count(), 3, "{fp}");
    }

    #[test]
    fn rechaza_no_tls_y_truncados() {
        assert!(parse_tls(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_none());
        let s = sample_client_hello();
        for n in 0..s.len() {
            let _ = parse_tls(&s[..n]);
        }
    }

    #[test]
    fn sniffing() {
        assert!(looks_like_tls(&sample_client_hello()));
        assert!(!looks_like_tls(b"HTTP/1.1 200 OK\r\n"));
    }
}
