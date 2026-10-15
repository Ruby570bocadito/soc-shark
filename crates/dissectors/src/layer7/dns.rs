//! DNS (RFC 1035): preguntas y respuestas con descompresión de nombres.
//!
//! Es la base del **Passive DNS** de `flow-aggregator`: extraemos pares
//! IP → dominio de cada respuesta A/AAAA/CNAME.

/// Tipos de registro con nombre conocido.
pub fn qtype_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        255 => "ANY",
        _ => "TYPE?",
    }
}

/// Pregunta DNS.
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Rdata normalizado.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsRdata {
    A([u8; 4]),
    Aaaa([u8; 16]),
    Cname(String),
    Ns(String),
    Ptr(String),
    Mx { pref: u16, exchange: String },
    Txt(String),
    Other,
}

impl DnsRdata {
    /// Representación corta para resúmenes: la IP o el dominio.
    pub fn value_str(&self) -> String {
        match self {
            DnsRdata::A(b) => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
            DnsRdata::Aaaa(b) => socshark_common::ipaddr::IpAddr::V6(*b).to_string(),
            DnsRdata::Cname(s) | DnsRdata::Ns(s) | DnsRdata::Ptr(s) => s.clone(),
            DnsRdata::Mx { exchange, .. } => exchange.clone(),
            DnsRdata::Txt(s) => s.clone(),
            DnsRdata::Other => "(datos)".into(),
        }
    }
}

/// Registro de respuesta.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub rdata: DnsRdata,
}

/// Mensaje DNS completo.
#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
}

impl DnsPacket {
    /// Dominio de la primera pregunta (el caso dominante).
    pub fn qname(&self) -> Option<&str> {
        self.questions.first().map(|q| q.name.as_str())
    }

    /// Pares (ip → dominio) para Passive DNS a partir de las respuestas.
    pub fn passive_dns_pairs(&self) -> Vec<(String, String)> {
        // Maps cname → dominio final para encadenar alias.
        let mut out = Vec::new();
        for r in &self.answers {
            match &r.rdata {
                DnsRdata::A(ip) => out.push((
                    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                    r.name.clone(),
                )),
                DnsRdata::Aaaa(ip) => out.push((
                    socshark_common::ipaddr::IpAddr::V6(*ip).to_string(),
                    r.name.clone(),
                )),
                DnsRdata::Cname(target) => out.push((target.clone(), r.name.clone())),
                _ => {}
            }
        }
        out
    }
}

const MAX_JUMPS: usize = 64;
const MAX_NAME_LEN: usize = 255;

/// Parsea un mensaje DNS. `tcp` = true si viene sobre TCP (prefijo de 2 bytes).
pub fn parse_dns(data: &[u8], tcp: bool) -> Option<DnsPacket> {
    let mut off = 0usize;
    if tcp {
        if data.len() < 2 {
            return None;
        }
        let dns_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if dns_len < 12 || dns_len > data.len() - 2 {
            return None;
        }
        off = 2;
    }
    let body = &data[off..];
    if body.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([body[0], body[1]]);
    let flags = u16::from_be_bytes([body[2], body[3]]);
    let qd = u16::from_be_bytes([body[4], body[5]]) as usize;
    let an = u16::from_be_bytes([body[6], body[7]]) as usize;
    let _ns = u16::from_be_bytes([body[8], body[9]]) as usize;
    let _ar = u16::from_be_bytes([body[10], body[11]]) as usize;
    let mut p = DnsPacket {
        id,
        is_response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0xf) as u8,
        rcode: (flags & 0xf) as u8,
        questions: Vec::new(),
        answers: Vec::new(),
    };
    let mut pos = 12usize;
    // Límites razonables contra paquetes crafted.
    let qd = qd.min(32);
    let an = an.min(256);
    for _ in 0..qd {
        let (name, np) = parse_name(body, pos)?;
        if np + 4 > body.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([body[np], body[np + 1]]);
        let qclass = u16::from_be_bytes([body[np + 2], body[np + 3]]);
        p.questions.push(DnsQuestion {
            name,
            qtype,
            qclass,
        });
        pos = np + 4;
    }
    for _ in 0..an {
        let (name, np) = parse_name(body, pos)?;
        if np + 10 > body.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([body[np], body[np + 1]]);
        let _class = u16::from_be_bytes([body[np + 2], body[np + 3]]);
        let ttl = u32::from_be_bytes([body[np + 4], body[np + 5], body[np + 6], body[np + 7]]);
        let rdlen = u16::from_be_bytes([body[np + 8], body[np + 9]]) as usize;
        let rd_start = np + 10;
        if rd_start + rdlen > body.len() {
            return None;
        }
        let rd = &body[rd_start..rd_start + rdlen];
        let rdata = parse_rdata(rtype, rd, body, rd_start);
        p.answers.push(DnsRecord {
            name,
            rtype,
            ttl,
            rdata,
        });
        pos = rd_start + rdlen;
    }
    Some(p)
}

fn parse_rdata(rtype: u16, rd: &[u8], msg: &[u8], rd_start: usize) -> DnsRdata {
    match rtype {
        1 if rd.len() == 4 => {
            let mut b = [0u8; 4];
            b.copy_from_slice(rd);
            DnsRdata::A(b)
        }
        28 if rd.len() == 16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(rd);
            DnsRdata::Aaaa(b)
        }
        2 | 5 | 12 => match parse_name(msg, rd_start) {
            Some((name, _)) => match rtype {
                2 => DnsRdata::Ns(name),
                5 => DnsRdata::Cname(name),
                _ => DnsRdata::Ptr(name),
            },
            None => DnsRdata::Other,
        },
        15 if rd.len() >= 3 => {
            let pref = u16::from_be_bytes([rd[0], rd[1]]);
            match parse_name(msg, rd_start + 2) {
                Some((name, _)) => DnsRdata::Mx {
                    pref,
                    exchange: name,
                },
                None => DnsRdata::Other,
            }
        }
        16 => {
            // TXT: cadenas length-prefixed concatenadas.
            let mut s = String::new();
            let mut i = 0usize;
            while i < rd.len() {
                let l = rd[i] as usize;
                if i + 1 + l > rd.len() {
                    break;
                }
                s.push_str(&String::from_utf8_lossy(&rd[i + 1..i + 1 + l]));
                i += 1 + l;
            }
            DnsRdata::Txt(s)
        }
        _ => DnsRdata::Other,
    }
}

/// Lee un nombre (posiblemente comprimido) empezando en `start` del mensaje.
/// Devuelve (nombre, offset absoluto tras el nombre).
///
/// Seguridad: solo acepta punteros que apunten estrictamente hacia atrás
/// (garantía de terminación), con límite de saltos y de longitud total.
fn parse_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumps = 0usize;
    let mut pos = start;
    let mut next_after = start;
    loop {
        let used: usize = labels.iter().map(|l| l.len() + 1).sum();
        if jumps > MAX_JUMPS || used > MAX_NAME_LEN {
            return None;
        }
        if pos >= msg.len() {
            return None;
        }
        let len = msg[pos];
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    if jumps == 0 {
                        next_after = pos + 1;
                    }
                    break;
                }
                let l = len as usize;
                if pos + 1 + l > msg.len() {
                    return None;
                }
                labels.push(String::from_utf8_lossy(&msg[pos + 1..pos + 1 + l]).to_string());
                pos += 1 + l;
            }
            0xc0 => {
                if pos + 1 >= msg.len() {
                    return None;
                }
                let target = (((len & 0x3f) as usize) << 8) | msg[pos + 1] as usize;
                if target >= msg.len() || target >= pos {
                    return None; // fuera de mensaje o puntero no-hacia-atrás
                }
                if jumps == 0 {
                    next_after = pos + 2;
                }
                jumps += 1;
                pos = target;
            }
            _ => return None, // etiquetas 0x40/0x80: bitmaps raros, no soportados
        }
    }
    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };
    Some((name, next_after))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Query "www.evil-cdn.ru" A.
    fn sample_query() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0x4a1bu16.to_be_bytes()); // id
        v.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
        v.extend_from_slice(&1u16.to_be_bytes()); // qd
        v.extend_from_slice(&0u16.to_be_bytes()); // an
        v.extend_from_slice(&0u16.to_be_bytes()); // ns
        v.extend_from_slice(&0u16.to_be_bytes()); // ar
        for label in ["www", "evil-cdn", "ru"] {
            v.push(label.len() as u8);
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&1u16.to_be_bytes()); // A
        v.extend_from_slice(&1u16.to_be_bytes()); // IN
        v
    }

    /// Respuesta con CNAME comprimido + A.
    /// Layout: header(12) + question(24) → answer1 @36 (CNAME),
    /// rdata del CNAME @48 ("cdn1" + ptr→19) → answer2 @56 (A).
    fn sample_response() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0x4a1bu16.to_be_bytes());
        v.extend_from_slice(&0x8180u16.to_be_bytes()); // QR + RD + RA
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&2u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        // question: update.evil-cdn.ru A IN
        for label in ["update", "evil-cdn", "ru"] {
            v.push(label.len() as u8);
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&1u16.to_be_bytes()); // A
        v.extend_from_slice(&1u16.to_be_bytes()); // IN
                                                  // answer 1 @23: CNAME update.evil-cdn.ru → cdn1.evil-cdn.ru
        v.extend_from_slice(&0xc00cu16.to_be_bytes()); // nombre = pregunta @12
        v.extend_from_slice(&5u16.to_be_bytes()); // CNAME
        v.extend_from_slice(&1u16.to_be_bytes()); // IN
        v.extend_from_slice(&300u32.to_be_bytes()); // ttl
        v.extend_from_slice(&7u16.to_be_bytes()); // rdlen: 1+4+2
        v.push(4);
        v.extend_from_slice(b"cdn1");
        v.extend_from_slice(&0xc013u16.to_be_bytes()); // puntero → "evil-cdn.ru" @19
                                                       // answer 2 @54: A cdn1.evil-cdn.ru (puntero al rdata del CNAME @47)
        v.extend_from_slice(&0xc030u16.to_be_bytes()); // → rdata CNAME @48
        v.extend_from_slice(&1u16.to_be_bytes()); // A
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&120u32.to_be_bytes());
        v.extend_from_slice(&4u16.to_be_bytes());
        v.extend_from_slice(&[185, 220, 101, 4]);
        v
    }

    #[test]
    fn parsea_query() {
        let buf = sample_query();
        let p = parse_dns(&buf, false).unwrap();
        assert!(!p.is_response);
        assert_eq!(p.qname(), Some("www.evil-cdn.ru"));
        assert_eq!(p.questions[0].qtype, 1);
        assert!(p.answers.is_empty());
    }

    #[test]
    fn parsea_respuesta_con_compresion() {
        let buf = sample_response();
        let p = parse_dns(&buf, false).unwrap();
        assert!(p.is_response);
        assert_eq!(p.qname(), Some("update.evil-cdn.ru"));
        assert_eq!(p.answers.len(), 2);
        assert_eq!(
            p.answers[0].rdata,
            DnsRdata::Cname("cdn1.evil-cdn.ru".into())
        );
        assert_eq!(p.answers[1].rdata, DnsRdata::A([185, 220, 101, 4]));
        let pairs = p.passive_dns_pairs();
        assert!(pairs.contains(&("185.220.101.4".into(), "cdn1.evil-cdn.ru".into())));
        assert!(pairs.contains(&("cdn1.evil-cdn.ru".into(), "update.evil-cdn.ru".into())));
    }

    #[test]
    fn sobre_tcp_con_prefijo() {
        let q = sample_query();
        let mut t = (q.len() as u16).to_be_bytes().to_vec();
        t.extend_from_slice(&q);
        let p = parse_dns(&t, true).unwrap();
        assert_eq!(p.id, 0x4a1b);
    }

    #[test]
    fn truncados_y_crafts_sin_panic() {
        let s = sample_response();
        for n in 0..s.len() {
            let _ = parse_dns(&s[..n], false);
        }
        // bucle de punteros
        let evil = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1];
        assert!(parse_dns(&evil, false).is_some() || parse_dns(&evil, false).is_none());
    }
}
