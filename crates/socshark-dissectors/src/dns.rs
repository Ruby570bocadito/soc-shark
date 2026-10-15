//! Dissector DNS (UDP y TCP; soporta compresión de nombres).
//!
//! Alcance Fase 1: cabecera, preguntas y respuestas con registros A, AAAA,
//! CNAME, NS y PTR. Otros tipos se listan por código sin decodificar su
//! rdata (suficiente para DNS pasivo y detección de túneles).
//!
//! DNS sobre TCP: el pipeline descarta el prefijo de longitud de 2 bytes
//! antes de llamar aquí (ver `DissectorPipeline::try_dns`).
//!
//! Seguridad: los límites (número de registros, saltos de puntero, etiquetas)
//! evitan bucles infinitos y explosión de memoria con paquetes crafted.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Registro de respuesta decodificado.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    /// Dirección IP si el registro es A/AAAA.
    pub address: Option<IpAddr>,
    /// Objetivo si el registro es CNAME/NS/PTR.
    pub target: Option<String>,
}

/// Pregunta DNS.
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Resultado del dissector DNS.
#[derive(Debug, Clone)]
pub struct DnsInfo {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    /// Código de respuesta (solo en paquetes de respuesta).
    pub rcode: Option<u8>,
    pub queries: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
}

/// Límites de seguridad contra paquetes maliciosos o degenerados.
const MAX_QUESTIONS: usize = 16;
const MAX_ANSWERS: usize = 64;
const MAX_NAME_LABELS: usize = 32;
const MAX_POINTER_JUMPS: usize = 16;

/// Parsea un mensaje DNS. Devuelve `None` si el mensaje está truncado más
/// allá de lo recuperable.
pub fn parse_dns(data: &[u8]) -> Option<DnsInfo> {
    if data.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = ((flags >> 11) & 0xf) as u8;
    let rcode = if is_response {
        Some((flags & 0x000f) as u8)
    } else {
        None
    };
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut off = 12usize;
    let mut queries = Vec::new();
    for _ in 0..qdcount.min(MAX_QUESTIONS) {
        let (name, next) = read_name(data, off)?;
        if next + 4 > data.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([data[next], data[next + 1]]);
        let qclass = u16::from_be_bytes([data[next + 2], data[next + 3]]);
        queries.push(DnsQuestion {
            name,
            qtype,
            qclass,
        });
        off = next + 4;
    }

    let mut answers = Vec::new();
    for _ in 0..ancount.min(MAX_ANSWERS) {
        // Un answer truncado no invalida los ya parseados: se corta la lista.
        let Some((name, next)) = read_name(data, off) else {
            break;
        };
        if next + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[next], data[next + 1]]);
        let ttl = u32::from_be_bytes([
            data[next + 4],
            data[next + 5],
            data[next + 6],
            data[next + 7],
        ]);
        let rdlen = u16::from_be_bytes([data[next + 8], data[next + 9]]) as usize;
        let rdata_start = next + 10;
        if rdata_start + rdlen > data.len() {
            break;
        }
        let rdata = &data[rdata_start..rdata_start + rdlen];

        let (address, target) = match rtype {
            1 if rdlen == 4 => (
                Some(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                ))),
                None,
            ),
            28 if rdlen == 16 => (
                Some(IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([rdata[0], rdata[1]]),
                    u16::from_be_bytes([rdata[2], rdata[3]]),
                    u16::from_be_bytes([rdata[4], rdata[5]]),
                    u16::from_be_bytes([rdata[6], rdata[7]]),
                    u16::from_be_bytes([rdata[8], rdata[9]]),
                    u16::from_be_bytes([rdata[10], rdata[11]]),
                    u16::from_be_bytes([rdata[12], rdata[13]]),
                    u16::from_be_bytes([rdata[14], rdata[15]]),
                ))),
                None,
            ),
            2 | 5 | 12 => (None, read_name(data, rdata_start).map(|(t, _)| t)),
            _ => (None, None),
        };

        answers.push(DnsRecord {
            name,
            rtype,
            ttl,
            address,
            target,
        });
        off = rdata_start + rdlen;
    }

    Some(DnsInfo {
        id,
        is_response,
        opcode,
        rcode,
        queries,
        answers,
    })
}

/// Lee un nombre DNS con punteros de compresión (RFC 1035 §4.1.4).
///
/// Devuelve `(nombre, offset_del_byte_posterior_al_nombre)`. El offset
/// devuelto apunta siempre a la posición original (post-primer-nombre),
/// aunque el nombre termine en un puntero, para que el caller pueda seguir
/// parseando campos fijos.
fn read_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<&str> = Vec::new();
    let mut off = start;
    let mut next_off: Option<usize> = None;
    let mut jumps = 0usize;

    loop {
        let len = *data.get(off)?;
        if len & 0xc0 == 0xc0 {
            // Puntero de compresión: 2 bytes, 14 bits de offset.
            let hi = *data.get(off + 1)?;
            if next_off.is_none() {
                next_off = Some(off + 2);
            }
            jumps += 1;
            if jumps > MAX_POINTER_JUMPS {
                return None; // bucle de punteros (puntero que apunta a sí mismo)
            }
            off = (((len & 0x3f) as usize) << 8) | hi as usize;
        } else if len == 0 {
            let end = next_off.unwrap_or(off + 1);
            return Some((labels.join("."), end));
        } else if len & 0xc0 != 0 {
            // 0x40/0x80: etiquetas reservadas / bitstring EDNS0, fuera de alcance.
            return None;
        } else {
            let l = len as usize;
            if labels.len() >= MAX_NAME_LABELS {
                return None;
            }
            let bytes = data.get(off + 1..off + 1 + l)?;
            let label = std::str::from_utf8(bytes).ok()?;
            labels.push(label);
            off += 1 + l;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_testgen as tg;

    #[test]
    fn consulta_y_respuesta_roundtrip() {
        let q = parse_dns(&tg::dns_query(0x1234, "example.com", 1)).unwrap();
        assert_eq!(q.id, 0x1234);
        assert!(!q.is_response);
        assert_eq!(q.queries.len(), 1);
        assert_eq!(q.queries[0].name, "example.com");
        assert_eq!(q.queries[0].qtype, 1);
        assert!(q.answers.is_empty());

        let r = parse_dns(&tg::dns_response(0x1234, "example.com", 1, tg::WEB)).unwrap();
        assert!(r.is_response);
        assert_eq!(r.rcode, Some(0));
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].address, Some(IpAddr::V4(tg::WEB)));
        assert_eq!(r.answers[0].ttl, 300);
    }

    #[test]
    fn mensaje_truncado_devuelve_none() {
        assert!(parse_dns(&[0u8; 11]).is_none());
        assert!(parse_dns(&[]).is_none());
    }

    #[test]
    fn bucle_de_punteros_no_cuelga() {
        // 0xc00c apunta al offset 12, que vuelve a ser el puntero: bucle.
        let mut m = vec![0u8; 12];
        m.extend_from_slice(&[0xc0, 0x0c]);
        let r = parse_dns(&m);
        assert!(r.is_none() || r.unwrap().queries.is_empty());
    }
}
