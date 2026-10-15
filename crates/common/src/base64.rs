//! Codificador/decodificador Base64 estándar (RFC 4648) en Rust puro.

const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Codifica `data` en Base64 con padding `=`.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TBL[(n >> 18) as usize & 63] as char);
        out.push(TBL[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TBL[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TBL[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodifica Base64 tolerante a espacios en blanco y padding ausente.
pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let clean: &[u8] = match clean.iter().position(|&b| b == b'=') {
        Some(i) => {
            if clean[i..].iter().any(|&b| b != b'=') {
                return Err("padding '=' en posición intermedia".into());
            }
            &clean[..i]
        }
        None => &clean,
    };
    let mut out = Vec::with_capacity(clean.len() / 4 * 3 + 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in clean {
        let v = val(c).ok_or_else(|| format!("carácter Base64 inválido: {:?}", c as char))?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if bits >= 6 {
        return Err("longitud Base64 inválida (residuo de bits)".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valores_conocidos() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"Hello"), "SGVsbG8=");
        assert_eq!(decode("SGVsbG8=").unwrap(), b"Hello");
    }

    #[test]
    fn roundtrip_binario() {
        let data: Vec<u8> = (0u8..=255).cycle().take(977).collect();
        assert_eq!(decode(&encode(&data)).unwrap(), data);
    }

    #[test]
    fn tolera_espacios_y_sin_padding() {
        assert_eq!(decode("SGVs\nbG8").unwrap(), b"Hello");
        assert!(decode("SGV!bG8=").is_err());
    }
}
