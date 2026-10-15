//! Utilidades hexadecimales: conversión y volcado estilo visor clásico.

/// Bytes a hexadecimal minúsculo (`4d 5a 90 00` → `"4d5a9000"`).
pub fn to_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
    }
    out
}

/// Hexadecimal a bytes; acepta espacios, `:` y mayúsculas.
pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b':' && *b != b'-')
        .collect();
    if clean.len() % 2 != 0 {
        return Err("longitud hexadecimal impar".into());
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for pair in clean.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| format!("dígito inválido: {:?}", pair[0] as char))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("dígito inválido: {:?}", pair[1] as char))?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

/// Volcado hex+ASCII estilo editor clásico, 16 bytes por línea:
/// ```text
/// 00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
/// ```
pub fn hex_dump(data: &[u8]) -> String {
    let mut out = String::new();
    for (row, chunk) in data.chunks(16).enumerate() {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{:08x}  ", row * 16));
        for i in 0..16 {
            match chunk.get(i) {
                Some(&b) => {
                    let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x} "));
                }
                None => out.push_str("   "),
            }
            if i == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        for &b in chunk {
            out.push(if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            });
        }
        out.push_str("|\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversiones_basicas() {
        assert_eq!(to_hex(&[0x4d, 0x5a]), "4d5a");
        assert_eq!(from_hex("4D 5A").unwrap(), vec![0x4d, 0x5a]);
        assert_eq!(from_hex("4d:5a").unwrap(), vec![0x4d, 0x5a]);
        assert!(from_hex("abc").is_err());
        assert!(from_hex("zz").is_err());
    }

    #[test]
    fn dump_formato() {
        let d = hex_dump(b"MZ\x90\x00");
        assert!(d.starts_with("00000000  4d 5a 90 00"));
        assert!(d.contains("|MZ.."));
    }
}
