//! Entropía de Shannon por byte (bits/byte, rango 0.0–8.0).
//!
//! Usada por `soc-engine` para: detección de contenido cifrado/comprimido,
//! heurística de DNS tunneling (subdominios de alta entropía) y señales de
//! exfiltración en payloads.

/// Calcula la entropía de Shannon de `data` en bits por byte.
///
/// Devuelve `0.0` para datos vacíos. Datos totalmente aleatorios → ~8.0,
/// ASCII repetitivo → < 3.0, texto natural → ~4.0–4.5.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut hist = [0u64; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    let n = data.len() as f64;
    hist.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Entropía de una cadena (conveniencia para qnames DNS).
pub fn str_entropy(s: &str) -> f64 {
    shannon_entropy(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vacio_y_constante() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert_eq!(shannon_entropy(b"aaaaaaaa"), 0.0);
    }

    #[test]
    fn aleatorio_alto_texto_bajo() {
        // Serie pseudoaleatoria determinista (LCG) cubriendo todo el rango.
        let mut x: u64 = 0x2545F4914F6CDD1D;
        let rnd: Vec<u8> = (0..4096)
            .map(|_| {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (x >> 33) as u8
            })
            .collect();
        assert!(shannon_entropy(&rnd) > 7.9, "{}", shannon_entropy(&rnd));
        assert!(str_entropy("hola mundo hola mundo") < 3.5);
    }

    #[test]
    fn texto_natural_en_rango_esperado() {
        let e = str_entropy("the quick brown fox jumps over the lazy dog");
        assert!(e > 3.3 && e < 4.6, "{e}");
    }
}
