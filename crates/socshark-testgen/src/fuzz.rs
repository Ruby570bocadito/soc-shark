//! Fuzzing determinista en proceso (Fase 2).
//!
//! Generación reproducible de tramas malformadas a partir de las tramas
//! válidas del escenario demo: mutaciones bit a bit, truncados, basura
//! final, empalmes entre tramas y valores de cabecera mentirosos. El
//! objetivo no es maximizar cobertura (para eso está cargo-fuzz/libFuzzer,
//! documentado en CONTRIBUTING) sino ejercitar en cada build de CI el
//! camino completo *dissector → agregador → SOC → filtro* con entrada
//! hostil y atrapar panics y regressiones de robustez.
//!
//! Propiedades:
//! - **Determinismo**: `splitmix64` puro; la misma semilla reproduce
//!   exactamente el mismo corpus, así que un fallo se reproduce con
//!   `socshark dev fuzz --seed <S> --iterations <N+1>`.
//! - **Sin dependencias**: nada de `rand`; ~30 líneas de PRNG.

/// PRNG splitmix64 (Steele et al.): pequeño, rápido, determinista y sin
/// dependencias. No es criptográfico ni estadísticamente perfecto; para
/// mutar tramas sobra.
#[derive(Debug, Clone)]
pub struct FuzzRng {
    state: u64,
}

impl FuzzRng {
    pub fn new(seed: u64) -> Self {
        // Nunca una semilla 0: dejaría el generador degenerado.
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Entero uniforme en `[0, n)`. `n == 0` devuelve 0 (llamada errónea).
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }

    /// Lanzamiento de moneda con probabilidad `pct`%.
    pub fn coin(&mut self, pct: u64) -> bool {
        self.next_u64() % 100 < pct.min(100)
    }
}

/// Aplica una mutación aleatoria a una trama y devuelve una copia.
///
/// Catálogo (elegido por el RNG):
/// - volteo de un bit,
/// - sustitución de hasta 8 bytes por aleatorios,
/// - truncado a una longitud aleatoria,
/// - basura final (hasta 64 bytes),
/// - zeroizado de un rango (rompe checksums y longitudes de forma dirigida),
/// - intercambio de dos bytes (rompe estructuras sin romper el tamaño).
pub fn mutate_frame(rng: &mut FuzzRng, frame: &[u8]) -> Vec<u8> {
    let mut v = frame.to_vec();
    if v.is_empty() {
        // Trama base vacía: solo cabe añadir basura.
        let extra = rng.below(32) + 1;
        v.extend_from_slice(&random_bytes(rng, extra));
        return v;
    }
    match rng.below(6) {
        0 => {
            // Volteo de un bit.
            let pos = rng.below(v.len());
            let bit = rng.below(8) as u32;
            v[pos] ^= 1u8 << bit;
        }
        1 => {
            // Sustitución de 1..=8 bytes.
            let k = rng.below(8) + 1;
            for _ in 0..k {
                let pos = rng.below(v.len());
                v[pos] = (rng.next_u64() & 0xff) as u8;
            }
        }
        2 => {
            // Truncado (mínimo 1 byte para que el paquete no desaparezca).
            let keep = rng.below(v.len()) + 1;
            v.truncate(keep);
        }
        3 => {
            // Basura final.
            let extra = rng.below(64);
            v.extend_from_slice(&random_bytes(rng, extra));
        }
        4 => {
            // Zeroizado de un rango.
            let start = rng.below(v.len());
            let end = (start + rng.below(16) + 1).min(v.len());
            for b in &mut v[start..end] {
                *b = 0;
            }
        }
        _ => {
            // Intercambio de dos posiciones.
            let a = rng.below(v.len());
            let b = rng.below(v.len());
            v.swap(a, b);
        }
    }
    v
}

/// Empalma el prefijo de `a` con el sufijo de `b`: confunde a los parsers
/// con cabeceras de una trama y datos de otra (longitudes incoherentes).
pub fn splice_frames(rng: &mut FuzzRng, a: &[u8], b: &[u8]) -> Vec<u8> {
    let cut_a = a.len() / 4 + rng.below(a.len() / 2 + 1);
    let cut_b = b.len() / 4 + rng.below(b.len() / 2 + 1);
    let mut v = a[..cut_a.min(a.len())].to_vec();
    v.extend_from_slice(&b[cut_b.min(b.len())..]);
    v
}

fn random_bytes(rng: &mut FuzzRng, n: usize) -> Vec<u8> {
    (0..n).map(|_| (rng.next_u64() & 0xff) as u8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_misma_semilla_genera_el_mismo_corpus() {
        let mut r1 = FuzzRng::new(1234);
        let mut r2 = FuzzRng::new(1234);
        for _ in 0..100 {
            assert_eq!(r1.next_u64(), r2.next_u64());
        }
    }

    #[test]
    fn las_mutaciones_respetan_la_determinismo_y_no_panican() {
        let base = vec![0x45u8; 64];
        let mut r1 = FuzzRng::new(7);
        let mut r2 = FuzzRng::new(7);
        for _ in 0..500 {
            let m1 = mutate_frame(&mut r1, &base);
            let m2 = mutate_frame(&mut r2, &base);
            assert_eq!(m1, m2);
        }
    }

    #[test]
    fn el_empalme_mezcla_dos_tramas() {
        let mut rng = FuzzRng::new(9);
        let a = vec![0xAAu8; 40];
        let b = vec![0xBBu8; 40];
        let s = splice_frames(&mut rng, &a, &b);
        assert!(!s.is_empty());
        assert!(s.len() <= 80);
    }
}
