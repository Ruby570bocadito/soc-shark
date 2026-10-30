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

// ------------------------------------------------- escenarios hostiles

/// Escenarios hostiles **ordenados** (cada uno, una conversación completa)
/// para el corpus de fuzz: clases de entrada que las mutaciones aleatorias
/// de las tramas demo casi nunca producen.
///
/// - HTTP chunked con tamaños de chunk gigantes (`ffffffffffffffff`, más de
///   16 dígitos, `7fff…`): regresión del desborde de `pos + size` en el
///   carving.
/// - Respuesta con miles de `HTTP/1.` falsos sin fin de cabeceras
///   (búsqueda cuadrática en el carving).
/// - Datagrama IPv4 fragmentado (MF + offset, y fragmentos solapados).
/// - ClientHello TLS partido en dos registros y en segmentos TCP
///   desordenados con retransmisión.
pub fn hostile_scenarios() -> Vec<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for size in [
        "ffffffffffffffff",
        "fffffffffffffffffff",
        "7fffffffffffffff",
        "10000000000000000",
        "-1",
    ] {
        let mut body = b"4\r\nMZab\r\n".to_vec();
        body.extend_from_slice(size.as_bytes());
        body.extend_from_slice(b"\r\nresto del cuerpo\r\n0\r\n\r\n");
        out.push(http_exchange(
            b"GET /f.bin HTTP/1.1\r\nHost: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\n",
            &body,
            40100,
        ));
    }
    // Content-Length enorme y 304 con Content-Length (sin cuerpo).
    out.push(http_exchange(
        b"GET /a.jpg HTTP/1.1\r\n\r\nGET /b.exe HTTP/1.1\r\n\r\n",
        b"HTTP/1.1 304 Not Modified\r\nContent-Length: 18446744073709551615\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n",
        b"MZ\x90\x00",
        40110,
    ));
    // Miles de "HTTP/1." falsos repartidos en varios segmentos.
    let mut fake = Vec::new();
    while fake.len() < 6000 {
        fake.extend_from_slice(b"HTTP/1.1 200 HTTP/1.x ");
    }
    out.push(http_exchange(b"GET / HTTP/1.1\r\n\r\n", &fake, b"", 40120));

    out.push(fragmented_udp());
    out.push(tls_split_records());
    out
}

/// Intercambio HTTP en un flujo TCP: petición del cliente y respuesta del
/// servidor partida en segmentos de 1400 bytes.
fn http_exchange(req: &[u8], resp_head: &[u8], resp_body: &[u8], sport: u16) -> Vec<Vec<u8>> {
    use crate::{flags, frame_tcp, HOST_A, MAC_HOST_A, MAC_ROUTER, WEB};
    let (cseq, sseq) = (1000u32, 9000u32);
    let mut frames = vec![
        frame_tcp(
            MAC_HOST_A,
            MAC_ROUTER,
            HOST_A,
            WEB,
            sport,
            80,
            cseq - 1,
            0,
            flags::SYN,
            &[],
        ),
        frame_tcp(
            MAC_ROUTER,
            MAC_HOST_A,
            WEB,
            HOST_A,
            80,
            sport,
            sseq - 1,
            cseq,
            flags::SYN_ACK,
            &[],
        ),
        frame_tcp(
            MAC_HOST_A,
            MAC_ROUTER,
            HOST_A,
            WEB,
            sport,
            80,
            cseq,
            sseq,
            flags::PSH_ACK,
            req,
        ),
    ];
    let mut resp = resp_head.to_vec();
    resp.extend_from_slice(resp_body);
    let ack = cseq + req.len() as u32;
    for (i, chunk) in resp.chunks(1400).enumerate() {
        let seq = sseq + (i * 1400) as u32;
        frames.push(frame_tcp(
            MAC_ROUTER,
            MAC_HOST_A,
            WEB,
            HOST_A,
            80,
            sport,
            seq,
            ack,
            flags::PSH_ACK,
            chunk,
        ));
    }
    let fin_seq = sseq + resp.len() as u32;
    frames.push(frame_tcp(
        MAC_ROUTER,
        MAC_HOST_A,
        WEB,
        HOST_A,
        80,
        sport,
        fin_seq,
        ack,
        flags::FIN_ACK,
        &[],
    ));
    frames
}

/// Trama IPv4 con control de fragmentación explícito (id, MF, offset en
/// unidades de 8 bytes). `l4` es el trozo de datos del fragmento.
fn ipv4_fragment(id: u16, more: bool, offset8: u16, proto: u8, l4: &[u8]) -> Vec<u8> {
    use crate::{DNS_EXT, HOST_A, MAC_HOST_A, MAC_ROUTER};
    let mut f = crate::frame(MAC_HOST_A, MAC_ROUTER, HOST_A, DNS_EXT, 64, l4, proto);
    // Cabecera IP a partir del byte 14: id (18..20), flags+offset (20..22).
    f[18..20].copy_from_slice(&id.to_be_bytes());
    let fo = (if more { 0x2000 } else { 0 }) | (offset8 & 0x1fff);
    f[20..22].copy_from_slice(&fo.to_be_bytes());
    f[24..26].copy_from_slice(&[0, 0]);
    let ck = crate::checksum16(&f[14..34]);
    f[24..26].copy_from_slice(&ck.to_be_bytes());
    f
}

/// Consulta DNS sobre UDP fragmentada en tres trozos, más un fragmento
/// solapado y uno huérfano con offset máximo.
fn fragmented_udp() -> Vec<Vec<u8>> {
    let dgram = crate::udp(
        53999,
        53,
        &crate::dns_query(0x7777, "fragmentado.example", 1),
    );
    let (a, rest) = dgram.split_at(16);
    let (b, c) = rest.split_at(rest.len().min(16));
    vec![
        ipv4_fragment(0x4242, true, 0, 17, a),
        ipv4_fragment(0x4242, true, 2, 17, b),
        // Solape: reescribe parte del segundo trozo con otro contenido.
        ipv4_fragment(0x4242, true, 3, 17, &[0xee; 8]),
        ipv4_fragment(0x4242, false, 4, 17, c),
        // Huérfano: último fragmento con offset máximo de otro datagrama.
        ipv4_fragment(0x4343, false, 0x1fff, 17, b"cola"),
        // Primer fragmento sin el resto: cabecera UDP sin datagrama completo.
        ipv4_fragment(0x4444, true, 0, 17, a),
    ]
}

/// ClientHello partido en dos registros TLS (el mensaje cruza registros) y
/// enviado en segmentos TCP desordenados, con una retransmisión.
pub fn tls_split_records() -> Vec<Vec<u8>> {
    use crate::{flags, frame_tcp, HOST_A, MAC_HOST_A, MAC_ROUTER, WEB};
    let rec = crate::client_hello("partido.example", b"h2");
    let hs = &rec[5..]; // mensaje handshake sin cabecera de registro
    let cut = hs.len() / 3;
    let mut two = Vec::new();
    for part in [&hs[..cut], &hs[cut..]] {
        two.extend_from_slice(&[0x16, 0x03, 0x01]);
        two.extend_from_slice(&(part.len() as u16).to_be_bytes());
        two.extend_from_slice(part);
    }
    let isn = 5000u32;
    let mid = two.len() / 2;
    let seg = |seq: u32, data: &[u8]| {
        frame_tcp(
            MAC_HOST_A,
            MAC_ROUTER,
            HOST_A,
            WEB,
            40200,
            443,
            seq,
            1,
            flags::PSH_ACK,
            data,
        )
    };
    vec![
        frame_tcp(
            MAC_HOST_A,
            MAC_ROUTER,
            HOST_A,
            WEB,
            40200,
            443,
            isn,
            0,
            flags::SYN,
            &[],
        ),
        seg(isn + 1 + mid as u32, &two[mid..]),
        seg(isn + 1, &two[..mid]),
        seg(isn + 1, &two[..mid]),
        // Registro con longitud mentirosa (más de lo que llega).
        seg(
            isn + 1 + two.len() as u32,
            &[0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff],
        ),
    ]
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
    fn escenarios_hostiles_no_vacios_y_deterministas() {
        let a = hostile_scenarios();
        assert!(a.len() >= 8);
        assert!(a.iter().all(|s| !s.is_empty()));
        assert_eq!(a, hostile_scenarios());
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
