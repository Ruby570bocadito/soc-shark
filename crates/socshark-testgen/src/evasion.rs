//! Escenarios de evasión (hoja de ruta 0.8) y sus contraejemplos legítimos.
//!
//! - Túnel DNS de **baja entropía**: 200 subdominios únicos y cortos
//!   (`a0001.t.evil.com`...) que la regla por consulta (entropía) no ve y la
//!   de volumen sí.
//! - Navegación normal: muchos nombres repartidos entre muchos dominios,
//!   consultas repetidas al mismo nombre y resolución inversa (PTR).
//! - Beacon con **jitter aleatorio** uniforme (estilo Cobalt Strike
//!   `jitter`), entre conexiones (TCP) y dentro de un flujo (UDP), y su
//!   contraejemplo: conexiones interactivas de cola pesada.
//!
//! Todo determinista: el jitter sale de [`crate::fuzz::FuzzRng`] con semilla.

use std::net::Ipv4Addr;

use crate::fuzz::FuzzRng;
use crate::*;

/// Inicio común de los escenarios (2023-11-14T22:13:20Z).
const T0: u64 = 1_700_000_000_000_000;

/// Dominio del túnel de baja entropía.
pub const LOW_ENTROPY_TUNNEL_DOMAIN: &str = "evil.com";

/// Consulta DNS de `client` a [`DNS_EXT`], cada una en su flujo (puerto
/// origen distinto, como hacen los resolutores).
fn query(t: u64, client: Ipv4Addr, sport: u16, name: &str, qtype: u16) -> (u64, Vec<u8>) {
    (
        t,
        frame_udp(
            MAC_HOST_C,
            MAC_ROUTER,
            client,
            DNS_EXT,
            sport,
            53,
            &dns_query(sport, name, qtype),
        ),
    )
}

/// Túnel DNS de baja entropía: [`HOST_C`] pregunta por 200 subdominios
/// únicos `a0001.t.evil.com`..`a0200.t.evil.com` (TXT), uno cada 2 s
/// (≈ 6.7 min). Ningún nombre es largo ni aleatorio: solo el volumen
/// delata el túnel.
pub fn dns_low_entropy_tunnel_packets() -> Vec<(u64, Vec<u8>)> {
    (1..=200u16)
        .map(|i| {
            query(
                T0 + u64::from(i) * 2_000_000,
                HOST_C,
                30_000 + i,
                &format!("a{i:04}.t.{LOW_ENTROPY_TUNNEL_DOMAIN}"),
                16,
            )
        })
        .collect()
}

/// Nombres de una sesión de navegación normal: 30 hosts de muchos dominios.
pub const BROWSER_HOSTS: [&str; 30] = [
    "www.google.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "www.gstatic.com",
    "apis.google.com",
    "www.youtube.com",
    "i.ytimg.com",
    "yt3.ggpht.com",
    "www.wikipedia.org",
    "upload.wikimedia.org",
    "es.wikipedia.org",
    "github.com",
    "avatars.githubusercontent.com",
    "api.github.com",
    "collector.github.com",
    "www.bbc.co.uk",
    "static.files.bbci.co.uk",
    "ichef.bbci.co.uk",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "ajax.cloudflare.com",
    "static.cloudflareinsights.com",
    "www.elpais.com",
    "static.elpais.com",
    "imagenes.elpais.com",
    "connect.facebook.net",
    "www.googletagmanager.com",
    "stats.g.doubleclick.net",
    "outlook.office365.com",
    "login.microsoftonline.com",
];

/// Tráfico DNS legítimo de [`HOST_A`]: una sesión de navegación (30 nombres
/// de muchos dominios), 100 consultas al **mismo** subdominio de telemetría
/// y 100 resoluciones inversas (PTR) de la LAN. Nada debe alertar.
pub fn dns_benign_packets() -> Vec<(u64, Vec<u8>)> {
    let mut p = Vec::new();
    let mut sport = 20_000u16;
    let mut next = |t: u64, name: &str, qtype: u16, p: &mut Vec<(u64, Vec<u8>)>| {
        sport += 1;
        p.push(query(t, HOST_A, sport, name, qtype));
    };
    for (i, host) in BROWSER_HOSTS.iter().enumerate() {
        next(T0 + i as u64 * 500_000, host, 1, &mut p);
    }
    for i in 0..100u64 {
        next(
            T0 + 20_000_000 + i * 3_000_000,
            "settings-win.data.microsoft.com",
            1,
            &mut p,
        );
    }
    for i in 0..100u64 {
        let ptr = format!("{}.1.168.192.in-addr.arpa", i + 1);
        next(T0 + 30_000_000 + i * 1_000_000, &ptr, 12, &mut p);
    }
    p
}

/// Instantes (µs) de un beacon de periodo `period_secs` con jitter uniforme
/// ±`jitter_pct`% sobre cada intervalo (como el `jitter` de Cobalt Strike):
/// `n` intervalos, `n + 1` instantes.
pub fn jittered_times(seed: u64, period_secs: u64, jitter_pct: u64, n: usize) -> Vec<u64> {
    let mut rng = FuzzRng::new(seed);
    let period = period_secs * 1_000_000;
    let span = 2 * period * jitter_pct / 100; // amplitud total del jitter
    let mut t = T0;
    let mut out = vec![t];
    for _ in 0..n {
        // Uniforme en [period - J, period + J].
        let off = rng.next_u64() % (span + 1);
        t += period - span / 2 + off;
        out.push(t);
    }
    out
}

/// Conexión TCP corta (handshake, petición, cierre) de [`HOST_C`] a
/// `dst:443` desde `sport`, que empieza en `t`.
fn short_session(t: u64, dst: Ipv4Addr, sport: u16) -> Vec<(u64, Vec<u8>)> {
    let req = b"\x17\x03\x03\x00\x20checkin-checkin-checkin-checkin!";
    vec![
        (
            t,
            frame_tcp(
                MAC_HOST_C,
                MAC_ROUTER,
                HOST_C,
                dst,
                sport,
                443,
                1,
                0,
                flags::SYN,
                &[],
            ),
        ),
        (
            t + 20_000,
            frame_tcp(
                MAC_ROUTER,
                MAC_HOST_C,
                dst,
                HOST_C,
                443,
                sport,
                900,
                2,
                flags::SYN_ACK,
                &[],
            ),
        ),
        (
            t + 40_000,
            frame_tcp(
                MAC_HOST_C,
                MAC_ROUTER,
                HOST_C,
                dst,
                sport,
                443,
                2,
                901,
                flags::PSH_ACK,
                req,
            ),
        ),
        (
            t + 80_000,
            frame_tcp(
                MAC_HOST_C,
                MAC_ROUTER,
                HOST_C,
                dst,
                sport,
                443,
                2 + req.len() as u32,
                901,
                flags::FIN_ACK,
                &[],
            ),
        ),
    ]
}

/// Beacon entre conexiones con jitter: [`HOST_C`] abre una conexión TLS
/// corta a [`C2`]:443 cada 60 s ± 40% (uniforme), 21 conexiones = 20
/// intervalos. Con timeout de inactividad < 36 s cada llamada es un flujo.
pub fn jittered_beacon_packets(seed: u64) -> Vec<(u64, Vec<u8>)> {
    jittered_times(seed, 60, 40, 20)
        .into_iter()
        .enumerate()
        .flat_map(|(i, t)| short_session(t, C2, 41_000 + i as u16))
        .collect()
}

/// Beacon UDP dentro de un único flujo con jitter: [`HOST_C`] → [`C2`]:8443
/// cada 60 s ± 40%, 21 datagramas = 20 intervalos.
pub fn jittered_udp_beacon_packets(seed: u64) -> Vec<(u64, Vec<u8>)> {
    let payload: Vec<u8> = (0..48u8).collect();
    jittered_times(seed, 60, 40, 20)
        .into_iter()
        .map(|t| {
            (
                t,
                frame_udp(MAC_HOST_C, MAC_ROUTER, HOST_C, C2, 53_200, 8443, &payload),
            )
        })
        .collect()
}

/// Separaciones (s) entre conexiones de una persona: cola pesada tipo
/// log-normal (muchas cortas, algunas muy largas).
pub const INTERACTIVE_GAPS_SECS: [u64; 20] = [
    3, 45, 8, 120, 15, 600, 30, 5, 240, 12, 900, 20, 60, 7, 1500, 40, 10, 300, 25, 90,
];

/// Conexiones interactivas de [`HOST_C`] a [`WEB`]:443 separadas por
/// [`INTERACTIVE_GAPS_SECS`]: el mismo servicio una y otra vez, pero sin
/// ritmo. No debe alertar beaconing (ni estricto ni con jitter).
pub fn interactive_sessions_packets() -> Vec<(u64, Vec<u8>)> {
    let mut t = T0;
    let mut p = short_session(t, WEB, 42_000);
    for (i, gap) in INTERACTIVE_GAPS_SECS.iter().enumerate() {
        t += gap * 1_000_000;
        p.extend(short_session(t, WEB, 42_001 + i as u16));
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_determinista_y_dentro_de_banda() {
        let a = jittered_times(7, 60, 40, 20);
        assert_eq!(a, jittered_times(7, 60, 40, 20));
        assert_eq!(a.len(), 21);
        for w in a.windows(2) {
            let d = w[1] - w[0];
            assert!((36_000_000..=84_000_000).contains(&d), "{d}");
        }
    }

    #[test]
    fn escenarios_con_tramas_validas() {
        assert_eq!(dns_low_entropy_tunnel_packets().len(), 200);
        assert_eq!(dns_benign_packets().len(), 230);
        assert_eq!(jittered_beacon_packets(1).len(), 21 * 4);
        assert_eq!(interactive_sessions_packets().len(), 21 * 4);
        assert!(jittered_udp_beacon_packets(1)
            .iter()
            .all(|(_, d)| d.len() >= 42));
    }
}
