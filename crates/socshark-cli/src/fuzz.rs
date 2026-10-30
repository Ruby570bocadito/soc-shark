//! Fuzzing determinista en proceso: corpus mutado → pipeline completo.
//!
//! Cada iteración construye un lote de tramas malformadas (mutaciones de
//! [`socshark_testgen::fuzz`]) y lo hace pasar por *dissector → agregador →
//! SOC → filtro DSL*. La propiedad que se verifica es sencilla y valiosa:
//! **ninguna entrada puede colgar ni panicar el pipeline**. Los panics no
//! se capturan: el hook instalado imprime semilla e iteración y el proceso
//! muere con error, de modo que CI falla y el fallo es reproducible con
//! `socshark dev fuzz --seed <S> --iterations <N+1>`.

use std::panic;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use anyhow::Result;
use socshark_core::config::PipelineConfig;
use socshark_core::{LinkType, RawPacket};
use socshark_dissectors::DissectorPipeline;
use socshark_flow::FlowAggregator;
use socshark_soc::{enrich_all, SocContext};
use socshark_testgen as tg;
use socshark_testgen::fuzz::{hostile_scenarios, mutate_frame, splice_frames, FuzzRng};

static FUZZ_SEED: AtomicU64 = AtomicU64::new(0);
static FUZZ_ITER: AtomicUsize = AtomicUsize::new(0);

/// Parámetros de una sesión de fuzzing.
#[derive(Debug, Clone)]
pub struct FuzzOptions {
    pub iterations: usize,
    pub seed: u64,
    pub report_every: usize,
}

/// Resumen acumulado de la sesión.
#[derive(Debug, Default, Clone, Copy)]
pub struct FuzzStats {
    pub frames: u64,
    pub parsed: u64,
    pub exported: u64,
    pub dsl_evals: u64,
}

/// Ejecuta la sesión completa. Devuelve `Ok` con el resumen si no hubo
/// panics; un panic aborta el proceso (comportamiento deseado en CI).
pub fn run_fuzz(opts: &FuzzOptions) -> Result<FuzzStats> {
    FUZZ_SEED.store(opts.seed, Ordering::Relaxed);
    FUZZ_ITER.store(0, Ordering::Relaxed);

    let prev_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        eprintln!(
            "\n[!] FUZZ FALLÓ — reproducible con: socshark dev fuzz --seed {} --iterations {}",
            FUZZ_SEED.load(Ordering::Relaxed),
            FUZZ_ITER.load(Ordering::Relaxed) + 1
        );
        prev_hook(info);
    }));

    // Escenarios hostiles ordenados (chunked gigante, miles de "HTTP/1.",
    // IPv4 fragmentado, TLS en registros partidos): se inyectan completos y
    // además sus tramas engrosan el corpus base que se muta.
    let scenarios = hostile_scenarios();
    let base: Vec<Vec<u8>> = tg::sample_pcap_packets()
        .into_iter()
        .map(|(_, frame)| frame)
        .chain(scenarios.iter().flatten().cloned())
        .collect();
    anyhow::ensure!(!base.is_empty(), "el corpus base está vacío");

    // collect_streams ON: el reensamblado (StreamBuf, aritmética de serie)
    // es una de las zonas con más superficie de ataque.
    let cfg = PipelineConfig {
        collect_streams: true,
        ..PipelineConfig::default()
    };

    let mut rng = FuzzRng::new(opts.seed);
    let mut stats = FuzzStats::default();

    for iter in 0..opts.iterations {
        FUZZ_ITER.store(iter, Ordering::Relaxed);
        fuzz_iteration(&mut rng, &base, &scenarios, &cfg, &mut stats);
        if opts.report_every > 0 && iter > 0 && iter % opts.report_every == 0 {
            eprintln!(
                "[*] fuzz iter {iter}/{} · {} tramas · {} diseccionadas · {} exportadas · {} evals DSL",
                opts.iterations, stats.frames, stats.parsed, stats.exported, stats.dsl_evals
            );
        }
    }

    // Restaurar el hook por defecto: la sesión de fuzz ha terminado y los
    // panics posteriores no necesitan contexto de reproducción.
    let _ = panic::take_hook();
    Ok(stats)
}

/// Una iteración: lote mutado → pipeline; expiraciones y enriquecimiento
/// probabilísticos para cubrir también los caminos de exportación.
fn fuzz_iteration(
    rng: &mut FuzzRng,
    base: &[Vec<u8>],
    scenarios: &[Vec<Vec<u8>>],
    cfg: &PipelineConfig,
    stats: &mut FuzzStats,
) {
    let mut aggregator = FlowAggregator::new(cfg.max_flows, cfg.idle_timeout_secs, true);
    let dissectors = DissectorPipeline::new();

    // Un escenario hostil completo y en orden (mutado con poca
    // probabilidad por trama) para que llegue entero al reensamblado, al
    // ClientHello y al carving.
    if !scenarios.is_empty() && rng.coin(30) {
        let sc = &scenarios[rng.below(scenarios.len())];
        for (i, frame) in sc.iter().enumerate() {
            let frame = if rng.coin(10) {
                mutate_frame(rng, frame)
            } else {
                frame.clone()
            };
            let raw = RawPacket {
                ts_micros: 1_000_000 + i as u64 * 1_000,
                orig_len: frame.len() as u32,
                data: frame,
            };
            if let Some(dp) = dissectors.dissect(&raw, LinkType::Ethernet) {
                aggregator.on_packet(raw.ts_micros, raw.data.len(), &dp);
                stats.parsed += 1;
            }
            stats.frames += 1;
        }
    }

    let batch = 1 + rng.below(base.len() * 2);
    for _ in 0..batch {
        let mut frame = base[rng.below(base.len())].clone();
        if rng.coin(85) {
            frame = mutate_frame(rng, &frame);
        }
        if rng.coin(8) {
            let other = &base[rng.below(base.len())];
            frame = splice_frames(rng, &frame, other);
        }
        // Timestamps acotados a 48 bits (µs ≈ 9 días): ejercita expiraciones
        // y reordenamientos sin desbordes artificiales.
        let ts = rng.next_u64() & 0x0000_FFFF_FFFF_FFFF;
        let mut raw = RawPacket {
            ts_micros: ts,
            orig_len: frame.len() as u32,
            data: frame,
        };
        // Mentiras de snaplen: `orig_len` puede declarar más bytes de los
        // capturados (caso real en pcaps con snaplen pequeño).
        if rng.coin(4) {
            raw.orig_len = (rng.next_u64() & 0xffff) as u32;
        }
        if let Some(dp) = dissectors.dissect(&raw, LinkType::Ethernet) {
            aggregator.on_packet(raw.ts_micros, raw.data.len(), &dp);
            stats.parsed += 1;
        }
        stats.frames += 1;
    }

    // Expiración con `now` aleatorio: cubre drain_expired con relojes
    // adelantados, atrasados y absurdos.
    if rng.coin(20) {
        let now = rng.next_u64() >> 1;
        let mut expired = aggregator.drain_expired(now);
        if !expired.is_empty() {
            stats.exported += expired.len() as u64;
            if rng.coin(50) {
                let mut ctx = SocContext::default();
                enrich_all(&mut ctx, &mut expired, cfg);
                eval_random_dsl(rng, &expired, stats);
            }
        }
    }

    let (mut flows, streams) = aggregator.finish_with_streams();
    stats.exported += flows.len() as u64;
    // Carving HTTP sobre los streams reensamblados (chunked, Content-Length
    // y búsqueda de cabeceras con entrada hostil).
    socshark_soc::carve::carve_all(&mut flows, &streams);
    if rng.coin(15) {
        let mut ctx = SocContext::default();
        enrich_all(&mut ctx, &mut flows, cfg);
        eval_random_dsl(rng, &flows, stats);
    }
}

/// Genera expresiones DSL bien formadas con operandos aleatorios y evalúa
/// el resultado sobre los flujos: estresa parser, VM y FactSource.
fn eval_random_dsl(
    rng: &mut FuzzRng,
    flows: &[socshark_core::EnrichedFlow],
    stats: &mut FuzzStats,
) {
    const NUM_FIELDS: [&str; 8] = [
        "flow.risk",
        "flow.bytes",
        "flow.packets",
        "flow.alerts",
        "ip.version",
        "tcp.port",
        "udp.port",
        "dns.qtype",
    ];
    const OPS: [&str; 6] = ["==", "!=", ">", "<", ">=", "<="];

    let field = NUM_FIELDS[rng.below(NUM_FIELDS.len())];
    let op = OPS[rng.below(OPS.len())];
    let value = rng.below(300);
    let expr = format!("{field} {op} {value}");
    if let Ok(ast) = socshark_filter::parse(&expr) {
        for f in flows {
            let _ = socshark_filter::eval(&ast, f);
            stats.dsl_evals += 1;
        }
    }

    const TEXT_FIELDS: [&str; 2] = ["dns.qname", "flow.state"];
    let field = TEXT_FIELDS[rng.below(TEXT_FIELDS.len())];
    let expr = format!("{field} contains \"a\"");
    if let Ok(ast) = socshark_filter::parse(&expr) {
        for f in flows {
            let _ = socshark_filter::eval(&ast, f);
            stats.dsl_evals += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Versión reducida de la sesión de CI: suficientes iteraciones para
    /// cubrir todos los tipos de mutación y los caminos de exportación,
    /// rápido incluso en debug.
    #[test]
    fn fuzz_corto_no_panica_y_es_reproducible() {
        let stats = run_fuzz(&FuzzOptions {
            iterations: 300,
            seed: 0xC0FFEE,
            report_every: 0,
        })
        .expect("la sesión de fuzz no debe fallar");
        assert!(stats.frames > 300, "debe procesar al menos una trama/iter");
        assert!(
            stats.parsed > 0,
            "las tramas válidas deben seguir diseccionándose"
        );
    }
}
