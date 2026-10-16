//! Daemon de captura en vivo (Fase 2): `socshark daemon -i <iface>`.
//!
//! Flujo: libpcap (dlopen, ADR-009) entrega paquetes → disección secuencial
//! → agregador con expiración incremental (`drain_expired`) → enriquecimiento
//! SOC del contexto persistente → JSONL incremental (`--json`) + alertas por
//! stderr según riesgo mínimo.
//!
//! Decisiones de diseño:
//! - **Disección secuencial en vivo** aunque el pool exista: en vivo el
//!   cuello de botela suele ser la interfaz, y los lotes del pool (256
//!   paquetes) añadirían latencia de alerta. El paralelismo queda para el
//!   análisis de archivos, donde el throughput manda.
//! - **Los ticks de timeout no terminan nada**: [`CaptureSource`] devuelve
//!   `Ok(None)` cuando vence el timeout de lectura sin tráfico; aquí es la
//!   señal para barrer expiraciones. Solo un `Err` (o los límites
//!   `--duration`/`--max-packets`) cierra la sesión.
//! - **Contexto SOC persistente**: la DNS pasiva y el resto de contexto se
//!   acumulan durante toda la sesión, como en el análisis de archivo.
//! - Los timestamps de los paquetes son de reloj de pared (epoch µs), así
//!   que `drain_expired` se alimenta con `SystemTime::now()` del mismo
//!   universo temporal.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use socshark_capture::{CaptureSource, LiveCapture, LiveCaptureConfig};
use socshark_core::config::PipelineConfig;
use socshark_core::EnrichedFlow;
use socshark_dissectors::DissectorPipeline;
use socshark_flow::FlowAggregator;
use socshark_soc::{enrich_all, SocContext};

/// Opciones del daemon ya normalizadas desde la CLI.
#[derive(Debug, Clone)]
pub struct DaemonOptions {
    pub iface: String,
    pub bpf: Option<String>,
    pub json: Option<PathBuf>,
    pub min_risk: u32,
    pub show_noise: bool,
    pub flush_secs: u64,
    pub report_secs: u64,
    pub duration_secs: Option<u64>,
    pub max_packets: Option<u64>,
    pub max_flows: usize,
    pub idle_timeout_secs: u64,
    /// Listas de threat intel offline (Fase 4): se cargan al arrancar y
    /// alimentan las reglas R7 en cada ciclo de expiración.
    pub intel_feodo: Option<PathBuf>,
    pub intel_tor: Option<PathBuf>,
}

/// Reloj de pared en microsegundos (mismo universo que los timestamps pcap).
fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Enumera interfaces capturables (`socshark daemon --list`).
pub fn list_interfaces() -> Result<()> {
    let ifaces = socshark_capture::list_ifaces().map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("Interfaces capturables (según libpcap):");
    for i in &ifaces {
        match &i.description {
            Some(d) => println!("  {:<14} {d}", i.name),
            None => println!("  {}", i.name),
        }
    }
    Ok(())
}

/// Bucle principal del daemon. Vuelve cuando se alcanza `--duration` /
/// `--max-packets` o ante un error fatal de captura (agotando lo
/// acumulado); Ctrl-C termina el proceso (el kernel limpia el handle).
pub fn run_daemon(opts: &DaemonOptions) -> Result<()> {
    let cap_cfg = LiveCaptureConfig::new(opts.iface.clone()).with_bpf(opts.bpf.clone());
    let mut source = LiveCapture::open(cap_cfg).map_err(|e| anyhow::anyhow!("{e}"))?;
    let link = source.link_type();

    eprintln!("[*] Daemon en vivo: {} (enlace {link:?})", opts.iface);
    if let Some(bpf) = &opts.bpf {
        eprintln!("[*] Filtro BPF pushdown al kernel: {bpf}");
    }
    eprintln!(
        "[*] Cadencia: expiración cada {}s · estado cada {}s · timeout de flujo {}s",
        opts.flush_secs.max(1),
        opts.report_secs.max(1),
        opts.idle_timeout_secs
    );

    let mut aggregator = FlowAggregator::new(opts.max_flows, opts.idle_timeout_secs, false);
    let dissectors = DissectorPipeline::new();
    let mut ctx = SocContext::default();
    let pcfg = PipelineConfig {
        max_flows: opts.max_flows,
        idle_timeout_secs: opts.idle_timeout_secs,
        intel_feodo: opts.intel_feodo.clone(),
        intel_tor: opts.intel_tor.clone(),
        ..PipelineConfig::default()
    };

    // Threat intel offline (Fase 4): se carga una vez al arrancar; un
    // fichero ilegible aborta la sesión antes de perder tiempo capturando.
    if opts.intel_feodo.is_some() || opts.intel_tor.is_some() {
        let db = socshark_soc::ThreatIntelDb::from_paths(
            opts.intel_feodo.as_deref(),
            opts.intel_tor.as_deref(),
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "no se pudo cargar la lista de threat intel: {e} (revisa --intel-feodo / --intel-tor)"
            )
        })?;
        eprintln!(
            "[*] Threat intel offline: {} entradas (Feodo: {} · Tor: {})",
            db.len(),
            db.feodo_entries,
            db.tor_entries
        );
        ctx.intel = Some(db);
    }

    // El JSONL incremental escribe al vuelo; stdout sin búfer intermedio
    // para que `| jq` responda en tiempo real.
    let mut writer: Option<Box<dyn Write>> = match &opts.json {
        Some(p) if p.as_os_str() == "-" => Some(Box::new(io::stdout().lock())),
        Some(p) => Some(Box::new(BufWriter::new(
            File::create(p).with_context(|| format!("no se pudo crear {}", p.display()))?,
        ))),
        None => None,
    };

    let start = Instant::now();
    let mut last_flush = Instant::now();
    let mut last_report = Instant::now();
    let mut packets: u64 = 0;
    let mut alerts: u64 = 0;

    loop {
        if let Some(d) = opts.duration_secs {
            if start.elapsed() >= Duration::from_secs(d) {
                eprintln!("[*] Límite de duración alcanzado ({}s)", d);
                break;
            }
        }
        if let Some(m) = opts.max_packets {
            if packets >= m {
                eprintln!("[*] Límite de paquetes alcanzado ({m})");
                break;
            }
        }

        match source.next_packet() {
            Ok(Some(pkt)) => {
                packets += 1;
                if let Some(dp) = dissectors.dissect(&pkt, link) {
                    aggregator.on_packet(pkt.ts_micros, pkt.data.len(), &dp);
                }
            }
            Ok(None) => {} // tick: se atiende más abajo en la cadencia
            Err(e) => {
                eprintln!("[!] Error de captura: {e}");
                eprintln!("    Termino con lo acumulado hasta ahora.");
                break;
            }
        }

        if last_flush.elapsed() >= Duration::from_secs(opts.flush_secs.max(1)) {
            last_flush = Instant::now();
            let mut expired = aggregator.drain_expired(now_micros());
            if !expired.is_empty() {
                enrich_all(&mut ctx, &mut expired, &pcfg);
                alerts += announce(&expired, opts, writer.as_mut())?;
            }
        }

        if last_report.elapsed() >= Duration::from_secs(opts.report_secs.max(1)) {
            last_report = Instant::now();
            let (recv, drop) = source.kernel_stats().unwrap_or((0, 0));
            eprintln!(
                "[*] {:.0}s · {packets} paq (kernel: {recv} recv / {drop} drop) · {} flujos creados · {alerts} alertas",
                start.elapsed().as_secs_f32(),
                aggregator.stats().flows_created,
            );
        }
    }

    // Cierre ordenado: `finish` expira todo lo vivo y lo ordena por
    // primer avistamiento.
    let mut remaining = aggregator.finish();
    enrich_all(&mut ctx, &mut remaining, &pcfg);
    alerts += announce(&remaining, opts, writer.as_mut())?;
    if let Some(w) = writer.as_mut() {
        w.flush().context("error vaciando el JSONL")?;
    }

    eprintln!(
        "[+] Daemon terminado: {packets} paquetes · {} flujos exportados · {alerts} alertas",
        remaining.len()
    );
    Ok(())
}

/// Escribe los flujos al JSONL (si hay destino) y anuncia por stderr los
/// flujos con alertas según `min_risk`/`show_noise`. Devuelve el número de
/// flujos anunciados.
fn announce(
    flows: &[EnrichedFlow],
    opts: &DaemonOptions,
    mut writer: Option<&mut Box<dyn Write>>,
) -> Result<u64> {
    let mut announced = 0u64;
    for f in flows {
        if let Some(w) = writer.as_deref_mut() {
            let line = serde_json::to_string(f).context("error serializando flujo")?;
            writeln!(w, "{line}").context("error escribiendo JSONL")?;
        }
        if (opts.show_noise || !f.is_background_noise)
            && u32::from(f.risk_score) >= opts.min_risk
            && !f.alerts.is_empty()
        {
            announced += 1;
            for a in &f.alerts {
                eprintln!(
                    "[!] ALERTA riesgo {} · {} [{}] · {} · MITRE {}",
                    f.risk_score,
                    a.name,
                    a.id,
                    a.detail,
                    a.mitre.as_deref().unwrap_or("-")
                );
            }
        }
    }
    Ok(announced)
}
