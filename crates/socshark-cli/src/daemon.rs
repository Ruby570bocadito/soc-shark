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
//!   señal para barrer expiraciones. Solo un `Err`, los límites
//!   `--duration`/`--max-packets` o Ctrl-C/SIGTERM cierran la sesión, y
//!   siempre de forma ordenada: los flujos vivos se exportan antes de salir.
//! - **Contexto SOC persistente**: la DNS pasiva y el resto de contexto se
//!   acumulan durante toda la sesión, como en el análisis de archivo.
//! - Los timestamps de los paquetes son de reloj de pared (epoch µs), así
//!   que `drain_expired` se alimenta con `SystemTime::now()` del mismo
//!   universo temporal.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// Parada pedida por señal. El manejador solo marca la bandera (operación
/// async-signal-safe); el bucle la consulta en cada tick, que llega como
/// mucho cada timeout de lectura porque la señal interrumpe el `poll`.
static STOP: AtomicBool = AtomicBool::new(false);

/// Instala el manejador de SIGINT (Ctrl-C) y SIGTERM. El primero que llega
/// restaura la acción por defecto, así que un segundo Ctrl-C mata el
/// proceso sin esperar al cierre ordenado.
#[cfg(unix)]
fn install_stop_handler() {
    use std::ffi::c_int;

    const SIGINT: c_int = 2;
    const SIGTERM: c_int = 15;

    extern "C" {
        /// `handler = None` es `SIG_DFL` (puntero nulo).
        fn signal(signum: c_int, handler: Option<extern "C" fn(c_int)>) -> usize;
    }

    extern "C" fn on_stop(sig: c_int) {
        STOP.store(true, Ordering::SeqCst);
        unsafe { signal(sig, None) };
    }

    unsafe {
        signal(SIGINT, Some(on_stop));
        signal(SIGTERM, Some(on_stop));
    }
}

/// Interruptor de la lectura en curso. En Windows no hay señal que corte la
/// espera de Npcap, así que el manejador de consola (que corre en su propio
/// hilo) la despierta con `pcap_breakloop`.
#[cfg(windows)]
static BREAKER: std::sync::OnceLock<socshark_capture::LiveBreaker> = std::sync::OnceLock::new();

/// Windows: Ctrl-C y el cierre de la consola llegan como eventos de
/// consola. El primero marca la parada (se atiende: el proceso sigue y cierra
/// ordenado); si ya estaba marcada, se deja al manejador por defecto, que
/// termina el proceso (segundo Ctrl-C = salida forzada, como en unix).
#[cfg(windows)]
fn install_stop_handler() {
    extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }

    unsafe extern "system" fn on_ctrl(_event: u32) -> i32 {
        let first = !STOP.swap(true, Ordering::SeqCst);
        if first {
            if let Some(b) = BREAKER.get() {
                b.interrupt();
            }
        }
        i32::from(first)
    }

    unsafe {
        SetConsoleCtrlHandler(Some(on_ctrl), 1);
    }
}

/// Sin captura en vivo en el resto de plataformas.
#[cfg(not(any(unix, windows)))]
fn install_stop_handler() {}

/// Enumera interfaces capturables (`socshark daemon --list`).
pub fn list_interfaces() -> Result<()> {
    let ifaces = socshark_capture::list_ifaces().map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("Interfaces capturables (según libpcap):");
    for i in &ifaces {
        let mut facts: Vec<String> = Vec::new();
        if let Some(d) = &i.description {
            facts.push(d.clone());
        }
        if i.loopback {
            facts.push("este mismo equipo".into());
        }
        if i.wireless {
            facts.push("inalámbrica".into());
        }
        if i.connected == Some(false) {
            facts.push("sin conexión".into());
        }
        facts.extend(i.addresses.iter().take(2).map(|a| a.to_string()));
        if facts.is_empty() {
            println!("  {}", i.name);
        } else {
            println!("  {:<14} {}", i.name, facts.join(" · "));
        }
    }
    Ok(())
}

/// Bucle principal del daemon. Vuelve cuando se alcanza `--duration` /
/// `--max-packets`, al recibir Ctrl-C/SIGTERM o ante un error fatal de
/// captura; en todos los casos exporta lo acumulado antes de volver.
pub fn run_daemon(opts: &DaemonOptions) -> Result<()> {
    let cap_cfg = LiveCaptureConfig::new(opts.iface.clone()).with_bpf(opts.bpf.clone());
    let mut source = LiveCapture::open(cap_cfg).map_err(|e| anyhow::anyhow!("{e}"))?;
    let link = source.link_type();
    #[cfg(windows)]
    let _ = BREAKER.set(source.breaker());
    install_stop_handler();

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
        for w in &db.warnings {
            eprintln!("[!] {w}");
        }
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
    if let Some(p) = &opts.json {
        let inputs: Vec<&std::path::Path> = [&opts.intel_feodo, &opts.intel_tor]
            .into_iter()
            .flatten()
            .map(|p| p.as_path())
            .collect();
        crate::output::refuse_overwrite(p, &inputs)?;
    }
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
    let mut fatal: Option<String> = None;

    loop {
        if STOP.load(Ordering::SeqCst) {
            eprintln!("[*] Parada solicitada: cierre ordenado (otro Ctrl-C fuerza la salida)");
            break;
        }
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
                // Se exporta lo acumulado y después se devuelve el error:
                // el código de salida debe reflejar que la sesión falló.
                fatal = Some(e.to_string());
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
    match fatal {
        Some(e) => Err(anyhow::anyhow!("la captura en vivo falló: {e}")),
        None => Ok(()),
    }
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
                eprintln!("{}", alert_line(f, a));
            }
        }
    }
    // Cada lote llega al disco al momento: con BufWriter y vaciado solo al
    // salir, un `tail -f` no veía nada y un corte perdía la sesión.
    if let Some(w) = writer {
        w.flush().context("error vaciando el JSONL")?;
    }
    Ok(announced)
}

/// Línea de alerta para stderr, neutralizada para el terminal (el detalle
/// lleva qnames, SNI... que controla quien genera el tráfico).
fn alert_line(f: &EnrichedFlow, a: &socshark_core::Alert) -> String {
    let line = format!(
        "[!] ALERTA riesgo {} · {} [{}] · {} · MITRE {}",
        f.risk_score,
        a.name,
        a.id,
        a.detail,
        a.mitre.as_deref().unwrap_or("-")
    );
    crate::output::sanitize_terminal(&line).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Destino que guarda lo que realmente le llega (tras el BufWriter).
    #[derive(Clone, Default)]
    struct Disco(Arc<Mutex<Vec<u8>>>);

    impl Write for Disco {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn flujo_con_alerta(detail: &str) -> EnrichedFlow {
        let mut f: EnrichedFlow = serde_json::from_str(
            r#"{
                "flow_id": "udp/10.0.0.1:5300-8.8.8.8:53",
                "state": "Idle", "transport": "Udp", "l7_protocol": "Dns",
                "src_ip": "10.0.0.1", "src_port": 5300,
                "dst_ip": "8.8.8.8", "dst_port": 53,
                "first_seen_micros": 0, "last_seen_micros": 1, "duration_micros": 1,
                "packets": 1, "bytes": 80, "packets_rev": 1, "bytes_rev": 100,
                "tcp_flags": {"syn":0,"ack":0,"fin":0,"rst":0,"psh":0,"urg":0},
                "human_summary": "", "risk_score": 80,
                "alerts": [], "extracted_files": []
            }"#,
        )
        .unwrap();
        f.alerts.push(socshark_core::Alert {
            id: "DNS-TUNNELING".into(),
            name: "Túnel DNS".into(),
            severity: socshark_core::Severity::High,
            detail: detail.into(),
            mitre: None,
        });
        f
    }

    fn opts() -> DaemonOptions {
        DaemonOptions {
            iface: "lo".into(),
            bpf: None,
            json: None,
            min_risk: 0,
            show_noise: false,
            flush_secs: 1,
            report_secs: 1,
            duration_secs: None,
            max_packets: None,
            max_flows: 10,
            idle_timeout_secs: 1,
            intel_feodo: None,
            intel_tor: None,
        }
    }

    #[test]
    fn cada_lote_llega_al_disco_sin_esperar_al_final() {
        let disco = Disco::default();
        let mut w: Box<dyn Write> = Box::new(BufWriter::new(disco.clone()));
        let n = announce(&[flujo_con_alerta("x")], &opts(), Some(&mut w)).unwrap();
        assert_eq!(n, 1);
        // Sin soltar el BufWriter: el lote ya está en el destino.
        let escrito = String::from_utf8(disco.0.lock().unwrap().clone()).unwrap();
        assert_eq!(escrito.lines().count(), 1, "{escrito}");
        assert!(escrito.contains("DNS-TUNNELING"));
    }

    #[test]
    fn alerta_neutralizada_para_el_terminal() {
        let f = flujo_con_alerta("qname evil\x1b]0;x\x07.example");
        let line = alert_line(&f, &f.alerts[0]);
        assert!(!line.contains('\x1b') && !line.contains('\x07'), "{line:?}");
        assert!(line.contains("evil\\x1b]0;x\\x07.example"));
    }
}
