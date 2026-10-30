//! Punto de entrada del binario `socshark`.

use clap::Parser;
use socshark_cli::cli::{Cli, Cmd, DevCmd, Scenario};
use socshark_cli::daemon::{self, DaemonOptions};
use socshark_cli::follow;
use socshark_cli::fuzz::{self, FuzzOptions};
use socshark_cli::gui::{self, GuiOptions};
use socshark_cli::output;
use socshark_cli::pipeline::{run_capture, run_follow};
#[cfg(feature = "tui")]
use socshark_cli::tui;
use socshark_core::config::PipelineConfig;
use std::io::Write;
use std::path::{Path, PathBuf};

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        // `socshark capture --json - | head -1`: que el lector se vaya no es
        // un error del análisis; se sale limpio, como las herramientas Unix.
        if output::is_broken_pipe(&err) {
            std::process::exit(0);
        }
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

/// Entradas de un comando (captura e intel) que ninguna salida puede pisar.
fn inputs<'a>(
    read: &'a Path,
    intel_feodo: &'a Option<PathBuf>,
    intel_tor: &'a Option<PathBuf>,
) -> Vec<&'a Path> {
    std::iter::once(read)
        .chain(intel_feodo.as_deref())
        .chain(intel_tor.as_deref())
        .collect()
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.cmd {
        Cmd::Capture {
            read,
            json,
            filter,
            show_noise,
            max_flows,
            idle_timeout,
            top,
            workers,
            carve_files,
            intel_feodo,
            intel_tor,
        } => {
            if workers == 0 {
                eprintln!("error: --workers debe ser ≥ 1");
                std::process::exit(2);
            }
            if let Some(path) = &json {
                output::refuse_overwrite(path, &inputs(&read, &intel_feodo, &intel_tor))?;
            }
            let cfg = PipelineConfig {
                max_flows,
                idle_timeout_secs: idle_timeout,
                workers,
                file_carving: carve_files,
                intel_feodo,
                intel_tor,
                ..PipelineConfig::default()
            };
            let out = run_capture(&read, filter.as_deref(), show_noise, &cfg)?;

            match &json {
                Some(path) if path.as_os_str() == "-" => {
                    // Volcado puro a stdout (para tuberías con jq, etc.).
                    output::write_jsonl_to(&mut std::io::stdout().lock(), &out.flows)?;
                }
                Some(path) => {
                    output::write_jsonl(path, &out.flows)?;
                    eprintln!("[+] JSONL escrito en {}", path.display());
                    output::print_summary(&out, top)?;
                }
                None => output::print_summary(&out, top)?,
            }
            Ok(())
        }

        Cmd::Follow {
            read,
            flow,
            hex,
            max_bytes,
        } => {
            // El reensamblado exige recolectar segmentos durante el pipeline.
            let cfg = PipelineConfig {
                collect_streams: true,
                ..PipelineConfig::default()
            };
            match run_follow(&read, &flow, &cfg)? {
                Some((flow, stream)) => follow::print_follow(&flow, &stream, hex, max_bytes)?,
                None => {
                    eprintln!("[!] ningún flujo coincide con '{flow}'");
                    eprintln!(
                        "    Pista: busca una subcadena del id, p. ej. --flow \"93.184.216.34:443\""
                    );
                    std::process::exit(2);
                }
            }
            Ok(())
        }

        Cmd::Tui { read, filter } => {
            #[cfg(feature = "tui")]
            {
                tui::run(&read, filter.as_deref())
            }
            #[cfg(not(feature = "tui"))]
            {
                let _ = (&read, &filter);
                Err(anyhow::anyhow!(
                    "la TUI no está incluida en este build: recompila con --features tui"
                ))
            }
        }

        Cmd::Daemon {
            iface,
            list,
            bpf,
            json,
            min_risk,
            show_noise,
            flush_secs,
            report_secs,
            duration,
            max_packets,
            intel_feodo,
            intel_tor,
        } => {
            if list {
                return daemon::list_interfaces();
            }
            let opts = DaemonOptions {
                iface,
                bpf,
                json,
                min_risk,
                show_noise,
                flush_secs,
                report_secs,
                duration_secs: duration,
                max_packets,
                max_flows: 50_000,
                idle_timeout_secs: 120,
                intel_feodo,
                intel_tor,
            };
            daemon::run_daemon(&opts)
        }

        Cmd::Gui {
            read,
            port,
            no_open,
            intel_feodo,
            intel_tor,
        } => gui::run(GuiOptions {
            read,
            port,
            open: !no_open,
            // La GUI talla archivos siempre: el encubrimiento (T1036) es de
            // lo primero que una persona necesita ver.
            cfg: PipelineConfig {
                file_carving: true,
                intel_feodo,
                intel_tor,
                ..PipelineConfig::default()
            },
        }),

        Cmd::Report {
            read,
            out,
            utc_offset,
            intel_feodo,
            intel_tor,
        } => {
            output::refuse_overwrite(&out, &inputs(&read, &intel_feodo, &intel_tor))?;
            let cfg = PipelineConfig {
                file_carving: true,
                intel_feodo,
                intel_tor,
                ..PipelineConfig::default()
            };
            let html = socshark_cli::report::from_file(&read, &cfg, utc_offset)?;
            std::fs::write(&out, html)
                .map_err(|e| anyhow::anyhow!("no se pudo escribir {}: {e}", out.display()))?;
            eprintln!(
                "[+] Informe escrito en {} (ábrelo con el navegador)",
                out.display()
            );
            Ok(())
        }

        Cmd::Export {
            read,
            format,
            out,
            filter,
            show_noise,
            carve_files,
            intel_feodo,
            intel_tor,
        } => {
            let fmt = format.to_ascii_lowercase();
            if !matches!(fmt.as_str(), "ecs" | "wazuh") {
                eprintln!("error: --format debe ser 'ecs' o 'wazuh' (recibido: '{format}')");
                std::process::exit(2);
            }
            if let Some(p) = &out {
                output::refuse_overwrite(p, &inputs(&read, &intel_feodo, &intel_tor))?;
            }
            let cfg = PipelineConfig {
                file_carving: carve_files,
                intel_feodo,
                intel_tor,
                ..PipelineConfig::default()
            };
            let out_data = run_capture(&read, filter.as_deref(), show_noise, &cfg)?;
            let mut sink: Box<dyn Write> = match &out {
                Some(p) if p.as_os_str() == "-" => Box::new(std::io::stdout().lock()),
                Some(p) => Box::new(std::io::BufWriter::new(std::fs::File::create(p)?)),
                None => Box::new(std::io::stdout().lock()),
            };
            for flow in &out_data.flows {
                let line = match fmt.as_str() {
                    "wazuh" => socshark_soc::siem::to_wazuh(flow).to_string(),
                    _ => socshark_soc::siem::to_ecs(flow).to_string(),
                };
                writeln!(sink, "{line}")?;
            }
            // Un fallo al vaciar (disco lleno, tubería rota) es un fallo de
            // la exportación: se propaga en vez de salir con 0.
            sink.flush()?;
            eprintln!(
                "[+] {} flujos exportados en formato {fmt} a {}",
                out_data.flows.len(),
                out.as_ref()
                    .map_or_else(|| "stdout".to_string(), |p| p.display().to_string())
            );
            Ok(())
        }

        Cmd::Dev { cmd } => match cmd {
            DevCmd::SamplePcap { out, escenario } => {
                let (packets, label) = match escenario {
                    Scenario::Demo => (socshark_testgen::sample_pcap_packets(), "demo"),
                    Scenario::Casa => (socshark_testgen::home_pcap_packets(), "casa"),
                };
                socshark_testgen::write_pcap(&out, 1, &packets)?;
                eprintln!(
                    "[+] Escenario {label} ({} paquetes) escrito en {}",
                    packets.len(),
                    out.display()
                );
                eprintln!("    Prueba: socshark capture -r {}", out.display());
                Ok(())
            }
            DevCmd::Fuzz {
                iterations,
                seed,
                report_every,
            } => {
                eprintln!("[*] Fuzzing determinista: {iterations} iteraciones, semilla {seed:#x}");
                let stats = fuzz::run_fuzz(&FuzzOptions {
                    iterations,
                    seed,
                    report_every,
                })?;
                eprintln!(
                    "[+] Fuzz OK: {} tramas · {} diseccionadas · {} exportadas · {} evaluaciones DSL",
                    stats.frames, stats.parsed, stats.exported, stats.dsl_evals
                );
                Ok(())
            }
        },
    }
}
