//! Punto de entrada del binario `socshark`.

use clap::Parser;
use socshark_cli::cli::{Cli, Cmd, DevCmd};
use socshark_cli::daemon::{self, DaemonOptions};
use socshark_cli::follow;
use socshark_cli::fuzz::{self, FuzzOptions};
use socshark_cli::output;
use socshark_cli::pipeline::{run_capture, run_follow};
use socshark_cli::tui;
use socshark_core::config::PipelineConfig;

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
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
        } => {
            if workers == 0 {
                eprintln!("error: --workers debe ser ≥ 1");
                std::process::exit(2);
            }
            let cfg = PipelineConfig {
                max_flows,
                idle_timeout_secs: idle_timeout,
                workers,
                ..PipelineConfig::default()
            };
            let out = run_capture(&read, filter.as_deref(), show_noise, &cfg)?;

            match &json {
                Some(path) if path.as_os_str() == "-" => {
                    // Volcado puro a stdout (para tuberías con jq, etc.).
                    for flow in &out.flows {
                        println!("{}", serde_json::to_string(flow)?);
                    }
                }
                Some(path) => {
                    output::write_jsonl(path, &out.flows)?;
                    eprintln!("[+] JSONL escrito en {}", path.display());
                    output::print_summary(&out, top);
                }
                None => output::print_summary(&out, top),
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
                Some((flow, stream)) => follow::print_follow(&flow, &stream, hex, max_bytes),
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
                eprintln!(
                    "[!] La TUI no está incluida en este build: recompila con --features tui"
                );
                Ok(())
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
            };
            daemon::run_daemon(&opts)
        }

        Cmd::Dev { cmd } => match cmd {
            DevCmd::SamplePcap { out } => {
                let packets = socshark_testgen::sample_pcap_packets();
                socshark_testgen::write_pcap(&out, 1, &packets)?;
                eprintln!(
                    "[+] Escenario demo ({} paquetes) escrito en {}",
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
