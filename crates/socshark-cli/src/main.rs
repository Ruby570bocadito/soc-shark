//! Punto de entrada del binario `socshark`.

use clap::Parser;
use socshark_cli::cli::{Cli, Cmd, DevCmd};
use socshark_cli::output;
use socshark_cli::pipeline::run_capture;
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
        } => {
            let cfg = PipelineConfig {
                max_flows,
                idle_timeout_secs: idle_timeout,
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

        Cmd::Daemon { iface } => {
            // Stub de la Fase 2: documenta el plan y no hace nada más.
            eprintln!("[!] La captura en vivo ({iface}) llega en la Fase 2.");
            eprintln!(
                "    Plan: daemon con CAP_NET_RAW (libpcap → AF_XDP) + módulos eBPF en Fase 3."
            );
            eprintln!("    Ver docs/roadmap.md y docs/ebpf-design.md.");
            eprintln!("    Por ahora: socshark capture -r archivo.pcap");
            Ok(())
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
        },
    }
}
