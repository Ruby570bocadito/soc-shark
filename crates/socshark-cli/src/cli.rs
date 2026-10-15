//! Definición de la interfaz de línea de comandos (clap derive).

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// CLI de soc-shark.
#[derive(Debug, Parser)]
#[command(
    name = "socshark",
    version,
    about = "soc-shark · analizador de tráfico de red pensado para el SOC",
    after_help = "Ejemplos:
  socshark dev sample-pcap -o demo.pcap
  socshark capture -r demo.pcap
  socshark capture -r demo.pcap --json flujos.jsonl
  socshark capture -r demo.pcap -f \"flow.risk >= 30\"
  socshark capture -r demo.pcap -f \"dns.qname contains evil\" --show-noise

Documentación completa: docs/index.md"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// Subcomandos de la CLI.
#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Procesa una captura pcap y muestra flujos enriquecidos.
    Capture {
        /// Archivo pcap de entrada (formato clásico, micro o nanosegundos).
        #[arg(short = 'r', long = "read")]
        read: PathBuf,
        /// Escribe los flujos como JSONL en la ruta indicada (`-` = stdout).
        #[arg(long)]
        json: Option<PathBuf>,
        /// Filtra los flujos con el DSL (p. ej. "tcp.port == 443").
        #[arg(short = 'f', long = "filter")]
        filter: Option<String>,
        /// Incluye el ruido de fondo (NTP, mDNS, ...).
        #[arg(long = "show-noise")]
        show_noise: bool,
        /// Máximo de flujos en memoria.
        #[arg(long, default_value_t = 50_000)]
        max_flows: usize,
        /// Segundos de inactividad antes de expirar un flujo (streaming).
        #[arg(long, default_value_t = 120)]
        idle_timeout: u64,
        /// Flujos a mostrar en la tabla resumen.
        #[arg(long, default_value_t = 20)]
        top: usize,
    },
    /// Captura en vivo desde una interfaz (Fase 2; hoy imprime el plan).
    Daemon {
        /// Interfaz de red a monitorizar.
        #[arg(short, long, default_value = "eth0")]
        iface: String,
    },
    /// Utilidades de desarrollo.
    Dev {
        #[command(subcommand)]
        cmd: DevCmd,
    },
}

/// Subcomandos de desarrollo.
#[derive(Debug, Subcommand)]
pub enum DevCmd {
    /// Genera un pcap de demostración con tráfico y eventos SOC.
    SamplePcap {
        /// Ruta de salida del pcap.
        #[arg(short, long, default_value = "demo.pcap")]
        out: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn la_cli_valida() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parsea_subcomando_capture_con_filtro() {
        let cli = Cli::try_parse_from([
            "socshark",
            "capture",
            "-r",
            "demo.pcap",
            "-f",
            "tcp.port == 443",
            "--show-noise",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::Capture {
                read,
                filter,
                show_noise,
                ..
            } => {
                assert_eq!(read, PathBuf::from("demo.pcap"));
                assert_eq!(filter.as_deref(), Some("tcp.port == 443"));
                assert!(show_noise);
            }
            other => panic!("subcomando inesperado: {other:?}"),
        }
    }
}
