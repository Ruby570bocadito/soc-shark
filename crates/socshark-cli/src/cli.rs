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
  socshark capture -r demo.pcap -f \"ip.version == 6\" --workers 4
  socshark follow -r demo.pcap --flow \"93.184.216.34:443\"
  socshark tui -r demo.pcap
  socshark gui -r demo.pcap                              <- interfaz gráfica
  socshark capture -r demo.pcap --carve-files            <- file carving (T1036)
  socshark capture -r demo.pcap --intel-feodo feodo.txt
  socshark export -r demo.pcap --format ecs -o ecs.jsonl
  socshark export -r demo.pcap --format wazuh -o wazuh.jsonl
  socshark daemon --list
  socshark daemon -i eth0 --bpf \"tcp port 443\" --json flujos.jsonl
  socshark dev fuzz --seed 42 --iterations 20000

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
        /// Hilos de disección (> 1 activa el pool concurrente; la salida es
        /// idéntica al modo secuencial).
        #[arg(long, default_value_t = 1)]
        workers: usize,
        /// File carving HTTP: extrae archivos de las respuestas y detecta
        /// encubrimiento T1036 (magic ≠ extensión). Requiere recolectar
        /// streams (hasta 1 MiB por dirección de cada flujo TCP).
        #[arg(long = "carve-files")]
        carve_files: bool,
        /// Lista de IPs/CIDR de C2 tipo Feodo (threat intel offline).
        #[arg(long = "intel-feodo")]
        intel_feodo: Option<PathBuf>,
        /// Lista de nodos de salida de Tor (threat intel offline).
        #[arg(long = "intel-tor")]
        intel_tor: Option<PathBuf>,
    },
    /// Informe de la red en lenguaje claro (un HTML para guardar, imprimir
    /// o compartir): qué pasó, qué hacer, equipos y sitios de Internet.
    Report {
        /// Captura de entrada (pcap o pcapng).
        #[arg(short = 'r', long = "read")]
        read: PathBuf,
        /// Archivo HTML de salida.
        #[arg(short, long, default_value = "informe.html")]
        out: PathBuf,
        /// Minutos de diferencia con UTC para las horas (España: 60 en
        /// invierno, 120 en verano).
        #[arg(long = "utc-offset", default_value_t = 0, allow_hyphen_values = true)]
        utc_offset: i32,
        /// Lista de IPs/CIDR de C2 tipo Feodo (threat intel offline).
        #[arg(long = "intel-feodo")]
        intel_feodo: Option<PathBuf>,
        /// Lista de nodos de salida de Tor (threat intel offline).
        #[arg(long = "intel-tor")]
        intel_tor: Option<PathBuf>,
    },
    /// Captura en vivo desde una interfaz (libpcap vía dlopen).
    Daemon {
        /// Interfaz de red a monitorizar.
        #[arg(short, long, default_value = "eth0")]
        iface: String,
        /// Enumera las interfaces capturables y sale.
        #[arg(long)]
        list: bool,
        /// Filtro BPF con pushdown al kernel (sintaxis pcap).
        #[arg(long)]
        bpf: Option<String>,
        /// Escribe los flujos expirados como JSONL incremental (`-` = stdout).
        #[arg(long)]
        json: Option<PathBuf>,
        /// Riesgo mínimo (0-100) para anunciar alertas por stderr.
        #[arg(long, default_value_t = 30)]
        min_risk: u32,
        /// Anuncia también flujos clasificados como ruido de fondo.
        #[arg(long = "show-noise")]
        show_noise: bool,
        /// Segundos entre barridos de expiración de flujos.
        #[arg(long, default_value_t = 5)]
        flush_secs: u64,
        /// Segundos entre líneas de estado por stderr.
        #[arg(long, default_value_t = 30)]
        report_secs: u64,
        /// Detiene el daemon tras N segundos (útil para pruebas y demo).
        #[arg(long)]
        duration: Option<u64>,
        /// Detiene el daemon tras N paquetes capturados.
        #[arg(long)]
        max_packets: Option<u64>,
        /// Lista de IPs/CIDR de C2 tipo Feodo (threat intel offline).
        #[arg(long = "intel-feodo")]
        intel_feodo: Option<PathBuf>,
        /// Lista de nodos de salida de Tor (threat intel offline).
        #[arg(long = "intel-tor")]
        intel_tor: Option<PathBuf>,
    },
    /// Sigue el stream TCP de un flujo reensamblándolo (Fase 2).
    Follow {
        /// Archivo pcap de entrada.
        #[arg(short = 'r', long = "read")]
        read: PathBuf,
        /// Selector del flujo: id completo o subcadena (p. ej. "93.184.216.34:443").
        #[arg(short, long)]
        flow: String,
        /// Muestra el contenido como hexdump en lugar de texto.
        #[arg(long)]
        hex: bool,
        /// Máximo de bytes a mostrar por dirección.
        #[arg(long, default_value_t = 8 * 1024)]
        max_bytes: usize,
    },
    /// TUI (Fase 2): explorador Flow-First de los flujos de una captura.
    Tui {
        /// Archivo pcap de entrada.
        #[arg(short = 'r', long = "read")]
        read: PathBuf,
        /// Filtro DSL inicial aplicado al arrancar.
        #[arg(short = 'f', long = "filter")]
        filter: Option<String>,
    },
    /// Interfaz gráfica: abre una ventana para explorar la captura con
    /// explicaciones en lenguaje claro (también abre archivos desde ella).
    Gui {
        /// Captura a abrir al arrancar (opcional: se puede abrir desde la ventana).
        #[arg(short = 'r', long = "read")]
        read: Option<PathBuf>,
        /// Puerto local (por defecto 8787 o, si está ocupado, uno libre).
        #[arg(long)]
        port: Option<u16>,
        /// No abrir la ventana: solo mostrar la dirección.
        #[arg(long = "no-open")]
        no_open: bool,
        /// Lista de IPs/CIDR de C2 tipo Feodo (threat intel offline).
        #[arg(long = "intel-feodo")]
        intel_feodo: Option<PathBuf>,
        /// Lista de nodos de salida de Tor (threat intel offline).
        #[arg(long = "intel-tor")]
        intel_tor: Option<PathBuf>,
    },
    /// Exporta los flujos enriquecidos a un SIEM (Fase 4).
    Export {
        /// Archivo pcap de entrada.
        #[arg(short = 'r', long = "read")]
        read: PathBuf,
        /// Formato de salida: `ecs` (Elastic Common Schema) o `wazuh`.
        #[arg(short = 'F', long = "format", default_value = "ecs")]
        format: String,
        /// Archivo de salida JSONL (`-` = stdout, por defecto).
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Filtra los flujos con el DSL antes de exportar.
        #[arg(short = 'f', long = "filter")]
        filter: Option<String>,
        /// Incluye el ruido de fondo (NTP, mDNS, ...).
        #[arg(long = "show-noise")]
        show_noise: bool,
        /// File carving HTTP antes de exportar (añade los archivos tallados).
        #[arg(long = "carve-files")]
        carve_files: bool,
        /// Lista de IPs/CIDR de C2 tipo Feodo (threat intel offline).
        #[arg(long = "intel-feodo")]
        intel_feodo: Option<PathBuf>,
        /// Lista de nodos de salida de Tor (threat intel offline).
        #[arg(long = "intel-tor")]
        intel_tor: Option<PathBuf>,
    },
    /// Utilidades de desarrollo.
    Dev {
        #[command(subcommand)]
        cmd: DevCmd,
    },
}

/// Escenarios de `socshark dev sample-pcap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Scenario {
    /// Eventos SOC: túnel DNS, escaneo, archivo disfrazado, beacon…
    Demo,
    /// Red de casa: móvil, PC con Windows, impresora, Chromecast y router.
    Casa,
}

/// Subcomandos de desarrollo.
#[derive(Debug, Subcommand)]
pub enum DevCmd {
    /// Genera un pcap de demostración con tráfico y eventos SOC.
    SamplePcap {
        /// Ruta de salida del pcap.
        #[arg(short, long, default_value = "demo.pcap")]
        out: PathBuf,
        /// Qué escenario: `demo` (eventos SOC) o `casa` (una red doméstica
        /// cuyos equipos se presentan solos: quién es quién).
        #[arg(long, value_enum, default_value_t = Scenario::Demo)]
        escenario: Scenario,
    },
    /// Fuzzing determinista en proceso (parsers + agregador + SOC + DSL).
    Fuzz {
        /// Número de iteraciones (cada una procesa un lote mutado).
        #[arg(long, default_value_t = 10_000)]
        iterations: usize,
        /// Semilla del generador: la misma semilla reproduce el mismo corpus.
        #[arg(long, default_value_t = 0xFACADE)]
        seed: u64,
        /// Iteraciones entre informes de progreso por stderr.
        #[arg(long, default_value_t = 2_000)]
        report_every: usize,
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
