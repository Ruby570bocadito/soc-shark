//! **soc-shark** — analizador de tráfico de nueva generación (fase 1: motor).
//!
//! Subcomandos:
//! - `read <captura>`: analiza un .pcap/.pcapng y muestra el informe SOC.
//! - `fields`: catálogo de campos del filter-dsl.
//! - `live <iface>`: captura en vivo (fase 2; guía de preparación).
//!
//! El daemon de la arquitectura final (gRPC sobre Unix sockets, separación
//! de privilegios CAP_NET_RAW) está diseñado en `docs/07-seguridad.md` y
//! `docs/02-arquitectura.md`; esta fase entrega el motor completo vía CLI.

use socshark_daemon::{output, pipeline};

use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    // Std-only: sin libc, gestionamos EPIPE (`soc-shark … | head`) con un
    // hook de pánico que sale limpio cuando stdout se cierra.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info.to_string().contains("Broken pipe") {
            std::process::exit(0);
        }
        default_hook(info);
    }));
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("soc-shark: error: {e}");
            eprintln!("usa `soc-shark --help` para ver la ayuda");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let Some(cmd) = args.first() else {
        print_help();
        return Ok(ExitCode::from(2));
    };
    match cmd.as_str() {
        "--help" | "-h" | "help" => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
        "--version" | "-V" | "version" => {
            println!("soc-shark {VERSION}");
            Ok(ExitCode::SUCCESS)
        }
        "read" => pipeline::cmd_read(&args[1..]),
        "fields" => {
            output::print_fields();
            Ok(ExitCode::SUCCESS)
        }
        "live" => {
            let iface = args.get(1).cloned().unwrap_or_else(|| "eth0".into());
            print_live_guidance(&iface);
            Ok(ExitCode::from(3))
        }
        "info" => {
            println!("soc-shark {VERSION}");
            println!("{}", socshark_storage_index::mmap_store::plan());
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("subcomando desconocido: {other}")),
    }
}

fn print_help() {
    println!(
        r#"soc-shark {VERSION} — analizador de tráfico SOC (fase 1: motor)

USO:
    soc-shark read <captura.pcap|pcapng> [opciones]
    soc-shark fields
    soc-shark live <iface>
    soc-shark info

OPCIONES DE read:
    --filter <expr>     Filtro flow-dsl: 'flow.risk >= 30 and not flow.noise'
    --json              Informe completo en JSON (stdout)
    --events            Líneas JSON por paquete (JSONL)
    --export-ecs <f>    Exporta los flujos a formato ECS JSONL para SIEM
    --export-suricata <f>  Regla Suricata para el flujo de mayor riesgo
    --iocs <f>          Lista local de IOCs (IPs/CIDRs)
    --min-risk <n>      Oculta flujos con riesgo < n
    --include-noise     Incluye los flujos marcados como ruido de fondo
    --limit <n>         Máximo de flujos mostrados (por defecto 40)
    --no-color          Desactiva los colores ANSI
EJEMPLOS:
    soc-shark read examples/demo_soc_incident.pcap
    soc-shark read captura.pcap --filter 'flow.risk >= 30 and not flow.noise'
    soc-shark read captura.pcapng --json --export-ecs incidente.jsonl
    soc-shark read captura.pcap --filter 'http.method == POST and tcp.dstport == 4444'"#
    );
}

fn print_live_guidance(iface: &str) {
    println!(
        r#"soc-shark: la captura en vivo llega en la fase 2 (docs/11-hoja-de-ruta.md).

Para preparar el entorno del daemon (arquitectura de privilegios separados):
    # 1. Capacidad de captura sin root:
    sudo setcap cap_net_raw,cap_bpf+eip target/release/soc-shark
    # 2. Interfaz en modo promiscuo (opcional):
    sudo ip link set {iface} promisc on
    # 3. Mientras tanto, captura con tcpdump y analízala con el motor:
    sudo tcpdump -i {iface} -w /tmp/captura.pcapng
    soc-shark read /tmp/captura.pcapng"#
    );
}
