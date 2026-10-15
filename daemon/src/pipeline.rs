//! Pipeline de análisis de capturas (Fase 1, monohilo y streaming).
//!
//! ```text
//! PcapFileSource ──▶ dissect ──▶ SocEngine.observe_packet ──▶ SessionTable.feed
//!                                    (passive DNS, carving, eventos DNS)
//! al agotar la fuente:
//! SocEngine.enrich ──▶ (alertas, riesgo, dominios, artefactos, resúmenes)
//!                  ──▶ filtro DSL ──▶ CaptureReport
//! ```
//!
//! Fase 2: las etapas se separan en hilos conectados por `SpscRing`
//! (`capture-core::ring_buffer`); la estructura del pipeline no cambia.

use crate::bridge::{FlowFacts, PacketFacts};
use socshark_capture_core::{LinkType, PacketSource};
use socshark_dissectors::view::{dissect, DissectedPacket};
use socshark_filter_dsl::Expr;

pub use crate::output::cmd_read;
use socshark_flow_aggregator::session_table::SessionTable;
use socshark_soc_engine::threat_intel::ThreatIntel;
use socshark_soc_engine::{EnrichStats, SocEngine};

/// Opciones del comando `read`.
#[derive(Debug, Clone)]
pub struct ReadOpts {
    pub filter: Option<String>,
    pub min_risk: u8,
    pub include_noise: bool,
    pub limit: usize,
    pub iocs: Option<String>,
}

impl Default for ReadOpts {
    fn default() -> Self {
        ReadOpts {
            filter: None,
            min_risk: 0,
            include_noise: false,
            limit: 40,
            iocs: None,
        }
    }
}

/// Resultado completo del análisis de una captura.
pub struct CaptureReport {
    pub path: String,
    pub link: LinkType,
    pub packets: usize,
    pub packet_errors: usize,
    pub bytes: u64,
    pub first_ts_us: u64,
    pub last_ts_us: u64,
    pub engine_stats: EnrichStats,
    pub table: SessionTable,
}

/// Ejecuta el pipeline completo sobre un archivo de captura.
pub fn analyze(path: &str, opts: &ReadOpts) -> Result<CaptureReport, String> {
    let data = std::fs::read(path).map_err(|e| format!("no se pudo abrir {path}: {e}"))?;
    if data.len() > 1_073_741_824 {
        eprintln!(
            "aviso: captura de {:.1} GiB cargada en RAM (el mmap llega en fase 2)",
            data.len() as f64 / 1_073_741_824.0
        );
    }
    let mut engine = SocEngine::new();
    let mut table = SessionTable::new();

    // Detecta formato por magic y recorre streaming.
    let mut packets = 0usize;
    let mut errors = 0usize;
    let mut first_ts = u64::MAX;
    let mut last_ts = 0u64;
    let mut bytes = 0u64;
    let link;
    {
        let is_pcapng = data.len() >= 4 && data[0..4] == [0x0a, 0x0d, 0x0d, 0x0a];
        if is_pcapng {
            let mut src = socshark_capture_core::pcapng::PcapngFileSource::new(&data)?;
            link = src.link_type();
            run_source(
                &mut src,
                &mut engine,
                &mut table,
                &mut packets,
                &mut errors,
                &mut bytes,
                &mut first_ts,
                &mut last_ts,
            );
        } else {
            let mut src = socshark_capture_core::pcap::PcapFileSource::new(&data)?;
            link = src.link_type();
            run_source(
                &mut src,
                &mut engine,
                &mut table,
                &mut packets,
                &mut errors,
                &mut bytes,
                &mut first_ts,
                &mut last_ts,
            );
        }
    }

    if packets == 0 {
        return Err(format!(
            "{path}: 0 paquetes leídos ({} error(es)) — ¿formato reconocible?",
            errors
        ));
    }

    // Enriquecimiento final con threat intel opcional.
    let ti = match &opts.iocs {
        Some(p) => {
            ThreatIntel::load(std::path::Path::new(p)).map_err(|e| format!("lista de IOCs: {e}"))?
        }
        None => ThreatIntel::empty(),
    };
    let stats = engine.enrich(&mut table, &ti);

    Ok(CaptureReport {
        path: path.to_string(),
        link,
        packets,
        packet_errors: errors,
        bytes,
        first_ts_us: if first_ts == u64::MAX { 0 } else { first_ts },
        last_ts_us: last_ts,
        engine_stats: stats,
        table,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_source<'a>(
    src: &mut dyn PacketSource<'a>,
    engine: &mut SocEngine,
    table: &mut SessionTable,
    packets: &mut usize,
    errors: &mut usize,
    bytes: &mut u64,
    first_ts: &mut u64,
    last_ts: &mut u64,
) {
    while let Some(item) = src.next_packet() {
        match item {
            Ok(rec) => {
                *packets += 1;
                *bytes += rec.cap_len() as u64;
                *first_ts = (*first_ts).min(rec.ts_us);
                *last_ts = (*last_ts).max(rec.ts_us);
                let dp: DissectedPacket = dissect(&rec, src.link_type());
                engine.observe_packet(&dp);
                table.feed(&dp, src.last_offset());
            }
            Err(_) => *errors += 1,
        }
    }
}

/// Aplica el filtro DSL y los umbrales de riesgo/ruido sobre los flujos.
/// Devuelve (índices visibles, expresión compilada).
pub fn visible_flows(report: &CaptureReport, opts: &ReadOpts) -> Result<Vec<usize>, String> {
    let expr: Option<Expr> = match &opts.filter {
        Some(f) => Some(socshark_filter_dsl::parse(f)?),
        None => None,
    };
    let mut out = Vec::new();
    for (i, f) in report.table.flows().iter().enumerate() {
        if !opts.include_noise && f.is_background_noise {
            continue;
        }
        if f.risk_score < opts.min_risk {
            continue;
        }
        if let Some(e) = &expr {
            let facts = FlowFacts(f);
            if !socshark_filter_dsl::eval(e, &facts) {
                continue;
            }
        }
        out.push(i);
    }
    // Ordena por riesgo descendente y luego por tiempo.
    out.sort_by(|&a, &b| {
        let fa = &report.table.flows()[a];
        let fb = &report.table.flows()[b];
        fb.risk_score
            .cmp(&fa.risk_score)
            .then(fa.first_seen_us.cmp(&fb.first_seen_us))
    });
    Ok(out)
}

/// Filtra paquetes por expresión DSL a nivel de paquete (modo --events).
pub fn packet_matches(dp: &DissectedPacket, expr: &Option<Expr>) -> bool {
    match expr {
        Some(e) => {
            let facts = PacketFacts(dp);
            socshark_filter_dsl::eval(e, &facts)
        }
        None => true,
    }
}

/// Recorre la fuente de nuevo (para --events) llamando `f` por paquete.
pub fn for_each_packet<F: FnMut(&DissectedPacket)>(path: &str, mut f: F) -> Result<(), String> {
    let data = std::fs::read(path).map_err(|e| format!("no se pudo abrir {path}: {e}"))?;
    let is_pcapng = data.len() >= 4 && data[0..4] == [0x0a, 0x0d, 0x0d, 0x0a];
    if is_pcapng {
        let mut src = socshark_capture_core::pcapng::PcapngFileSource::new(&data)?;
        while let Some(item) = src.next_packet() {
            if let Ok(rec) = item {
                let dp = dissect(&rec, src.link_type());
                f(&dp);
            }
        }
    } else {
        let mut src = socshark_capture_core::pcap::PcapFileSource::new(&data)?;
        while let Some(item) = src.next_packet() {
            if let Ok(rec) = item {
                let dp = dissect(&rec, src.link_type());
                f(&dp);
            }
        }
    }
    Ok(())
}
