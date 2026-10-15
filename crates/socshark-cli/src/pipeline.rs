//! Orquestación del pipeline: captura → dissectors → flujos → SOC → filtro.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use socshark_capture::{CaptureSource, PcapFileReader};
use socshark_core::config::PipelineConfig;
use socshark_core::EnrichedFlow;
use socshark_dissectors::DissectorPipeline;
use socshark_filter::parse as parse_filter;
use socshark_flow::{FlowAggregator, PipelineStats};
use socshark_soc::{enrich_all, SocContext};

/// Resultado completo de una ejecución de `socshark capture`.
pub struct CaptureOutput {
    /// Flujos enriquecidos (y filtrados si aplicó un DSL).
    pub flows: Vec<EnrichedFlow>,
    /// Estadísticas de paquetes/flujos.
    pub stats: PipelineStats,
    /// Configuración efectiva usada.
    pub config: PipelineConfig,
    /// Pcap de entrada.
    pub pcap_path: PathBuf,
    /// Entradas de la base de DNS pasivo al finalizar la sesión.
    pub passive_dns_entries: usize,
}

/// Ejecuta el pipeline completo sobre un archivo pcap.
///
/// Pasos: (1) leer paquetes y diseccionarlos, (2) agregar flujos,
/// (3) enriquecer con la capa SOC usando el contexto completo,
/// (4) aplicar el filtro DSL, (5) excluir ruido salvo petición explícita.
///
/// El progreso se informa por `stderr`; el resultado se devuelve completo
/// para que la capa de salida decida formato y destino.
pub fn run_capture(
    pcap_path: &Path,
    filter_expr: Option<&str>,
    show_noise: bool,
    cfg: &PipelineConfig,
) -> Result<CaptureOutput> {
    let mut reader = PcapFileReader::open(pcap_path)
        .with_context(|| format!("no se pudo abrir el pcap {}", pcap_path.display()))?;
    let link = reader.link_type();

    let mut aggregator = FlowAggregator::new(cfg.max_flows, cfg.idle_timeout_secs);
    let dissectors = DissectorPipeline::new();

    eprintln!("[*] Leyendo {} (enlace: {link:?})", pcap_path.display());
    while let Some(pkt) = reader.next_packet().context("error leyendo paquetes")? {
        if let Some(dp) = dissectors.dissect(&pkt, link) {
            aggregator.on_packet(pkt.ts_micros, pkt.data.len(), &dp);
        }
    }

    let stats = aggregator.stats();
    let mut flows = aggregator.finish();
    eprintln!("[*] {} → {} flujos agregados", stats.summary(), flows.len());

    let mut ctx = SocContext::default();
    enrich_all(&mut ctx, &mut flows, cfg);
    eprintln!(
        "[*] Enriquecimiento SOC listo ({} entradas de DNS pasivo)",
        ctx.passive_dns.len()
    );

    if let Some(expr_src) = filter_expr {
        let expr = parse_filter(expr_src).map_err(|e| anyhow::anyhow!("filtro inválido: {e}"))?;
        let before = flows.len();
        flows.retain(|f| socshark_filter::eval(&expr, f));
        eprintln!("[*] Filtro `{expr_src}`: {before} → {} flujos", flows.len());
    }

    if !show_noise {
        flows.retain(|f| !f.is_background_noise);
    }

    eprintln!("[+] Listo: {} flujos tras el filtrado", flows.len());
    Ok(CaptureOutput {
        flows,
        stats,
        config: cfg.clone(),
        pcap_path: pcap_path.to_path_buf(),
        passive_dns_entries: ctx.passive_dns.len(),
    })
}
