//! Orquestación del pipeline: captura → dissectors → flujos → SOC → filtro.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use socshark_capture::{CaptureSource, PcapFileReader};
use socshark_core::config::PipelineConfig;
use socshark_core::{EnrichedFlow, ExtractedFile, L7Protocol};
use socshark_dissectors::{DissectionPool, DissectorPipeline};
use socshark_filter::parse as parse_filter;
use socshark_flow::{FlowAggregator, PipelineStats, ReassembledStream};
use socshark_soc::{enrich_all, SocContext};

/// Paquetes por lote cuando el pool concurrente está activo (compromiso
/// entre paralelismo y latencia; ver ADR-010). Con 256 el reparto entre
/// hilos costaba más que la propia disección: `dev bench` con 4 workers
/// pasó de ~140k a ~218k paquetes/s al subirlo a 4096.
const POOL_CHUNK: usize = 4096;

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
/// Con `cfg.workers > 1` la disección corre en el pool concurrente por
/// lotes; la entrega al agregador es estrictamente ordenada, así que el
/// resultado es idéntico al camino secuencial (verificado por test E2E que
/// compara el JSONL de ambas rutas).
///
/// El progreso se informa por `stderr`; el resultado se devuelve completo
/// para que la capa de salida decida formato y destino.
pub fn run_capture(
    pcap_path: &Path,
    filter_expr: Option<&str>,
    show_noise: bool,
    cfg: &PipelineConfig,
) -> Result<CaptureOutput> {
    // El filtro se valida antes de leer: un error de sintaxis no debe
    // esperar a procesar una captura de varios GB.
    let filter = filter_expr
        .map(|src| {
            parse_filter(src)
                .map(|expr| (src, expr))
                .map_err(|e| anyhow::anyhow!("filtro inválido: {e}"))
        })
        .transpose()?;

    let mut reader = PcapFileReader::open(pcap_path)
        .with_context(|| format!("no se pudo abrir el pcap {}", pcap_path.display()))?;
    let link = reader.link_type();

    // El file carving necesita los streams TCP reensamblados: si está
    // activo, el agregador recolecta segmentos aunque `follow` no lo pida.
    let collect = cfg.collect_streams || cfg.file_carving;
    let mut aggregator = FlowAggregator::new(cfg.max_flows, cfg.idle_timeout_secs, collect)
        .with_stream_budget(cfg.stream_budget_mib.saturating_mul(1 << 20));
    let dissectors = DissectorPipeline::new();
    // Tallado temprano: solo para el carving, nunca con `follow` (que
    // necesita los streams completos al final).
    let mut early = if cfg.file_carving {
        EarlyCarve::new(cfg.collect_streams)
    } else {
        None
    };

    eprintln!("[*] Leyendo {} (enlace: {link:?})", pcap_path.display());

    if cfg.workers > 1 {
        // Camino paralelo: lotes de POOL_CHUNK paquetes diseccionados en
        // N hilos y volcados al agregador en orden de llegada al lote.
        let mut pool = DissectionPool::spawn(cfg.workers, POOL_CHUNK)
            .map_err(|e| anyhow::anyhow!("pool de dissectors: {e}"))?;
        eprintln!(
            "[*] Pool de disección: {} hilos × {} paquetes/lote",
            cfg.workers, POOL_CHUNK
        );
        let mut chunk: Vec<socshark_core::RawPacket> = Vec::with_capacity(POOL_CHUNK);
        let mut meta: Vec<(u64, usize)> = Vec::with_capacity(POOL_CHUNK); // (ts, len)
        loop {
            match reader.next_packet().context("error leyendo paquetes")? {
                Some(pkt) => {
                    meta.push((pkt.ts_micros, pkt.data.len()));
                    chunk.push(pkt);
                    if chunk.len() == POOL_CHUNK {
                        feed_chunk(
                            &mut pool,
                            link,
                            &mut chunk,
                            &mut meta,
                            &mut aggregator,
                            early.as_mut(),
                        );
                    }
                }
                None => {
                    if !chunk.is_empty() {
                        feed_chunk(
                            &mut pool,
                            link,
                            &mut chunk,
                            &mut meta,
                            &mut aggregator,
                            early.as_mut(),
                        );
                    }
                    break;
                }
            }
        }
        // El Drop del pool cierra los canales y hace join de los hilos.
    } else {
        // Camino secuencial (zero-copy estricto del payload).
        while let Some(pkt) = reader.next_packet().context("error leyendo paquetes")? {
            if let Some(dp) = dissectors.dissect(&pkt, link) {
                aggregator.on_packet(pkt.ts_micros, pkt.data.len(), &dp);
            }
            if let Some(e) = early.as_mut() {
                e.tick(&mut aggregator, pkt.ts_micros);
            }
        }
    }

    let stats = aggregator.stats();
    let (mut flows, streams) = aggregator.finish_with_streams();
    eprintln!("[*] {} → {} flujos agregados", stats.summary(), flows.len());

    // File carving (Fase 4): extrae archivos HTTP de los streams ANTES de la
    // capa SOC, para que R6 (T1036) y los resúmenes los vean.
    if cfg.file_carving {
        socshark_soc::carve::carve_all(&mut flows, &streams);
        if let Some(e) = early.take() {
            e.apply(&mut flows);
        }
        let total: usize = flows.iter().map(|f| f.extracted_files.len()).sum();
        eprintln!("[*] File carving: {total} archivos tallados de los streams HTTP");
    }

    let mut ctx = SocContext::default();
    load_intel(&mut ctx, cfg)?;
    enrich_all(&mut ctx, &mut flows, cfg);
    eprintln!(
        "[*] Enriquecimiento SOC listo ({} entradas de DNS pasivo)",
        ctx.passive_dns.len()
    );

    if let Some((expr_src, expr)) = filter {
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

/// Carga las listas de threat intel offline indicadas en la configuración
/// (Fase 4). Un fichero ilegible aborta con error claro: una lista que no
/// carga es un fallo de configuración, no algo a pasar por alto.
fn load_intel(ctx: &mut SocContext, cfg: &PipelineConfig) -> Result<()> {
    if cfg.intel_feodo.is_some() || cfg.intel_tor.is_some() {
        let db = socshark_soc::ThreatIntelDb::from_paths(
            cfg.intel_feodo.as_deref(),
            cfg.intel_tor.as_deref(),
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
    Ok(())
}

/// Envía un lote al pool y vuelca los resultados al agregador en el orden
/// original de los paquetes (determinismo, ADR-010).
/// Paquetes mínimos entre dos recorridos de la tabla en busca de
/// conexiones cerradas (mirar el presupuesto, en cambio, es O(1) y se hace
/// en cada paquete).
const RELEASE_SCAN_EVERY: usize = 256;
/// Silencio (tiempo de captura) que se exige a una conexión cerrada antes
/// de tallarla: absorbe ACK y retransmisiones tardías.
const RELEASE_QUIET_MICROS: u64 = 5_000_000;

/// Tallado temprano de las conexiones ya cerradas cuando el presupuesto de
/// reensamblado pasa de la mitad: los archivos se guardan por `flow_id` y se
/// aplican al final, así que el resultado es el mismo que tallando todo al
/// final (con un presupuesto infinito), pero con memoria acotada.
struct EarlyCarve {
    files: HashMap<String, Vec<ExtractedFile>>,
    since_check: usize,
    released: usize,
}

impl EarlyCarve {
    /// `None` si hay que conservar los streams completos (`follow`).
    fn new(keep_streams: bool) -> Option<Self> {
        (!keep_streams).then(|| Self {
            files: HashMap::new(),
            since_check: RELEASE_SCAN_EVERY,
            released: 0,
        })
    }

    fn tick(&mut self, aggregator: &mut FlowAggregator, now_micros: u64) {
        self.since_check = self.since_check.saturating_add(1);
        if self.since_check < RELEASE_SCAN_EVERY
            || aggregator.stream_bytes_used().saturating_mul(2) < aggregator.stream_budget()
        {
            return;
        }
        self.since_check = 0;
        for (id, l7, stream) in aggregator.release_closed_streams(now_micros, RELEASE_QUIET_MICROS)
        {
            self.released += 1;
            if l7 == L7Protocol::Http {
                let files = socshark_soc::carve::carve_http(&stream.client, &stream.server);
                if !files.is_empty() {
                    self.files.insert(id.0, files);
                }
            }
        }
    }

    fn apply(mut self, flows: &mut [EnrichedFlow]) {
        if self.released > 0 {
            eprintln!(
                "[*] Reensamblado: {} conexiones cerradas talladas antes de tiempo para liberar memoria",
                self.released
            );
        }
        for f in flows.iter_mut() {
            if let Some(files) = self.files.remove(&f.flow_id.0) {
                f.extracted_files = files;
            }
        }
    }
}

fn feed_chunk(
    pool: &mut DissectionPool,
    link: socshark_core::LinkType,
    chunk: &mut Vec<socshark_core::RawPacket>,
    meta: &mut Vec<(u64, usize)>,
    aggregator: &mut FlowAggregator,
    mut early: Option<&mut EarlyCarve>,
) {
    let results = pool.process(link, std::mem::take(chunk));
    debug_assert_eq!(
        results.len(),
        meta.len(),
        "el pool respeta el orden del lote"
    );
    for (dp, (ts, len)) in results.into_iter().zip(meta.drain(..)) {
        if let Some(dp) = dp {
            aggregator.on_packet(ts, len, &dp);
        }
        if let Some(e) = early.as_deref_mut() {
            e.tick(aggregator, ts);
        }
    }
}

/// Localiza un flujo por su id (coincidencia de subcadena) y devuelve el
/// flujo enriquecido junto a su stream TCP reensamblado (Fase 2).
///
/// Siempre recolecta segmentos (`collect_streams`), incluye el ruido (el
/// analista pidió ese flujo explícitamente) y no aplica filtro DSL.
pub fn run_follow(
    pcap_path: &Path,
    selector: &str,
    cfg: &PipelineConfig,
) -> Result<Option<(EnrichedFlow, ReassembledStream)>> {
    let mut reader = PcapFileReader::open(pcap_path)
        .with_context(|| format!("no se pudo abrir el pcap {}", pcap_path.display()))?;
    let link = reader.link_type();

    let mut aggregator = FlowAggregator::new(cfg.max_flows, cfg.idle_timeout_secs, true);
    let dissectors = DissectorPipeline::new();
    while let Some(pkt) = reader.next_packet().context("error leyendo paquetes")? {
        if let Some(dp) = dissectors.dissect(&pkt, link) {
            aggregator.on_packet(pkt.ts_micros, pkt.data.len(), &dp);
        }
    }

    let (mut flows, streams) = aggregator.finish_with_streams();
    let mut ctx = SocContext::default();
    enrich_all(&mut ctx, &mut flows, cfg);

    for flow in &flows {
        if let Some(stream) = streams.get(&flow.flow_id.0) {
            if flow.flow_id.0.contains(selector) {
                return Ok(Some((flow.clone(), stream.clone())));
            }
        }
    }
    Ok(None)
}
