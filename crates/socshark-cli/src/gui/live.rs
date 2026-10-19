//! Modo en vivo de la GUI: un hilo captura de la interfaz y, cada segundo,
//! publica una foto de la red (conversaciones ya terminadas + activas,
//! enriquecidas y explicadas) que la ventana va refrescando.
//!
//! La captura reutiliza el backend del daemon ([`LiveCapture`]): mismo
//! pushdown BPF, mismo tick garantizado sin tráfico. Las tramas van a un
//! [`PacketIndex`] en modo búfer circular que el servidor lee a la vez.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use socshark_capture::{CaptureSource, LiveCapture};
use socshark_core::EnrichedFlow;
use socshark_dissectors::DissectorPipeline;
use socshark_flow::FlowAggregator;
use socshark_soc::{enrich_all, SocContext};

use super::packets::PacketIndex;
use super::{Loaded, Server};

/// Cada cuánto se publica una foto nueva.
const PUBLISH_EVERY: Duration = Duration::from_millis(1000);
/// Conversaciones terminadas que se conservan (las más recientes).
const MAX_HISTORY: usize = 20_000;

/// Estado de la captura en vivo que ve la ventana.
#[derive(Debug, Clone, Serialize)]
pub struct LiveInfo {
    pub iface: String,
    pub bpf: Option<String>,
    pub running: bool,
    pub started_micros: u64,
    /// Contadores del sistema: recibidos y descartados por falta de búfer.
    pub kernel_recv: u32,
    pub kernel_drop: u32,
    /// Motivo si la captura se detuvo sola por un error.
    pub error: Option<String>,
}

pub fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Bucle del hilo de captura. Termina al activarse `stop` o ante un error de
/// lectura; en ambos casos publica una última foto con todo lo capturado.
/// `index` es el búfer de tramas que ya enseña la sesión inicial.
pub fn run(
    server: Arc<Server>,
    mut source: LiveCapture,
    mut info: LiveInfo,
    index: Arc<RwLock<PacketIndex>>,
    stop: Arc<AtomicBool>,
) {
    let link = source.link_type();
    let cfg = server.cfg.clone();
    let mut aggregator = FlowAggregator::new(cfg.max_flows, cfg.idle_timeout_secs, false);
    let dissectors = DissectorPipeline::new();
    let mut history: VecDeque<EnrichedFlow> = VecDeque::new();
    let mut last = Instant::now();
    let mut dirty = false;

    while !stop.load(Ordering::SeqCst) {
        match source.next_packet() {
            Ok(Some(pkt)) => {
                if let Some(dp) = dissectors.dissect(&pkt, link) {
                    aggregator.on_packet(pkt.ts_micros, pkt.data.len(), &dp);
                }
                if let Ok(mut idx) = index.write() {
                    idx.push(pkt);
                }
                dirty = true;
            }
            Ok(None) => {}
            Err(e) => {
                info.error = Some(e.to_string());
                break;
            }
        }
        if last.elapsed() >= PUBLISH_EVERY {
            last = Instant::now();
            let expired = aggregator.drain_expired(now_micros());
            if !expired.is_empty() {
                history.extend(expired);
                while history.len() > MAX_HISTORY {
                    history.pop_front();
                }
                dirty = true;
            }
            if let Some((recv, drop)) = source.kernel_stats() {
                dirty |= (recv, drop) != (info.kernel_recv, info.kernel_drop);
                info.kernel_recv = recv;
                info.kernel_drop = drop;
            }
            if dirty {
                publish(
                    &server,
                    &info,
                    &history,
                    aggregator.snapshot(),
                    &aggregator,
                    &index,
                );
                dirty = false;
            }
        }
    }

    // Cierre: las conversaciones vivas se exportan completas.
    info.running = false;
    let stats = aggregator.stats();
    let rest = aggregator.finish();
    publish_with(&server, &info, &history, rest, stats, &index);
}

fn publish(
    server: &Server,
    info: &LiveInfo,
    history: &VecDeque<EnrichedFlow>,
    active: Vec<EnrichedFlow>,
    aggregator: &FlowAggregator,
    index: &Arc<RwLock<PacketIndex>>,
) {
    publish_with(server, info, history, active, aggregator.stats(), index);
}

/// Enriquece historial + activas con un contexto nuevo (el escáner y el DNS
/// pasivo ven siempre el conjunto completo) y sustituye la sesión.
fn publish_with(
    server: &Server,
    info: &LiveInfo,
    history: &VecDeque<EnrichedFlow>,
    active: Vec<EnrichedFlow>,
    stats: socshark_flow::PipelineStats,
    index: &Arc<RwLock<PacketIndex>>,
) {
    let mut flows: Vec<EnrichedFlow> = history.iter().cloned().chain(active).collect();
    flows.sort_by_key(|f| f.first_seen_micros);
    let mut ctx = SocContext {
        intel: server.intel.clone(),
        ..SocContext::default()
    };
    enrich_all(&mut ctx, &mut flows, &server.cfg);
    let loaded = Loaded::new(
        format!("En vivo · {}", info.iface),
        flows,
        stats,
        Arc::clone(index),
        Some(info.clone()),
    );
    server.replace_session(loaded);
}
