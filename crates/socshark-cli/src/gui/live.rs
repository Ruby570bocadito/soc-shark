//! Modo en vivo de la GUI: un hilo captura de la interfaz y, cada segundo,
//! publica una foto de la red (conversaciones ya terminadas + activas,
//! enriquecidas y explicadas) que la ventana va refrescando.
//!
//! La captura reutiliza el backend del daemon ([`LiveCapture`]): mismo
//! pushdown BPF, mismo tick garantizado sin tráfico. Las tramas van a un
//! [`PacketIndex`] en modo búfer circular que el servidor lee a la vez, y
//! que de paso aprende quién es quién. Para el tráfico de esta máquina se
//! averigua además qué programa abrió cada conexión ([`SocketTable`]).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use socshark_capture::{CaptureSource, LiveCapture, SocketOwner, SocketTable};
use socshark_core::{EnrichedFlow, Transport};
use socshark_dissectors::{DissectedPacket, DissectorPipeline};
use socshark_flow::FlowAggregator;
use socshark_soc::{enrich_all, SocContext};

use super::packets::{flow_id, PacketIndex};
use super::{Loaded, Server};

/// Cada cuánto se publica una foto nueva.
const PUBLISH_EVERY: Duration = Duration::from_millis(1000);
/// Cada cuánto, como mucho, se mira qué programa tiene cada conexión.
const OWNERS_EVERY: Duration = Duration::from_millis(400);
/// Conversaciones sin programa que se dejan de buscar tras este tiempo.
const OWNERS_GIVE_UP: Duration = Duration::from_secs(15);
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
    /// Direcciones de esta máquina (para «este ordenador» y sus programas).
    #[serde(skip)]
    pub local_addrs: Vec<IpAddr>,
}

pub fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Qué programa abrió cada conversación de esta máquina.
struct Owners {
    /// Conversaciones pendientes: id → (transporte, puerto local, desde).
    pending: HashMap<String, (Transport, u16, Instant)>,
    found: HashMap<String, SocketOwner>,
    last: Instant,
    /// `false` si el sistema no permite saberlo: no se vuelve a intentar.
    available: bool,
}

impl Owners {
    fn new() -> Self {
        Self {
            pending: HashMap::new(),
            found: HashMap::new(),
            last: Instant::now(),
            available: true,
        }
    }

    /// Anota la conversación del paquete si un extremo es esta máquina.
    fn note(&mut self, dp: &DissectedPacket, local: &[IpAddr]) {
        if !self.available {
            return;
        }
        let (Some(src), Some(dst)) = (dp.src_ip(), dp.dst_ip()) else {
            return;
        };
        let (sport, dport) = match (&dp.tcp, &dp.udp) {
            (Some(t), _) => (t.src_port, t.dst_port),
            (_, Some(u)) => (u.src_port, u.dst_port),
            _ => return,
        };
        let mine = |ip: IpAddr| ip.is_loopback() || local.contains(&ip);
        let port = if mine(src) {
            sport
        } else if mine(dst) {
            dport
        } else {
            return;
        };
        let Some(id) = flow_id(dp) else { return };
        if !self.found.contains_key(&id) {
            self.pending
                .entry(id)
                .or_insert((dp.transport, port, Instant::now()));
        }
    }

    /// Resuelve las pendientes con una foto de la tabla de sockets.
    fn resolve(&mut self) {
        if !self.available || self.pending.is_empty() || self.last.elapsed() < OWNERS_EVERY {
            return;
        }
        self.last = Instant::now();
        let table = match SocketTable::snapshot() {
            Ok(t) => t,
            Err(_) => {
                self.available = false;
                self.pending.clear();
                return;
            }
        };
        let found = &mut self.found;
        self.pending.retain(|id, (transport, port, since)| {
            if let Some(owner) = table.lookup(*transport, *port) {
                found.insert(id.clone(), owner.clone());
                return false;
            }
            since.elapsed() < OWNERS_GIVE_UP
        });
    }

    fn apply(&self, flows: &mut [EnrichedFlow]) {
        for f in flows {
            if let Some(o) = self.found.get(&f.flow_id.0) {
                f.process_name = Some(o.name.clone());
                f.pid = Some(o.pid);
            }
        }
    }
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
    let mut owners = Owners::new();
    let mut last = Instant::now();
    let mut dirty = false;

    while !stop.load(Ordering::SeqCst) {
        match source.next_packet() {
            Ok(Some(pkt)) => {
                if let Some(dp) = dissectors.dissect(&pkt, link) {
                    aggregator.on_packet(pkt.ts_micros, pkt.data.len(), &dp);
                    owners.note(&dp, &info.local_addrs);
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
        owners.resolve();
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
                let stats = aggregator.stats();
                publish(
                    &server,
                    &info,
                    &history,
                    aggregator.snapshot(),
                    stats,
                    &index,
                    &owners,
                );
                dirty = false;
            }
        }
    }

    // Cierre: las conversaciones vivas se exportan completas.
    info.running = false;
    let stats = aggregator.stats();
    let rest = aggregator.finish();
    publish(&server, &info, &history, rest, stats, &index, &owners);
}

/// Enriquece historial + activas con un contexto nuevo (el escáner y el DNS
/// pasivo ven siempre el conjunto completo) y sustituye la sesión.
fn publish(
    server: &Server,
    info: &LiveInfo,
    history: &VecDeque<EnrichedFlow>,
    active: Vec<EnrichedFlow>,
    stats: socshark_flow::PipelineStats,
    index: &Arc<RwLock<PacketIndex>>,
    owners: &Owners,
) {
    let mut flows: Vec<EnrichedFlow> = history.iter().cloned().chain(active).collect();
    flows.sort_by_key(|f| f.first_seen_micros);
    owners.apply(&mut flows);
    let mut ctx = SocContext {
        intel: server.intel.clone(),
        ..SocContext::default()
    };
    enrich_all(&mut ctx, &mut flows, &server.cfg);
    let hosts = match index.read() {
        Ok(idx) => server.directory(&idx, &info.local_addrs),
        Err(_) => Default::default(),
    };
    let loaded = Loaded::new(
        format!("En vivo · {}", info.iface),
        flows,
        stats,
        Arc::clone(index),
        Some(info.clone()),
        hosts,
    );
    server.replace_session(loaded);
}
