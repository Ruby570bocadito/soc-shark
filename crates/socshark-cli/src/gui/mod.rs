//! GUI de soc-shark: `socshark gui` (ADR-013).
//!
//! La interfaz es una página web local que sirve el propio binario y que se
//! abre en una ventana de aplicación (Edge o Chrome en modo `--app`, o el
//! navegador por defecto). Así hay GUI en Windows, macOS y Linux sin
//! dependencias nuevas (ADR-003) y el mismo frontend podrá empaquetarse más
//! adelante en Tauri sin reescribirlo.
//!
//! Dos fuentes: una captura de archivo (abierta al arrancar o subida desde
//! la ventana) o la **captura en vivo** de una interfaz ([`live`]), que se
//! publica como fotos sucesivas; la ventana detecta cada foto nueva por su
//! número de generación.
//!
//! Seguridad (la captura la controla quien genera el tráfico):
//! - Solo escucha en `127.0.0.1`.
//! - Se exige la cabecera `Host` local exacta: bloquea el *DNS rebinding*.
//! - Toda la API exige un token aleatorio de sesión que solo conoce la
//!   página servida; una web ajena abierta en el navegador no puede leerlo
//!   ni enviarlo (cabecera propia ⇒ preflight CORS que nunca se aprueba).
//! - El frontend trata todo dato de la captura como texto (nunca HTML) y la
//!   CSP impide cargar o ejecutar nada externo.

mod http;
mod live;
pub mod packets;

use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use socshark_capture::{CaptureSource, LiveBreaker, LiveCapture, LiveCaptureConfig};
use socshark_core::config::PipelineConfig;
use socshark_core::{EnrichedFlow, L7Protocol, Transport};
use socshark_flow::PipelineStats;
use socshark_soc::explain::{explain, service_by_port, stories, Explanation, Level, Story};
use socshark_soc::ThreatIntelDb;

use crate::pipeline::run_capture;
use http::{read_request, write_response, ReadError, Request, Response};
use live::LiveInfo;
use packets::PacketIndex;

const INDEX_HTML: &str = include_str!("../../assets/gui/index.html");
const APP_JS: &str = include_str!("../../assets/gui/app.js");
const APP_CSS: &str = include_str!("../../assets/gui/app.css");

/// Puerto por defecto; si está ocupado se usa uno libre cualquiera.
pub const DEFAULT_PORT: u16 = 8787;
/// Tamaño máximo de una captura abierta desde la ventana.
const MAX_UPLOAD: usize = 512 * 1024 * 1024;
/// Flujos que se envían como mucho a la tabla (el resto, con un filtro).
const MAX_FLOWS: usize = 10_000;
/// Filas como mucho de cada tabla de estadísticas.
const MAX_STATS_ROWS: usize = 200;
/// Filas como mucho por página de la lista global de paquetes.
const MAX_PAGE: usize = 1000;

/// Opciones de `socshark gui`.
#[derive(Debug, Clone)]
pub struct GuiOptions {
    /// Captura a abrir al arrancar (también se puede abrir desde la ventana).
    pub read: Option<PathBuf>,
    /// Puerto local; `None` = [`DEFAULT_PORT`] o uno libre.
    pub port: Option<u16>,
    /// Abrir la ventana automáticamente.
    pub open: bool,
    pub cfg: PipelineConfig,
}

/// Captura analizada y lista para la interfaz.
pub(crate) struct Loaded {
    name: String,
    flows: Vec<EnrichedFlow>,
    explanations: Vec<Explanation>,
    stories: Vec<Story>,
    stats: PipelineStats,
    packets: Arc<RwLock<PacketIndex>>,
    live: Option<LiveInfo>,
    /// Número de foto: cambia cada vez que se sustituye la sesión.
    generation: u64,
}

impl Loaded {
    pub(crate) fn new(
        name: String,
        flows: Vec<EnrichedFlow>,
        stats: PipelineStats,
        packets: Arc<RwLock<PacketIndex>>,
        live: Option<LiveInfo>,
    ) -> Self {
        Self {
            explanations: flows.iter().map(explain).collect(),
            stories: stories(&flows),
            name,
            flows,
            stats,
            packets,
            live,
            generation: 0,
        }
    }
}

struct LiveHandle {
    stop: Arc<AtomicBool>,
    /// Despierta una lectura bloqueada para que la parada sea inmediata.
    breaker: LiveBreaker,
    thread: JoinHandle<()>,
}

pub(crate) struct Server {
    token: String,
    port: u16,
    host_ok: [String; 3],
    pub(crate) cfg: PipelineConfig,
    /// Listas de threat intel para el modo en vivo (el de archivo las carga
    /// en el propio pipeline).
    pub(crate) intel: Option<ThreatIntelDb>,
    session: RwLock<Option<Loaded>>,
    generation: AtomicU64,
    live: Mutex<Option<LiveHandle>>,
    upload_seq: AtomicU64,
}

/// Analiza una captura de archivo con el pipeline completo (ruido incluido:
/// la interfaz decide si lo muestra) y prepara su índice de paquetes.
fn load(path: &Path, name: String, cfg: &PipelineConfig) -> Result<Loaded> {
    let out = run_capture(path, None, true, cfg)?;
    let packets = PacketIndex::build(path)?;
    Ok(Loaded::new(
        name,
        out.flows,
        out.stats,
        Arc::new(RwLock::new(packets)),
        None,
    ))
}

/// 128 bits impredecibles para quien no ve la página: dos `RandomState`
/// (claves SipHash sembradas por el sistema operativo) sobre el instante y
/// el PID. Basta para un token anti-CSRF local sin dependencias.
fn new_token() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    (0..2u8)
        .map(|i| {
            let mut h = RandomState::new().build_hasher();
            h.write_u8(i);
            h.write_u128(now);
            h.write_u32(std::process::id());
            format!("{:016x}", h.finish())
        })
        .collect()
}

/// Comparación en tiempo constante (no filtra el token por tiempos).
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// Nombre a mostrar de un archivo subido: sin rutas y acotado.
fn display_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw).trim();
    let name: String = base.chars().filter(|c| !c.is_control()).take(100).collect();
    if name.is_empty() {
        "captura.pcap".into()
    } else {
        name
    }
}

/// Un lock envenenado (un hilo cayó con él tomado) no tumba el servidor.
fn lock_err() -> Response {
    Response::error(500, "estado interno inconsistente")
}

impl Server {
    fn new(port: u16, cfg: PipelineConfig) -> Self {
        Self {
            token: new_token(),
            port,
            host_ok: [
                format!("127.0.0.1:{port}"),
                format!("localhost:{port}"),
                format!("[::1]:{port}"),
            ],
            cfg,
            intel: None,
            session: RwLock::new(None),
            generation: AtomicU64::new(0),
            live: Mutex::new(None),
            upload_seq: AtomicU64::new(0),
        }
    }

    /// Sustituye la captura que enseña la ventana (archivo o foto en vivo).
    pub(crate) fn replace_session(&self, mut loaded: Loaded) {
        loaded.generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        if let Ok(mut s) = self.session.write() {
            *s = Some(loaded);
        }
    }

    /// Detiene la captura en vivo, si la hay, y espera a su última foto.
    fn stop_live(&self) {
        let handle = self.live.lock().ok().and_then(|mut h| h.take());
        if let Some(h) = handle {
            h.stop.store(true, Ordering::SeqCst);
            h.breaker.interrupt();
            let _ = h.thread.join();
        }
    }

    fn route(self: &Arc<Self>, req: &Request) -> Response {
        // Antes que nada: solo peticiones dirigidas a este servidor local.
        match req.header("host") {
            Some(h) if self.host_ok.iter().any(|ok| ok.eq_ignore_ascii_case(h)) => {}
            _ => return Response::error(421, "host no permitido"),
        }
        let path = req.path.as_str();
        if !path.starts_with("/api/") {
            return match (req.method.as_str(), path) {
                ("GET", "/") => Response::new(
                    200,
                    "text/html; charset=utf-8",
                    INDEX_HTML.replace("__SOCSHARK_TOKEN__", &self.token),
                ),
                ("GET", "/app.js") => Response::new(200, "text/javascript; charset=utf-8", APP_JS),
                ("GET", "/app.css") => Response::new(200, "text/css; charset=utf-8", APP_CSS),
                _ => Response::error(404, "no existe"),
            };
        }
        match req.header("x-socshark-token") {
            Some(t) if same(t, &self.token) => {}
            _ => return Response::error(403, "token de sesión ausente o incorrecto"),
        }

        let parts: Vec<&str> = path.trim_start_matches("/api/").split('/').collect();
        match (req.method.as_str(), parts.as_slice()) {
            ("GET", ["session"]) => self.with_session(|s| Response::json(200, &session_json(s))),
            ("GET", ["stories"]) => self.with_loaded(|l| {
                Response::json(
                    200,
                    &serde_json::to_value(&l.stories).unwrap_or(Value::Null),
                )
            }),
            ("GET", ["flows"]) => self.with_loaded(|l| flows_json(l, req.query_param("filter"))),
            ("GET", ["flows", i, what @ ("packets" | "stream")]) => self.with_loaded(|l| {
                let Some(flow) = i.parse::<usize>().ok().and_then(|i| l.flows.get(i)) else {
                    return Response::error(404, "flujo inexistente");
                };
                let Ok(idx) = l.packets.read() else {
                    return lock_err();
                };
                if *what == "stream" {
                    return Response::json(
                        200,
                        &serde_json::to_value(idx.stream(flow)).unwrap_or(Value::Null),
                    );
                }
                let (rows, more) = idx.list(flow);
                Response::json(
                    200,
                    &json!({ "packets": rows, "more": more, "truncated": idx.truncated }),
                )
            }),
            ("GET", ["packets"]) => self.with_loaded(|l| packets_page(l, req)),
            ("GET", ["stats"]) => self.with_loaded(|l| stats_json(l, req)),
            ("GET", ["packets", n]) => self.with_loaded(|l| {
                let Ok(idx) = l.packets.read() else {
                    return lock_err();
                };
                match n.parse::<usize>().ok().and_then(|n| idx.detail(n)) {
                    Some(d) => Response::json(200, &serde_json::to_value(d).unwrap_or(Value::Null)),
                    None => Response::error(404, "paquete inexistente"),
                }
            }),
            ("GET", ["timeline"]) => {
                self.with_loaded(|l| {
                    let sel = match ViewFilter::from_request(l, req) {
                        Ok(f) => f,
                        Err(resp) => return resp,
                    };
                    let keep = |id: &str| sel.keep(id);
                    match l.packets.read() {
                        Ok(idx) => Response::json(
                            200,
                            &serde_json::to_value(idx.timeline(
                                120,
                                sel.active().then_some(&keep as &dyn Fn(&str) -> bool),
                            ))
                            .unwrap_or(Value::Null),
                        ),
                        Err(_) => lock_err(),
                    }
                })
            }
            ("GET", ["save.pcap"]) => self.with_loaded(|l| match l.packets.read() {
                Ok(idx) => {
                    Response::download(&save_name(l), "application/vnd.tcpdump.pcap", idx.to_pcap())
                }
                Err(_) => lock_err(),
            }),
            ("GET", ["live", "ifaces"]) => match socshark_capture::list_ifaces() {
                Ok(ifaces) => Response::json(
                    200,
                    &json!(ifaces
                        .iter()
                        .map(|i| json!({ "name": i.name, "description": i.description }))
                        .collect::<Vec<_>>()),
                ),
                Err(e) => Response::error(503, &e.to_string()),
            },
            ("POST", ["live", "start"]) => self.start_live(req),
            ("POST", ["live", "stop"]) => {
                self.stop_live();
                self.with_session(|s| Response::json(200, &session_json(s)))
            }
            ("POST", ["open"]) => self.open_upload(req),
            (
                _,
                ["session" | "stories" | "flows" | "packets" | "stats" | "timeline" | "save.pcap"
                | "live" | "open", ..],
            ) => Response::error(405, "método no permitido"),
            _ => Response::error(404, "no existe"),
        }
    }

    fn with_session(&self, f: impl FnOnce(Option<&Loaded>) -> Response) -> Response {
        match self.session.read() {
            Ok(s) => f(s.as_ref()),
            Err(_) => lock_err(),
        }
    }

    fn with_loaded(&self, f: impl FnOnce(&Loaded) -> Response) -> Response {
        self.with_session(|s| match s {
            Some(l) => f(l),
            None => Response::error(404, "no hay ninguna captura abierta"),
        })
    }

    /// Empieza a capturar en vivo de una interfaz (detiene la anterior).
    fn start_live(self: &Arc<Self>, req: &Request) -> Response {
        let Some(iface) = req.query_param("iface").filter(|i| !i.trim().is_empty()) else {
            return Response::error(400, "falta la interfaz");
        };
        let bpf = req.query_param("bpf").filter(|b| !b.trim().is_empty());
        self.stop_live();
        let cfg = LiveCaptureConfig {
            // Tick frecuente: la ventana responde rápido a "Detener".
            timeout_ms: 250,
            ..LiveCaptureConfig::new(iface.clone()).with_bpf(Some(self.live_bpf(bpf.as_deref())))
        };
        let source = match LiveCapture::open(cfg) {
            Ok(s) => s,
            Err(e) => return Response::error(400, &e.to_string()),
        };
        let index = Arc::new(RwLock::new(PacketIndex::new(source.link_type(), true)));
        let info = LiveInfo {
            iface: iface.clone(),
            bpf,
            running: true,
            started_micros: live::now_micros(),
            kernel_recv: 0,
            kernel_drop: 0,
            error: None,
        };
        self.replace_session(Loaded::new(
            format!("En vivo · {iface}"),
            Vec::new(),
            PipelineStats::default(),
            Arc::clone(&index),
            Some(info.clone()),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let breaker = source.breaker();
        let server = Arc::clone(self);
        let stop_thread = Arc::clone(&stop);
        let thread =
            std::thread::spawn(move || live::run(server, source, info, index, stop_thread));
        if let Ok(mut h) = self.live.lock() {
            *h = Some(LiveHandle {
                stop,
                breaker,
                thread,
            });
        }
        self.with_session(|s| Response::json(200, &session_json(s)))
    }

    /// Filtro BPF de la captura en vivo: el del usuario, sin el tráfico de la
    /// propia ventana con este servidor (en loopback lo inundaría todo).
    fn live_bpf(&self, user: Option<&str>) -> String {
        let own = format!("not (tcp port {} and host 127.0.0.1)", self.port);
        match user {
            Some(u) => format!("({u}) and {own}"),
            None => own,
        }
    }

    /// Analiza una captura subida desde la ventana ("Abrir captura…").
    fn open_upload(&self, req: &Request) -> Response {
        if req.body.is_empty() {
            return Response::error(400, "el archivo está vacío");
        }
        self.stop_live();
        let name = display_name(&req.query_param("name").unwrap_or_default());
        let seq = self.upload_seq.fetch_add(1, Ordering::Relaxed);
        let tmp =
            std::env::temp_dir().join(format!("socshark-gui-{}-{seq}.pcap", std::process::id()));
        let result = std::fs::write(&tmp, &req.body)
            .context("no se pudo guardar el archivo temporal")
            .and_then(|_| load(&tmp, name, &self.cfg));
        std::fs::remove_file(&tmp).ok();
        match result {
            Ok(loaded) => {
                self.replace_session(loaded);
                self.with_session(|s| Response::json(200, &session_json(s)))
            }
            // Solo la causa: la ruta del archivo temporal no le dice nada a
            // quien subió la captura.
            Err(e) => Response::error(400, &e.root_cause().to_string()),
        }
    }
}

/// Nombre sugerido al guardar la captura.
fn save_name(l: &Loaded) -> String {
    match &l.live {
        Some(info) => format!(
            "soc-shark-{}-{}.pcap",
            info.iface.rsplit(['\\', '/']).next().unwrap_or("vivo"),
            info.started_micros / 1_000_000
        ),
        None => {
            let base = l.name.trim_end_matches(".pcap").trim_end_matches(".cap");
            format!("{base}-soc-shark.pcap")
        }
    }
}

fn session_json(s: Option<&Loaded>) -> Value {
    let Some(l) = s else {
        return json!({ "loaded": false, "version": env!("CARGO_PKG_VERSION") });
    };
    let count = |lv: Level| l.explanations.iter().filter(|e| e.level == lv).count();
    let (stored_truncated, total) = l
        .packets
        .read()
        .map(|i| (i.truncated, i.total()))
        .unwrap_or((false, 0));
    json!({
        "loaded": true,
        "version": env!("CARGO_PKG_VERSION"),
        "generation": l.generation,
        "name": l.name,
        "packets": l.stats.total_packets.max(total as u64),
        "parsed": l.stats.parsed_packets,
        "skipped": l.stats.skipped_packets,
        "flows": l.flows.len(),
        "noise": l.flows.iter().filter(|f| f.is_background_noise).count(),
        "levels": { "ok": count(Level::Ok), "raro": count(Level::Raro), "peligro": count(Level::Peligro) },
        "stories": l.stories.len(),
        "first_seen": l.flows.iter().map(|f| f.first_seen_micros).min(),
        "last_seen": l.flows.iter().map(|f| f.last_seen_micros).max(),
        "packets_truncated": stored_truncated,
        "live": l.live,
    })
}

/// Filtro DSL ya parseado, o la respuesta 400 que señala el error.
fn parse_filter(filter: Option<String>) -> Result<Option<socshark_filter::Expr>, Response> {
    let filter = filter.filter(|f| !f.trim().is_empty());
    match filter.as_deref().map(socshark_filter::parse).transpose() {
        Ok(e) => Ok(e),
        Err(e) => Err(Response::json(
            400,
            &json!({ "error": e.message, "pos": e.pos, "filter": filter }),
        )),
    }
}

fn matches(expr: &Option<socshark_filter::Expr>, flow: &EnrichedFlow) -> bool {
    match expr {
        Some(e) => socshark_filter::eval(e, flow),
        None => true,
    }
}

fn flows_json(l: &Loaded, filter: Option<String>) -> Response {
    let expr = match parse_filter(filter) {
        Ok(e) => e,
        Err(resp) => return resp,
    };
    let matching: Vec<usize> = (0..l.flows.len())
        .filter(|&i| matches(&expr, &l.flows[i]))
        .collect();
    let rows: Vec<Value> = matching
        .iter()
        .take(MAX_FLOWS)
        .map(|&i| {
            let f = &l.flows[i];
            json!({ "idx": i, "proto": proto_name(f), "flow": f, "explain": &l.explanations[i] })
        })
        .collect();
    Response::json(
        200,
        &json!({ "flows": rows, "total": matching.len(), "truncated": matching.len() > MAX_FLOWS }),
    )
}

/// Nombre corto del protocolo de una conversación: el de aplicación si se
/// reconoció, si no el de transporte.
fn proto_name(f: &EnrichedFlow) -> &'static str {
    if f.l7_protocol == L7Protocol::Unknown {
        f.transport.as_str()
    } else {
        f.l7_protocol.as_str()
    }
}

/// Dónde está una dirección, dicho para personas.
fn ip_scope(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(v4) if v4.is_multicast() || v4.is_broadcast() => "grupo",
        IpAddr::V4(v4) if v4.is_private() || v4.is_loopback() || v4.is_link_local() => "local",
        IpAddr::V6(v6) if v6.is_multicast() => "grupo",
        IpAddr::V6(v6)
            if v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80 =>
        {
            "local"
        }
        _ => "internet",
    }
}

/// Estadísticas de lo que pasa el filtro, como los menús de Wireshark
/// Jerarquía de protocolos, Endpoints y Conversaciones, pero por
/// conversación: protocolos, equipos que más hablan y servicios usados.
fn stats_json(l: &Loaded, req: &Request) -> Response {
    let sel = match ViewFilter::from_request(l, req) {
        Ok(f) => f,
        Err(resp) => return resp,
    };

    #[derive(Default)]
    struct Proto {
        flows: u64,
        packets: u64,
        bytes: u64,
    }
    struct Endpoint<'a> {
        flows: u64,
        peers: HashSet<IpAddr>,
        packets_out: u64,
        packets_in: u64,
        bytes_out: u64,
        bytes_in: u64,
        level: Level,
        domain: Option<&'a str>,
    }
    struct Service {
        flows: u64,
        bytes: u64,
        level: Level,
    }

    let mut total = Proto::default();
    let mut protocols: HashMap<&'static str, Proto> = HashMap::new();
    let mut endpoints: HashMap<IpAddr, Endpoint> = HashMap::new();
    let mut services: HashMap<(u16, Transport), Service> = HashMap::new();
    for (i, (f, e)) in l.flows.iter().zip(&l.explanations).enumerate() {
        if !sel.keep_flow(i) {
            continue;
        }
        let (packets, bytes) = (f.packets + f.packets_rev, f.bytes + f.bytes_rev);
        for p in [&mut total, protocols.entry(proto_name(f)).or_default()] {
            p.flows += 1;
            p.packets += packets;
            p.bytes += bytes;
        }
        // Lo que envía el origen lo recibe el destino, y al revés.
        let sides = [
            (
                f.src_ip,
                f.dst_ip,
                f.packets,
                f.packets_rev,
                f.bytes,
                f.bytes_rev,
                None,
            ),
            (
                f.dst_ip,
                f.src_ip,
                f.packets_rev,
                f.packets,
                f.bytes_rev,
                f.bytes,
                f.resolved_domain.as_deref(),
            ),
        ];
        for (ip, peer, p_out, p_in, b_out, b_in, domain) in sides {
            let ep = endpoints.entry(ip).or_insert_with(|| Endpoint {
                flows: 0,
                peers: HashSet::new(),
                packets_out: 0,
                packets_in: 0,
                bytes_out: 0,
                bytes_in: 0,
                level: Level::Ok,
                domain: None,
            });
            ep.flows += 1;
            ep.peers.insert(peer);
            ep.packets_out += p_out;
            ep.packets_in += p_in;
            ep.bytes_out += b_out;
            ep.bytes_in += b_in;
            ep.level = ep.level.max(e.level);
            if ep.domain.is_none() {
                ep.domain = domain;
            }
        }
        if matches!(f.transport, Transport::Tcp | Transport::Udp) {
            let s = services
                .entry((f.dst_port, f.transport))
                .or_insert(Service {
                    flows: 0,
                    bytes: 0,
                    level: Level::Ok,
                });
            s.flows += 1;
            s.bytes += bytes;
            s.level = s.level.max(e.level);
        }
    }

    let mut protocols: Vec<(&str, Proto)> = protocols.into_iter().collect();
    protocols.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then(a.0.cmp(b.0)));
    let mut endpoints: Vec<(IpAddr, Endpoint)> = endpoints.into_iter().collect();
    endpoints.sort_by(|a, b| {
        (b.1.bytes_out + b.1.bytes_in)
            .cmp(&(a.1.bytes_out + a.1.bytes_in))
            .then(a.0.cmp(&b.0))
    });
    let mut services: Vec<((u16, Transport), Service)> = services.into_iter().collect();
    services.sort_by(|a, b| {
        b.1.flows
            .cmp(&a.1.flows)
            .then(b.1.bytes.cmp(&a.1.bytes))
            .then(a.0 .0.cmp(&b.0 .0))
    });

    Response::json(
        200,
        &json!({
            "total": { "flows": total.flows, "packets": total.packets, "bytes": total.bytes },
            "protocols": protocols.iter().map(|(name, p)| json!({
                "name": name, "flows": p.flows, "packets": p.packets, "bytes": p.bytes,
            })).collect::<Vec<_>>(),
            "endpoints_total": endpoints.len(),
            "endpoints": endpoints.iter().take(MAX_STATS_ROWS).map(|(ip, ep)| json!({
                "ip": ip, "scope": ip_scope(ip), "domain": ep.domain, "flows": ep.flows,
                "peers": ep.peers.len(), "packets_out": ep.packets_out, "packets_in": ep.packets_in,
                "bytes_out": ep.bytes_out, "bytes_in": ep.bytes_in, "level": ep.level,
            })).collect::<Vec<_>>(),
            "services_total": services.len(),
            "services": services.iter().take(MAX_STATS_ROWS).map(|((port, tr), s)| {
                let known = service_by_port(*port, *tr);
                json!({
                    "port": port, "transport": tr.as_str(), "name": known.map(|k| k.0),
                    "about": known.map(|k| k.1), "flows": s.flows, "bytes": s.bytes, "level": s.level,
                })
            }).collect::<Vec<_>>(),
        }),
    )
}

/// Lo que la ventana está mirando: filtro DSL (por conversación), si se
/// muestra el tráfico de fondo (`noise=0` lo oculta) y si solo lo importante
/// (`important=1`: raro o peligro). Lo comparten la lista de paquetes, la
/// línea de tiempo y las estadísticas, para que cuadren entre sí.
struct ViewFilter<'a> {
    l: &'a Loaded,
    by_id: HashMap<&'a str, usize>,
    expr: Option<socshark_filter::Expr>,
    show_noise: bool,
    important: bool,
}

impl<'a> ViewFilter<'a> {
    fn from_request(l: &'a Loaded, req: &Request) -> Result<Self, Response> {
        Ok(Self {
            l,
            by_id: l
                .flows
                .iter()
                .enumerate()
                .map(|(i, f)| (f.flow_id.0.as_str(), i))
                .collect(),
            expr: parse_filter(req.query_param("filter"))?,
            show_noise: req.query_param("noise").as_deref() != Some("0"),
            important: req.query_param("important").as_deref() == Some("1"),
        })
    }

    /// ¿Recorta algo? Si no, se evita evaluar paquete a paquete.
    fn active(&self) -> bool {
        self.expr.is_some() || !self.show_noise || self.important
    }

    fn flow(&self, id: &str) -> Option<usize> {
        self.by_id.get(id).copied()
    }

    /// `i`: posición de la conversación en la sesión.
    fn keep_flow(&self, i: usize) -> bool {
        let f = &self.l.flows[i];
        (self.show_noise || !f.is_background_noise)
            && (!self.important || self.l.explanations[i].level > Level::Ok)
            && matches(&self.expr, f)
    }

    fn keep(&self, id: &str) -> bool {
        self.flow(id).is_some_and(|i| self.keep_flow(i))
    }
}

/// Página de la lista global de paquetes.
fn packets_page(l: &Loaded, req: &Request) -> Response {
    let sel = match ViewFilter::from_request(l, req) {
        Ok(f) => f,
        Err(resp) => return resp,
    };
    let num = |k: &str, d: usize| req.query_param(k).and_then(|v| v.parse().ok()).unwrap_or(d);
    let (offset, limit) = (num("offset", 0), num("limit", 200).min(MAX_PAGE));
    let keep = |id: &str| sel.keep(id);
    let Ok(idx) = l.packets.read() else {
        return lock_err();
    };
    let (rows, total) = idx.page(
        offset,
        limit,
        sel.active().then_some(&keep as &dyn Fn(&str) -> bool),
    );
    let rows: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let flow = r.flow_id.as_deref().and_then(|id| sel.flow(id));
            let level = flow.map(|i| l.explanations[i].level);
            let mut v = serde_json::to_value(r).unwrap_or(Value::Null);
            v["flow"] = json!(flow);
            v["level"] = json!(level);
            v
        })
        .collect();
    Response::json(
        200,
        &json!({ "packets": rows, "total": total, "offset": offset }),
    )
}

fn handle(mut stream: TcpStream, server: &Arc<Server>) {
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(60))).ok();
    let resp = match read_request(&mut stream, MAX_UPLOAD) {
        Ok(req) => server.route(&req),
        Err(ReadError::Bad(status, msg)) => Response::error(status, msg),
        Err(ReadError::Io) => return,
    };
    write_response(&mut stream, &resp).ok();
}

/// Atiende conexiones para siempre, una por hilo.
fn serve(listener: TcpListener, server: Arc<Server>) {
    for stream in listener.incoming().flatten() {
        let server = Arc::clone(&server);
        std::thread::spawn(move || handle(stream, &server));
    }
}

fn bind(port: Option<u16>) -> Result<TcpListener> {
    let try_port = |p: u16| TcpListener::bind(("127.0.0.1", p));
    match port {
        Some(p) => try_port(p).with_context(|| format!("no se pudo usar el puerto {p}")),
        None => match try_port(DEFAULT_PORT) {
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                try_port(0).context("no se pudo abrir ningún puerto local")
            }
            other => other.context("no se pudo abrir el puerto local"),
        },
    }
}

/// Abre la interfaz en una ventana propia si hay Edge o Chrome (modo app,
/// sin barra del navegador); si no, en el navegador por defecto.
fn open_window(url: &str) {
    use std::process::Command;
    #[cfg(windows)]
    {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let candidates = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe".to_string(),
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe".to_string(),
            r"C:\Program Files\Google\Chrome\Application\chrome.exe".to_string(),
            format!(r"{local}\Google\Chrome\Application\chrome.exe"),
        ];
        for exe in candidates.iter().filter(|p| Path::new(p).exists()) {
            let app = format!("--app={url}");
            if Command::new(exe)
                .args([app.as_str(), "--window-size=1440,900"])
                .spawn()
                .is_ok()
            {
                return;
            }
        }
        let _ = Command::new("cmd").args(["/C", "start", "", url]).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg(url).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
}

/// `socshark gui`: analiza (si se indicó) la captura, sirve la interfaz y
/// abre la ventana. Termina con Ctrl-C.
pub fn run(opts: GuiOptions) -> Result<()> {
    let listener = bind(opts.port)?;
    let port = listener.local_addr()?.port();
    let mut server = Server::new(port, opts.cfg.clone());
    if opts.cfg.intel_feodo.is_some() || opts.cfg.intel_tor.is_some() {
        server.intel = Some(
            ThreatIntelDb::from_paths(
                opts.cfg.intel_feodo.as_deref(),
                opts.cfg.intel_tor.as_deref(),
            )
            .context("no se pudo cargar la lista de threat intel")?,
        );
    }
    let server = Arc::new(server);
    if let Some(path) = &opts.read {
        let name = display_name(&path.to_string_lossy());
        server.replace_session(load(path, name, &opts.cfg)?);
    }
    let url = format!("http://127.0.0.1:{port}/");
    eprintln!("[+] Interfaz lista en {url}  ·  Ctrl+C para cerrar");
    if opts.open {
        open_window(&url);
    } else {
        eprintln!("    Ábrela en tu navegador (no se abrió sola por --no-open).");
    }
    serve(listener, server);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_testgen::{sample_pcap_packets, write_pcap};
    use std::io::{Read, Write};

    fn demo_server() -> (Arc<Server>, PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "socshark-gui-test-{}-{:?}.pcap",
            std::process::id(),
            std::thread::current().id()
        ));
        write_pcap(&path, 1, &sample_pcap_packets()).unwrap();
        let cfg = PipelineConfig {
            file_carving: true,
            ..PipelineConfig::default()
        };
        let server = Arc::new(Server::new(8787, cfg.clone()));
        server.replace_session(load(&path, "demo.pcap".into(), &cfg).unwrap());
        (server, path)
    }

    fn call(server: &Arc<Server>, method: &str, path: &str, token: Option<&str>) -> Response {
        let (p, q) = path.split_once('?').unwrap_or((path, ""));
        let mut headers = vec![("Host".to_string(), "127.0.0.1:8787".to_string())];
        if let Some(t) = token {
            headers.push(("X-Socshark-Token".into(), t.into()));
        }
        server.route(&Request {
            method: method.into(),
            path: p.into(),
            query: q.into(),
            headers,
            body: vec![],
        })
    }

    fn get(server: &Arc<Server>, path: &str, token: Option<&str>, host: &str) -> (u16, Value) {
        let (p, q) = path.split_once('?').unwrap_or((path, ""));
        let mut headers = vec![("Host".to_string(), host.to_string())];
        if let Some(t) = token {
            headers.push(("X-Socshark-Token".into(), t.into()));
        }
        let r = server.route(&Request {
            method: "GET".into(),
            path: p.into(),
            query: q.into(),
            headers,
            body: vec![],
        });
        let v = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        (r.status, v)
    }

    #[test]
    fn seguridad_host_y_token() {
        let (s, path) = demo_server();
        let t = s.token.clone();
        assert_eq!(t.len(), 32);
        assert_ne!(t, Server::new(8787, PipelineConfig::default()).token);
        // DNS rebinding: Host ajeno, ni siquiera la página.
        assert_eq!(get(&s, "/", None, "evil.example:8787").0, 421);
        assert_eq!(
            get(&s, "/api/session", Some(&t), "evil.example:8787").0,
            421
        );
        // Sin token o con token incorrecto: 403.
        assert_eq!(get(&s, "/api/session", None, "127.0.0.1:8787").0, 403);
        assert_eq!(get(&s, "/api/session", Some("x"), "127.0.0.1:8787").0, 403);
        assert_eq!(get(&s, "/api/session", Some(&t), "localhost:8787").0, 200);
        assert_eq!(call(&s, "GET", "/api/save.pcap", None).status, 403);
        // La página lleva el token incrustado y no queda el marcador.
        let page = call(&s, "GET", "/", None);
        let html = String::from_utf8(page.body).unwrap();
        assert!(html.contains(&t) && !html.contains("__SOCSHARK_TOKEN__"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn api_de_la_demo() {
        let (s, path) = demo_server();
        let t = s.token.clone();
        let h = "127.0.0.1:8787";

        let (st, session) = get(&s, "/api/session", Some(&t), h);
        assert_eq!(st, 200);
        assert_eq!(session["packets"], 45);
        assert_eq!(session["flows"], 22);
        assert_eq!(session["generation"], 1);
        assert_eq!(session["live"], Value::Null);
        assert_eq!(
            session["levels"]["peligro"], 2,
            "túnel DNS + archivo disfrazado"
        );

        let (_, flows) = get(&s, "/api/flows", Some(&t), h);
        assert_eq!(flows["total"], 22);
        let (st, filtrados) = get(&s, "/api/flows?filter=flow.risk+%3E%3D+40", Some(&t), h);
        assert_eq!(st, 200);
        assert_eq!(filtrados["total"], 2);
        assert_eq!(filtrados["flows"][0]["explain"]["level"], "peligro");

        let (st, err) = get(&s, "/api/flows?filter=tcp.port+%3D%3D", Some(&t), h);
        assert_eq!(st, 400);
        assert_eq!(err["pos"], "tcp.port ==".len());

        // Historias: el escaneo de 12 puertos es una sola.
        let (_, stories) = get(&s, "/api/stories", Some(&t), h);
        let scans: Vec<&Value> = stories
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| s["alert_id"] == "PORT-SCAN")
            .collect();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0]["flows"].as_array().unwrap().len(), 12);

        // Paquetes de un flujo, su conversación y el detalle de uno.
        let tls = flows["flows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["flow"]["l7_protocol"] == "Tls")
            .unwrap();
        let (_, pk) = get(
            &s,
            &format!("/api/flows/{}/packets", tls["idx"]),
            Some(&t),
            h,
        );
        let rows = pk["packets"].as_array().unwrap();
        assert_eq!(rows.len(), 7);
        assert_eq!(rows[0]["summary"], "Pide abrir una conexión (SYN)");
        assert!(rows.iter().any(|r| r["summary"]
            .as_str()
            .unwrap()
            .starts_with("Saludo TLS del cliente")));
        let (st, det) = get(&s, &format!("/api/packets/{}", rows[0]["n"]), Some(&t), h);
        assert_eq!(st, 200);
        assert_eq!(det["layers"][2]["name"], "TCP");
        let (st, conv) = get(
            &s,
            &format!("/api/flows/{}/stream", tls["idx"]),
            Some(&t),
            h,
        );
        assert_eq!(st, 200);
        assert!(conv["client_bytes"].as_u64().unwrap() > 0);

        assert_eq!(get(&s, "/api/flows/9999/packets", Some(&t), h).0, 404);
        assert_eq!(get(&s, "/api/packets/0", Some(&t), h).0, 404);
        assert_eq!(get(&s, "/api/nada", Some(&t), h).0, 404);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn estadisticas_de_la_demo() {
        let (s, path) = demo_server();
        let t = s.token.clone();
        let h = "127.0.0.1:8787";

        let (st, all) = get(&s, "/api/stats", Some(&t), h);
        assert_eq!(st, 200);
        assert_eq!(all["total"]["flows"], 22);
        assert_eq!(all["total"]["packets"], 45);
        let sum = |key: &str| -> u64 {
            all["protocols"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p[key].as_u64().unwrap())
                .sum()
        };
        assert_eq!(sum("flows"), 22);
        assert_eq!(sum("bytes"), all["total"]["bytes"].as_u64().unwrap());
        // Cada conversación cuenta en sus dos extremos.
        let eps = all["endpoints"].as_array().unwrap();
        let ep_flows: u64 = eps.iter().map(|e| e["flows"].as_u64().unwrap()).sum();
        assert_eq!(ep_flows, 44);
        let bytes = |e: &Value| e["bytes_out"].as_u64().unwrap() + e["bytes_in"].as_u64().unwrap();
        assert!(eps.windows(2).all(|w| bytes(&w[0]) >= bytes(&w[1])));
        assert!(eps.iter().any(|e| e["scope"] == "local"));
        let https = all["services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["port"] == 443 && s["transport"] == "TCP")
            .expect("hay tráfico web seguro");
        assert_eq!(https["name"], "HTTPS");

        // Sin ruido y con filtro: el mismo recorte que la tabla.
        let (_, flows) = get(&s, "/api/flows?filter=flow.risk+%3E%3D+40", Some(&t), h);
        let (_, risky) = get(&s, "/api/stats?filter=flow.risk+%3E%3D+40", Some(&t), h);
        assert_eq!(risky["total"]["flows"], flows["total"]);
        let (_, session) = get(&s, "/api/session", Some(&t), h);
        let (_, quiet) = get(&s, "/api/stats?noise=0", Some(&t), h);
        assert_eq!(
            quiet["total"]["flows"].as_u64().unwrap(),
            22 - session["noise"].as_u64().unwrap()
        );
        let (st, _) = get(&s, "/api/stats?filter=tcp.port+%3D%3D", Some(&t), h);
        assert_eq!(st, 400);
        // La línea de tiempo usa el mismo recorte (y el mismo eje).
        let (_, tl_all) = get(&s, "/api/timeline", Some(&t), h);
        let (_, tl_risky) = get(&s, "/api/timeline?filter=flow.risk+%3E%3D+40", Some(&t), h);
        assert_eq!(tl_all["start_micros"], tl_risky["start_micros"]);
        let sum = |v: &Value| -> u64 {
            v["packets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap())
                .sum()
        };
        assert_eq!(sum(&tl_all), 45);
        assert_eq!(sum(&tl_risky), risky["total"]["packets"].as_u64().unwrap());
        let (st, _) = get(&s, "/api/timeline?filter=tcp.port+%3D%3D", Some(&t), h);
        assert_eq!(st, 400);
        // "Solo lo importante": raro o peligro, también en la lista de paquetes.
        let important = session["levels"]["raro"].as_u64().unwrap()
            + session["levels"]["peligro"].as_u64().unwrap();
        let (_, imp) = get(&s, "/api/stats?important=1", Some(&t), h);
        assert_eq!(imp["total"]["flows"].as_u64().unwrap(), important);
        let (_, page) = get(&s, "/api/packets?important=1&limit=1000", Some(&t), h);
        assert_eq!(page["total"], imp["total"]["packets"]);
        assert!(page["packets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["level"] != "ok"));
        // Toda fila de la tabla trae su protocolo ya nombrado.
        assert!(flows["flows"][0]["proto"].is_string());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn lista_global_linea_de_tiempo_y_guardar() {
        let (s, path) = demo_server();
        let t = s.token.clone();
        let h = "127.0.0.1:8787";

        let (_, page) = get(&s, "/api/packets?offset=0&limit=5", Some(&t), h);
        assert_eq!(page["total"], 45);
        assert_eq!(page["packets"].as_array().unwrap().len(), 5);
        assert_eq!(page["packets"][0]["n"], 1);
        assert_eq!(page["packets"][0]["level"], "ok");
        // Sin ruido (NTP, mDNS) y con filtro DSL por conversación.
        assert_eq!(get(&s, "/api/packets?noise=0", Some(&t), h).1["total"], 43);
        let (_, tls) = get(&s, "/api/packets?filter=tcp.port+%3D%3D+443", Some(&t), h);
        assert_eq!(tls["total"], 7);
        assert_eq!(get(&s, "/api/packets?filter=%3D%3D", Some(&t), h).0, 400);

        let (_, tl) = get(&s, "/api/timeline", Some(&t), h);
        let sum: u64 = tl["packets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .sum();
        assert_eq!(sum, 45);

        let r = call(&s, "GET", "/api/save.pcap", Some(&t));
        assert_eq!(r.status, 200);
        assert_eq!(r.attachment.as_deref(), Some("demo-soc-shark.pcap"));
        assert_eq!(&r.body[..4], &0xa1b2_c3d4u32.to_le_bytes());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn en_vivo_sin_interfaz_valida_da_error_legible() {
        let s = Arc::new(Server::new(8787, PipelineConfig::default()));
        let t = s.token.clone();
        let r = call(&s, "POST", "/api/live/start", Some(&t));
        assert_eq!(r.status, 400, "falta la interfaz");
        let r = call(
            &s,
            "POST",
            "/api/live/start?iface=socshark-no-existe-99",
            Some(&t),
        );
        assert_eq!(r.status, 400);
        assert!(!String::from_utf8_lossy(&r.body).is_empty());
        // Detener sin captura en marcha no falla.
        assert_eq!(call(&s, "POST", "/api/live/stop", Some(&t)).status, 200);
        assert_eq!(call(&s, "GET", "/api/live/start", Some(&t)).status, 405);
    }

    #[test]
    fn abrir_desde_la_ventana_y_errores_legibles() {
        let s = Arc::new(Server::new(8787, PipelineConfig::default()));
        let t = s.token.clone();
        let post = |body: Vec<u8>, name: &str| {
            s.route(&Request {
                method: "POST".into(),
                path: "/api/open".into(),
                query: format!("name={name}"),
                headers: vec![
                    ("Host".into(), "127.0.0.1:8787".into()),
                    ("X-Socshark-Token".into(), t.clone()),
                ],
                body,
            })
        };
        // Sin captura aún: la sesión lo dice y la API de datos da 404.
        assert_eq!(
            get(&s, "/api/session", Some(&t), "127.0.0.1:8787").1["loaded"],
            false
        );
        assert_eq!(get(&s, "/api/flows", Some(&t), "127.0.0.1:8787").0, 404);

        let r = post(b"esto no es un pcap".to_vec(), "x.pcapng");
        assert_eq!(r.status, 400);
        let msg = String::from_utf8_lossy(&r.body).to_string();
        assert!(msg.contains("no es un pcap clásico"), "{msg}");
        assert!(
            !msg.contains("socshark-gui-"),
            "sin rutas temporales: {msg}"
        );

        let path =
            std::env::temp_dir().join(format!("socshark-gui-up-{}.pcap", std::process::id()));
        write_pcap(&path, 1, &sample_pcap_packets()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).ok();
        let r = post(bytes, "C%3A%5Ccapturas%5Coficina.pcap");
        assert_eq!(r.status, 200);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["name"], "oficina.pcap", "sin la ruta del cliente");
        assert_eq!(v["packets"], 45);
    }

    #[test]
    fn servidor_real_sobre_tcp() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let s = Arc::new(Server::new(port, PipelineConfig::default()));
        let token = s.token.clone();
        std::thread::spawn(move || serve(listener, s));

        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(
            c,
            "GET /api/session HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Socshark-Token: {token}\r\n\r\n"
        )
        .unwrap();
        let mut resp = String::new();
        c.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
        assert!(resp.contains("Content-Security-Policy: default-src 'none'"));
        assert!(resp.contains("\"loaded\":false"));
    }

    #[test]
    fn la_captura_en_vivo_excluye_el_trafico_de_la_propia_ventana() {
        let s = Server::new(8787, PipelineConfig::default());
        assert_eq!(s.live_bpf(None), "not (tcp port 8787 and host 127.0.0.1)");
        assert_eq!(
            s.live_bpf(Some("udp port 53")),
            "(udp port 53) and not (tcp port 8787 and host 127.0.0.1)"
        );
    }

    #[test]
    fn nombres_subidos_sin_rutas_ni_control() {
        assert_eq!(display_name(r"C:\Users\x\red.pcap"), "red.pcap");
        assert_eq!(display_name("/tmp/a/b.pcap"), "b.pcap");
        assert_eq!(display_name("mal\u{7}o.pcap"), "malo.pcap");
        assert_eq!(display_name(""), "captura.pcap");
        assert_eq!(display_name(&"a".repeat(500)).len(), 100);
    }
}
