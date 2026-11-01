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
//!
//! Idioma (ADR-015): la ventana manda el suyo en la cabecera
//! `X-Socshark-Lang` (o `?lang=`) y las frases, los paquetes y el informe
//! se cuentan en ese idioma. Los datos (flujos, `alert.id`, niveles) son
//! los mismos en los dos.

mod http;
mod live;
mod names;
pub mod packets;

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use socshark_capture::{CaptureSource, LiveBreaker, LiveCapture, LiveCaptureConfig};
use socshark_core::config::PipelineConfig;
use socshark_core::{EnrichedFlow, L7Protocol, Transport};
use socshark_flow::PipelineStats;
use socshark_soc::explain::{
    explain_in, service_by_port_in, stories_in, Explanation, Level, Story,
};
use socshark_soc::hosts::{term_in, HostDirectory};
use socshark_soc::{Lang, ThreatIntelDb};

use crate::pipeline::run_capture;
use http::{read_body, read_head, write_response, ReadError, Request, Response};
use live::LiveInfo;
use names::{clean_nickname, Nicknames};
use packets::PacketIndex;

const INDEX_HTML: &str = include_str!("../../assets/gui/index.html");
const APP_JS: &str = include_str!("../../assets/gui/app.js");
const I18N_JS: &str = include_str!("../../assets/gui/i18n.js");
const APP_CSS: &str = include_str!("../../assets/gui/app.css");

/// Puerto por defecto; si está ocupado se usa uno libre cualquiera.
pub const DEFAULT_PORT: u16 = 8787;
/// Tamaño máximo de una captura abierta desde la ventana.
const MAX_UPLOAD: usize = 512 * 1024 * 1024;
/// Cuerpo máximo de cualquier otra petición (apodos, etc.).
const MAX_SMALL_BODY: usize = 64 * 1024;
/// Conexiones simultáneas como mucho; las demás se cierran con un 503.
const MAX_CONNS: usize = 64;
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

/// Frases de una captura en un idioma.
struct Texts {
    explanations: Vec<Explanation>,
    stories: Vec<Story>,
}

impl Texts {
    fn new(flows: &[EnrichedFlow], hosts: &HostDirectory, lang: Lang) -> Self {
        Self {
            explanations: flows.iter().map(|f| explain_in(f, hosts, lang)).collect(),
            stories: stories_in(flows, hosts, lang),
        }
    }
}

/// Captura analizada y lista para la interfaz.
pub(crate) struct Loaded {
    name: String,
    flows: Vec<EnrichedFlow>,
    /// En español (el de referencia): siempre, también para los niveles.
    explanations: Vec<Explanation>,
    stories: Vec<Story>,
    /// En inglés: se calculan la primera vez que la ventana las pide.
    english: OnceLock<Texts>,
    stats: PipelineStats,
    packets: Arc<RwLock<PacketIndex>>,
    live: Option<LiveInfo>,
    /// Quién es quién: nombres, fabricante, router, apodos.
    hosts: HostDirectory,
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
        hosts: HostDirectory,
    ) -> Self {
        let es = Texts::new(&flows, &hosts, Lang::Es);
        Self {
            explanations: es.explanations,
            stories: es.stories,
            english: OnceLock::new(),
            name,
            flows,
            stats,
            packets,
            live,
            hosts,
            generation: 0,
        }
    }

    /// Frases y historias en el idioma dado (los niveles no cambian).
    fn texts(&self, lang: Lang) -> (&[Explanation], &[Story]) {
        match lang {
            Lang::Es => (&self.explanations, &self.stories),
            Lang::En => {
                let t = self
                    .english
                    .get_or_init(|| Texts::new(&self.flows, &self.hosts, Lang::En));
                (&t.explanations, &t.stories)
            }
        }
    }

    /// La misma captura con otros nombres (al poner o quitar un apodo).
    fn renamed(&self, hosts: HostDirectory) -> Self {
        Self::new(
            self.name.clone(),
            self.flows.clone(),
            self.stats,
            Arc::clone(&self.packets),
            self.live.clone(),
            hosts,
        )
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
    /// Conexiones atendiéndose ahora mismo (ver [`MAX_CONNS`]).
    conns: AtomicUsize,
    /// Hay una captura subiéndose: solo se admite una a la vez.
    uploading: AtomicBool,
    /// Apodos de los equipos (en disco salvo en tests).
    nicknames: Mutex<Nicknames>,
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
    // Algo más de entropía barata: la dirección de una reserva en el heap
    // (ASLR) y el hilo actual.
    let heap = Box::new(0u8);
    let addr = &*heap as *const u8 as usize;
    let thread = format!("{:?}", std::thread::current().id());
    (0..2u8)
        .map(|i| {
            let mut h = RandomState::new().build_hasher();
            h.write_u8(i);
            h.write_u128(now);
            h.write_u32(std::process::id());
            h.write_usize(addr);
            h.write(thread.as_bytes());
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

/// Idioma que pide la ventana: cabecera `X-Socshark-Lang` o `?lang=`.
fn req_lang(req: &Request) -> Lang {
    req.header("x-socshark-lang")
        .map(str::to_string)
        .or_else(|| req.query_param("lang"))
        .map_or(Lang::Es, |c| Lang::from_code(&c))
}

/// Mensaje de error de la API en el idioma de la ventana.
fn err_in(status: u16, lang: Lang, es: &str, en: &str) -> Response {
    Response::error(status, lang.pick(es, en))
}

/// Los errores del filtro DSL, en inglés si la ventana lo pide. El
/// analizador los da en español; aquí se traducen sus plantillas.
fn filter_message_in(message: &str, lang: Lang) -> String {
    if lang == Lang::Es {
        return message.to_string();
    }
    let fixed = [
        (
            "la expresión termina antes de tiempo",
            "the expression ends too early",
        ),
        ("se esperaba ')'", "expected ')'"),
        (
            "el lado izquierdo debe ser un campo (p. ej. ip.src)",
            "the left-hand side must be a field (e.g. ip.src)",
        ),
        (
            "se esperaba '&&' (un solo '&' no es válido)",
            "expected '&&' (a single '&' is not valid)",
        ),
        (
            "se esperaba '||' (un solo '|' no es válido)",
            "expected '||' (a single '|' is not valid)",
        ),
        (
            "escape incompleto al final de la cadena",
            "incomplete escape at the end of the string",
        ),
        ("cadena sin cerrar", "unterminated string"),
    ];
    if let Some((_, en)) = fixed.iter().find(|(es, _)| *es == message) {
        return en.to_string();
    }
    let templates = [
        (
            "expresión demasiado larga (máximo ",
            "expression too long (maximum ",
        ),
        ("token inesperado ", "unexpected token "),
        (
            "anidamiento demasiado profundo (máximo ",
            "nesting too deep (maximum ",
        ),
        (
            "se esperaba un campo, encontrado ",
            "expected a field, found ",
        ),
        (
            "se esperaba un valor, encontrado ",
            "expected a value, found ",
        ),
        ("el valor ", "the value "),
        ("carácter inesperado ", "unexpected character "),
    ];
    for (es, en) in templates {
        if let Some(rest) = message.strip_prefix(es) {
            let rest = rest
                .replace(" niveles)", " levels)")
                .replace(
                    " tras el final de la expresión",
                    " after the end of the expression",
                )
                .replace(
                    " no es una expresión válida por sí sola",
                    " is not a valid expression on its own",
                );
            return format!("{en}{rest}");
        }
    }
    message.to_string()
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
            conns: AtomicUsize::new(0),
            uploading: AtomicBool::new(false),
            nicknames: Mutex::new(Nicknames::in_memory()),
        }
    }

    /// Analiza una captura de archivo con el pipeline completo (ruido
    /// incluido: la interfaz decide si lo muestra) y prepara su índice de
    /// paquetes, que de paso aprende quién es quién.
    fn load(&self, path: &Path, name: String) -> Result<Loaded> {
        let out = run_capture(path, None, true, &self.cfg)?;
        let packets = PacketIndex::build(path)?;
        let hosts = self.directory(&packets, &[]);
        Ok(Loaded::new(
            name,
            out.flows,
            out.stats,
            Arc::new(RwLock::new(packets)),
            None,
            hosts,
        ))
    }

    /// Quién es quién según el índice, con este ordenador y los apodos.
    pub(crate) fn directory(&self, index: &PacketIndex, this_computer: &[IpAddr]) -> HostDirectory {
        let mut hosts = index.hosts.directory();
        hosts.mark_this_computer(this_computer);
        if let Ok(n) = self.nicknames.lock() {
            hosts.apply_nicknames(n.map());
        }
        hosts
    }

    /// `POST /api/hosts/nick?key=mac:…|ip:…&name=…` (nombre vacío = quitar).
    fn set_nickname(&self, req: &Request) -> Response {
        let Some(key) = req
            .query_param("key")
            .and_then(|k| HostDirectory::valid_key(&k))
        else {
            return err_in(400, req_lang(req), "equipo no válido", "invalid device");
        };
        let nickname = clean_nickname(&req.query_param("name").unwrap_or_default());
        let saved = match self.nicknames.lock() {
            Ok(mut n) => n.set(key, nickname),
            Err(_) => return lock_err(),
        };
        if let Err(e) = saved {
            return Response::error(500, &format!("no se pudo guardar el apodo: {e}"));
        }
        // Las frases llevan los nombres: se rehacen (en vivo, la próxima
        // foto ya los trae igualmente).
        let renamed = self.with_session_ref(|l| {
            let mut hosts = l.hosts.clone();
            if let Ok(n) = self.nicknames.lock() {
                hosts.apply_nicknames(n.map());
            }
            l.renamed(hosts)
        });
        if let Some(l) = renamed {
            self.replace_session(l);
        }
        self.with_session(|s| Response::json(200, &session_json(s)))
    }

    fn with_session_ref<T>(&self, f: impl FnOnce(&Loaded) -> T) -> Option<T> {
        self.session.read().ok().and_then(|s| s.as_ref().map(f))
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

    /// Host y token: se comprueba con solo la cabecera leída, antes de
    /// aceptar ningún cuerpo (ver [`handle`]).
    fn authorize(&self, req: &Request) -> Result<(), Response> {
        // Antes que nada: solo peticiones dirigidas a este servidor local.
        match req.header("host") {
            Some(h) if self.host_ok.iter().any(|ok| ok.eq_ignore_ascii_case(h)) => {}
            _ => return Err(Response::error(421, "host no permitido")),
        }
        if req.path.starts_with("/api/") {
            match req.header("x-socshark-token") {
                Some(t) if same(t, &self.token) => {}
                _ => return Err(Response::error(403, "token de sesión ausente o incorrecto")),
            }
        }
        Ok(())
    }

    fn route(self: &Arc<Self>, req: &Request) -> Response {
        if let Err(resp) = self.authorize(req) {
            return resp;
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
                ("GET", "/i18n.js") => {
                    Response::new(200, "text/javascript; charset=utf-8", I18N_JS)
                }
                ("GET", "/app.css") => Response::new(200, "text/css; charset=utf-8", APP_CSS),
                _ => Response::error(404, "no existe"),
            };
        }

        let parts: Vec<&str> = path.trim_start_matches("/api/").split('/').collect();
        let lang = req_lang(req);
        match (req.method.as_str(), parts.as_slice()) {
            ("GET", ["session"]) => self.with_session(|s| Response::json(200, &session_json(s))),
            ("GET", ["stories"]) => self.with_loaded(lang, |l| {
                Response::json(
                    200,
                    &serde_json::to_value(l.texts(lang).1).unwrap_or(Value::Null),
                )
            }),
            ("GET", ["flows"]) => {
                self.with_loaded(lang, |l| flows_json(l, req.query_param("filter"), lang))
            }
            ("GET", ["flows", i, what @ ("packets" | "stream")]) => self.with_loaded(lang, |l| {
                let Some(flow) = i.parse::<usize>().ok().and_then(|i| l.flows.get(i)) else {
                    return err_in(404, lang, "flujo inexistente", "no such conversation");
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
                let (rows, more) = idx.list(flow, lang);
                Response::json(
                    200,
                    &json!({ "packets": rows, "more": more, "truncated": idx.truncated }),
                )
            }),
            ("GET", ["packets"]) => self.with_loaded(lang, |l| packets_page(l, req, lang)),
            ("GET", ["stats"]) => self.with_loaded(lang, |l| stats_json(l, req, lang)),
            ("GET", ["map"]) => self.with_loaded(lang, |l| map_json(l, req, lang)),
            ("GET", ["report.html"]) => self.with_loaded(lang, |l| {
                // La ventana dice su zona horaria (minutos respecto a UTC).
                let tz = req
                    .query_param("tz")
                    .and_then(|v| v.parse::<i32>().ok())
                    .filter(|m| m.abs() <= 14 * 60)
                    .unwrap_or(0);
                let (explanations, stories) = l.texts(lang);
                let html = crate::report::render(&crate::report::ReportInput {
                    name: &l.name,
                    flows: &l.flows,
                    explanations,
                    stories,
                    hosts: &l.hosts,
                    packets: l.stats.total_packets,
                    tz_offset_minutes: tz,
                    generated_micros: live::now_micros(),
                    lang,
                });
                let base = save_name(l).trim_end_matches(".pcap").to_string();
                Response::download(
                    &format!("{}-{base}.html", lang.pick("informe", "report")),
                    "text/html; charset=utf-8",
                    html.into_bytes(),
                )
            }),
            ("GET", ["hosts"]) => self.with_loaded(lang, |l| {
                Response::json(
                    200,
                    &json!(l
                        .hosts
                        .hosts()
                        .iter()
                        .map(|h| host_json(h, lang))
                        .collect::<Vec<_>>()),
                )
            }),
            ("POST", ["hosts", "nick"]) => self.set_nickname(req),
            ("GET", ["packets", n]) => self.with_loaded(lang, |l| {
                let Ok(idx) = l.packets.read() else {
                    return lock_err();
                };
                match n.parse::<usize>().ok().and_then(|n| idx.detail(n, lang)) {
                    Some(d) => Response::json(200, &serde_json::to_value(d).unwrap_or(Value::Null)),
                    None => err_in(404, lang, "paquete inexistente", "no such packet"),
                }
            }),
            ("GET", ["timeline"]) => {
                self.with_loaded(lang, |l| {
                    let sel = match ViewFilter::from_request(l, req, lang) {
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
            ("GET", ["save.pcap"]) => self.with_loaded(lang, |l| match l.packets.read() {
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
                        .map(|i| json!({
                            "name": i.name,
                            "description": i.description,
                            "addresses": i.addresses,
                            "loopback": i.loopback,
                            "up": i.up,
                            "wireless": i.wireless,
                            "connected": i.connected,
                        }))
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
                ["session" | "stories" | "flows" | "packets" | "stats" | "map" | "hosts"
                | "timeline" | "save.pcap" | "report.html" | "live" | "open", ..],
            ) => err_in(405, lang, "método no permitido", "method not allowed"),
            _ => err_in(404, lang, "no existe", "not found"),
        }
    }

    fn with_session(&self, f: impl FnOnce(Option<&Loaded>) -> Response) -> Response {
        match self.session.read() {
            Ok(s) => f(s.as_ref()),
            Err(_) => lock_err(),
        }
    }

    fn with_loaded(&self, lang: Lang, f: impl FnOnce(&Loaded) -> Response) -> Response {
        self.with_session(|s| match s {
            Some(l) => f(l),
            None => err_in(
                404,
                lang,
                "no hay ninguna captura abierta",
                "no capture is open",
            ),
        })
    }

    /// Empieza a capturar en vivo de una interfaz (detiene la anterior).
    fn start_live(self: &Arc<Self>, req: &Request) -> Response {
        let lang = req_lang(req);
        let Some(iface) = req.query_param("iface").filter(|i| !i.trim().is_empty()) else {
            return err_in(400, lang, "falta la interfaz", "the interface is missing");
        };
        let bpf = req.query_param("bpf").filter(|b| !b.trim().is_empty());
        if !bpf.as_deref().map(parens_balanced).unwrap_or(true) {
            // `tcp) or (udp` escaparía del paréntesis de `live_bpf` y anularía
            // la exclusión del tráfico de la propia ventana.
            return err_in(
                400,
                lang,
                "el filtro BPF tiene paréntesis desequilibrados",
                "the BPF filter has unbalanced parentheses",
            );
        }
        self.stop_live();
        let open = |filter: Option<String>| {
            LiveCapture::open(LiveCaptureConfig {
                // Tick frecuente: la ventana responde rápido a "Detener".
                timeout_ms: 250,
                ..LiveCaptureConfig::new(iface.clone()).with_bpf(filter)
            })
        };
        // Interfaces que no son IP (NFLOG, Bluetooth, USB…) no admiten el
        // filtro que oculta la propia ventana; tampoco llevan su tráfico, así
        // que se reintenta solo con el del usuario.
        let source = match open(Some(self.live_bpf(bpf.as_deref()))).or_else(|_| open(bpf.clone()))
        {
            Ok(s) => s,
            Err(e) => return Response::error(400, &e.to_string()),
        };
        let index = Arc::new(RwLock::new(PacketIndex::new(source.link_type(), true)));
        // Las direcciones de esta máquina: «este ordenador» y, para su
        // tráfico, qué programa abrió cada conexión.
        let mut local_addrs: Vec<IpAddr> = socshark_capture::list_ifaces()
            .map(|l| l.into_iter().flat_map(|i| i.addresses).collect())
            .unwrap_or_default();
        local_addrs.sort();
        local_addrs.dedup();
        let info = LiveInfo {
            iface: iface.clone(),
            bpf,
            running: true,
            started_micros: live::now_micros(),
            kernel_recv: 0,
            kernel_drop: 0,
            error: None,
            local_addrs,
        };
        let hosts = self.directory(
            &PacketIndex::new(source.link_type(), true),
            &info.local_addrs,
        );
        self.replace_session(Loaded::new(
            format!("En vivo · {iface}"),
            Vec::new(),
            PipelineStats::default(),
            Arc::clone(&index),
            Some(info.clone()),
            hosts,
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
            return err_in(
                400,
                req_lang(req),
                "el archivo está vacío",
                "the file is empty",
            );
        }
        self.stop_live();
        let name = display_name(&req.query_param("name").unwrap_or_default());
        let tmp = match self.write_temp(&req.body) {
            Ok(tmp) => tmp,
            Err(e) => return Response::error(500, &format!("{e:#}")),
        };
        let result = self.load(&tmp, name);
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

    /// Guarda la subida en un archivo temporal NUEVO: nombre con parte
    /// aleatoria y `create_new` (nunca sigue un enlace simbólico ni pisa un
    /// archivo que otro usuario haya plantado en el temporal compartido) y,
    /// en Unix, permisos 0600.
    fn write_temp(&self, body: &[u8]) -> Result<PathBuf> {
        use std::io::Write;
        let mut last_err = None;
        for _ in 0..16 {
            let seq = self.upload_seq.fetch_add(1, Ordering::Relaxed);
            let tmp = std::env::temp_dir().join(format!(
                "socshark-gui-{}-{seq}-{}.pcap",
                std::process::id(),
                &new_token()[..16]
            ));
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            match opts.open(&tmp) {
                Ok(mut f) => {
                    let written = f.write_all(body).and_then(|_| f.flush());
                    if let Err(e) = written {
                        drop(f);
                        std::fs::remove_file(&tmp).ok();
                        return Err(e).context("no se pudo guardar el archivo temporal");
                    }
                    return Ok(tmp);
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => last_err = Some(e),
                Err(e) => return Err(e).context("no se pudo guardar el archivo temporal"),
            }
        }
        Err(last_err.expect("al menos un intento"))
            .context("no se pudo crear un archivo temporal nuevo")
    }
}

/// `true` si los paréntesis del filtro BPF están equilibrados (nunca se
/// cierra uno que no se abrió y no queda ninguno abierto).
fn parens_balanced(bpf: &str) -> bool {
    let mut depth = 0usize;
    for c in bpf.chars() {
        match c {
            '(' => depth += 1,
            ')' => match depth.checked_sub(1) {
                Some(d) => depth = d,
                None => return false,
            },
            _ => {}
        }
    }
    depth == 0
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
fn parse_filter(
    filter: Option<String>,
    lang: Lang,
) -> Result<Option<socshark_filter::Expr>, Response> {
    let filter = filter.filter(|f| !f.trim().is_empty());
    match filter.as_deref().map(socshark_filter::parse).transpose() {
        Ok(e) => Ok(e),
        Err(e) => Err(Response::json(
            400,
            &json!({ "error": filter_message_in(&e.message, lang), "pos": e.pos, "filter": filter }),
        )),
    }
}

fn matches(expr: &Option<socshark_filter::Expr>, flow: &EnrichedFlow) -> bool {
    match expr {
        Some(e) => socshark_filter::eval(e, flow),
        None => true,
    }
}

fn flows_json(l: &Loaded, filter: Option<String>, lang: Lang) -> Response {
    let expr = match parse_filter(filter, lang) {
        Ok(e) => e,
        Err(resp) => return resp,
    };
    let (explanations, _) = l.texts(lang);
    let matching: Vec<usize> = (0..l.flows.len())
        .filter(|&i| matches(&expr, &l.flows[i]))
        .collect();
    let rows: Vec<FlowRow> = matching
        .iter()
        .take(MAX_FLOWS)
        .map(|&i| {
            let f = &l.flows[i];
            let short = |ip| l.hosts.get(ip).and_then(|h| h.short_in(lang));
            let flow = if lang == Lang::Es {
                Cow::Borrowed(f)
            } else {
                // Solo la vista: el JSONL sigue llevando el resumen en español.
                let mut copy = f.clone();
                copy.human_summary = socshark_soc::summarize::summarize_in(f, lang);
                Cow::Owned(copy)
            };
            FlowRow {
                idx: i,
                proto: proto_name(f),
                src_name: short(f.src_ip),
                dst_name: short(f.dst_ip),
                flow,
                explain: &explanations[i],
            }
        })
        .collect();
    Response::json_of(
        200,
        &FlowsPage {
            total: matching.len(),
            truncated: matching.len() > MAX_FLOWS,
            flows: rows,
        },
    )
}

/// Una fila de `/api/flows`: se serializa tal cual, prestando el flujo y su
/// explicación (sin copiarlos a un árbol `Value`).
#[derive(serde::Serialize)]
struct FlowRow<'a> {
    idx: usize,
    proto: &'static str,
    src_name: Option<String>,
    dst_name: Option<String>,
    flow: Cow<'a, EnrichedFlow>,
    explain: &'a Explanation,
}

#[derive(serde::Serialize)]
struct FlowsPage<'a> {
    flows: Vec<FlowRow<'a>>,
    total: usize,
    truncated: bool,
}

/// Un equipo del directorio para la ventana: lo que se sabe de él, su
/// nombre corto y la clave con la que se le pone apodo. Las palabras
/// (a qué suele corresponder la marca, qué es, el sistema) van en el
/// idioma de la ventana.
fn host_json(h: &socshark_soc::hosts::HostInfo, lang: Lang) -> Value {
    let mut v = serde_json::to_value(h).unwrap_or(Value::Null);
    v["key"] = json!(h.key());
    v["short"] = json!(h.short_in(lang));
    v["scope"] = json!(ip_scope(&h.ip));
    if lang != Lang::Es {
        v["vendor_hint"] = json!(h.vendor_hint.map(|t| term_in(t, lang)));
        v["kind"] = json!(h.kind.map(|t| term_in(t, lang)));
        v["os"] = json!(h.os.map(|t| term_in(t, lang)));
    }
    v
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
        // x.x.x.255 privada: la difusión de una red /24 (la de casa).
        IpAddr::V4(v4)
            if v4.is_multicast()
                || v4.is_broadcast()
                || (v4.is_private() && v4.octets()[3] == 255) =>
        {
            "grupo"
        }
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
fn stats_json(l: &Loaded, req: &Request, lang: Lang) -> Response {
    let sel = match ViewFilter::from_request(l, req, lang) {
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
            // 0.0.0.0: un equipo que aún pide dirección; aparece luego con la suya.
            if ip.is_unspecified() {
                continue;
            }
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
                "host": l.hosts.get(*ip).map(|h| host_json(h, lang)),
            })).collect::<Vec<_>>(),
            "services_total": services.len(),
            "services": services.iter().take(MAX_STATS_ROWS).map(|((port, tr), s)| {
                let known = service_by_port_in(*port, *tr, lang);
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
    fn from_request(l: &'a Loaded, req: &Request, lang: Lang) -> Result<Self, Response> {
        Ok(Self {
            l,
            by_id: l
                .flows
                .iter()
                .enumerate()
                .map(|(i, f)| (f.flow_id.0.as_str(), i))
                .collect(),
            expr: parse_filter(req.query_param("filter"), lang)?,
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

/// Sitios de Internet que se dibujan por separado en el mapa (el resto se
/// agrupa en «otros sitios»).
const MAP_MAX_EXTERNAL: usize = 12;
/// Equipos de la red local que se dibujan como mucho.
const MAP_MAX_LOCAL: usize = 40;

/// Icono de un equipo en el mapa, por lo que se sabe de él.
fn map_icon(h: Option<&socshark_soc::hosts::HostInfo>, ip: &IpAddr) -> &'static str {
    use socshark_soc::hosts::Role;
    if ip.is_loopback() {
        return "computer";
    }
    let Some(h) = h else { return "device" };
    match h.role {
        Some(Role::Router) => return "router",
        Some(Role::ThisComputer) => return "computer",
        None => {}
    }
    let hint = h.vendor_hint.unwrap_or("");
    // El nombre que el equipo se pone suele decir qué es.
    let name = h.name.as_deref().unwrap_or("").to_lowercase();
    let named = |words: &[&str]| words.iter().any(|w| name.contains(w));
    if named(&[
        "iphone", "ipad", "android", "galaxy", "pixel", "redmi", "xiaomi", "huawei", "movil",
        "móvil", "phone",
    ]) {
        return "phone";
    }
    if named(&[
        "desktop-",
        "laptop",
        "portatil",
        "portátil",
        "macbook",
        "imac",
        "-pc",
        "thinkpad",
    ]) {
        return "computer";
    }
    if named(&["tv", "tele", "chromecast", "roku", "firestick"]) {
        return "tv";
    }
    match h.kind.unwrap_or("") {
        "la impresora" => "printer",
        "el Chromecast" | "el Fire TV" | "el dispositivo AirPlay" => "tv",
        "el altavoz" => "speaker",
        "el ordenador" => "computer",
        _ if hint.contains("impresora") => "printer",
        _ if hint.contains("router") || hint.contains("Wi-Fi") => "router",
        _ if hint.contains("móvil") => "phone",
        _ if hint.contains("televisión") => "tv",
        _ if h.os == Some("Windows") || hint.contains("ordenador") => "computer",
        _ if h.os == Some("Android") => "phone",
        _ => "device",
    }
}

/// El mapa de la red: equipos de casa, router, sitios de Internet y quién
/// habla con quién (con los mismos recortes que la ventana).
fn map_json(l: &Loaded, req: &Request, lang: Lang) -> Response {
    let sel = match ViewFilter::from_request(l, req, lang) {
        Ok(f) => f,
        Err(resp) => return resp,
    };
    #[derive(Default)]
    struct Acc {
        bytes: u64,
        flows: u64,
        level: Option<Level>,
    }
    impl Acc {
        fn add(&mut self, bytes: u64, level: Level) {
            self.bytes += bytes;
            self.flows += 1;
            self.level = Some(self.level.map_or(level, |l| l.max(level)));
        }
    }
    // Un extremo: equipo de casa, sitio de Internet o «toda la red».
    let resolve = |ip: IpAddr, mac: Option<&str>| -> Option<(String, &'static str)> {
        if ip.is_unspecified() {
            // Aún sin dirección (DHCP): se reconoce por su MAC si se puede.
            let h = mac.and_then(|m| l.hosts.by_mac(m))?;
            return Some((h.ip.to_string(), "local"));
        }
        Some(match ip_scope(&ip) {
            "grupo" => ("grupo".to_string(), "group"),
            "local" => (ip.to_string(), "local"),
            _ if ip.is_loopback() => (ip.to_string(), "local"),
            _ => (ip.to_string(), "internet"),
        })
    };

    // Primera pasada: cuánto mueve cada extremo, para elegir los que se dibujan.
    let kept: Vec<usize> = (0..l.flows.len()).filter(|&i| sel.keep_flow(i)).collect();
    let mut volume: HashMap<String, (u64, &'static str)> = HashMap::new();
    let mut labels: HashMap<String, String> = HashMap::new();
    for &i in &kept {
        let f = &l.flows[i];
        let bytes = f.bytes + f.bytes_rev;
        for (ip, mac) in [
            (f.src_ip, f.src_mac.as_deref()),
            (f.dst_ip, f.dst_mac.as_deref()),
        ] {
            if let Some((id, col)) = resolve(ip, mac) {
                volume.entry(id).or_insert((0, col)).0 += bytes;
            }
        }
        // Un sitio de Internet se llama por su nombre: el de la web pedida
        // (SNI) o el dominio resuelto, salvo en DNS (ahí el dominio es lo
        // que se preguntó, no quién responde), o un servidor conocido.
        let named = match f.l7_protocol {
            L7Protocol::Dns => None,
            _ => f.tls_sni.as_deref().or(f.resolved_domain.as_deref()),
        };
        if let Some(name) =
            named.or_else(|| socshark_soc::explain::well_known_name_in(f.dst_ip, lang))
        {
            labels
                .entry(f.dst_ip.to_string())
                .or_insert_with(|| name.to_string());
        }
    }
    let top = |col: &str, max: usize| -> HashSet<String> {
        let mut v: Vec<(&String, u64)> = volume
            .iter()
            .filter(|(_, (_, c))| *c == col)
            .map(|(id, (b, _))| (id, *b))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        v.into_iter().take(max).map(|(id, _)| id.clone()).collect()
    };
    let shown_ext = top("internet", MAP_MAX_EXTERNAL);
    let shown_local = top("local", MAP_MAX_LOCAL);
    let node_of = |ip: IpAddr, mac: Option<&str>| -> Option<String> {
        let (id, col) = resolve(ip, mac)?;
        Some(match col {
            "internet" if !shown_ext.contains(&id) => "internet-otros".to_string(),
            "local" if !shown_local.contains(&id) => "local-otros".to_string(),
            _ => id,
        })
    };

    // Segunda pasada: nodos y enlaces.
    let mut nodes: HashMap<String, Acc> = HashMap::new();
    let mut links: HashMap<(String, String), Acc> = HashMap::new();
    for &i in &kept {
        let f = &l.flows[i];
        let (Some(a), Some(b)) = (
            node_of(f.src_ip, f.src_mac.as_deref()),
            node_of(f.dst_ip, f.dst_mac.as_deref()),
        ) else {
            continue;
        };
        let bytes = f.bytes + f.bytes_rev;
        let level = l.explanations[i].level;
        nodes.entry(a.clone()).or_default().add(bytes, level);
        if a != b {
            nodes.entry(b.clone()).or_default().add(bytes, level);
            let key = if a <= b { (a, b) } else { (b, a) };
            links.entry(key).or_default().add(bytes, level);
        }
    }
    let hidden = |col: &str, shown: &HashSet<String>| {
        volume
            .iter()
            .filter(|(id, (_, c))| *c == col && !shown.contains(*id))
            .count()
    };
    let (hidden_ext, hidden_local) = (
        hidden("internet", &shown_ext),
        hidden("local", &shown_local),
    );
    let mut router: Option<String> = None;
    let mut out_nodes: Vec<Value> = nodes
        .iter()
        .map(|(id, acc)| {
            let ip: Option<IpAddr> = id.parse().ok();
            let host = ip.and_then(|ip| l.hosts.get(ip));
            let (column, label, icon) = match (id.as_str(), ip) {
                ("grupo", _) => (
                    "group",
                    lang.pick("Toda la red local", "The whole local network")
                        .to_string(),
                    "group",
                ),
                ("internet-otros", _) => (
                    "internet",
                    socshark_soc::tr!(lang, "{hidden_ext} sitios más", "{hidden_ext} more sites"),
                    "internet",
                ),
                ("local-otros", _) => (
                    "local",
                    socshark_soc::tr!(
                        lang,
                        "{hidden_local} equipos más",
                        "{hidden_local} more devices"
                    ),
                    "device",
                ),
                (_, Some(ip)) if ip_scope(&ip) == "internet" && !ip.is_loopback() => (
                    "internet",
                    labels.get(id).cloned().unwrap_or_else(|| id.clone()),
                    "internet",
                ),
                (_, Some(ip)) => {
                    let icon = map_icon(host, &ip);
                    let label = host.and_then(|h| h.short_in(lang)).unwrap_or_else(|| {
                        if ip.is_loopback() {
                            lang.pick("Este mismo equipo", "This same device").into()
                        } else {
                            id.clone()
                        }
                    });
                    let col = if icon == "router" && host.is_some_and(|h| h.role.is_some()) {
                        "router"
                    } else {
                        "local"
                    };
                    (col, label, icon)
                }
                _ => ("local", id.clone(), "device"),
            };
            if column == "router" {
                router = Some(id.clone());
            }
            json!({
                "id": id, "ip": ip, "label": label, "icon": icon, "column": column,
                "bytes": acc.bytes, "flows": acc.flows, "level": acc.level,
                "host": host.map(|h| host_json(h, lang)),
            })
        })
        .collect();
    out_nodes.sort_by(|a, b| {
        b["bytes"]
            .as_u64()
            .cmp(&a["bytes"].as_u64())
            .then(a["id"].as_str().cmp(&b["id"].as_str()))
    });
    let mut out_links: Vec<Value> = links
        .iter()
        .map(|((a, b), acc)| json!({ "a": a, "b": b, "bytes": acc.bytes, "flows": acc.flows, "level": acc.level }))
        .collect();
    out_links.sort_by(|x, y| y["bytes"].as_u64().cmp(&x["bytes"].as_u64()));
    Response::json(
        200,
        &json!({ "nodes": out_nodes, "links": out_links, "router": router }),
    )
}

/// Página de la lista global de paquetes.
fn packets_page(l: &Loaded, req: &Request, lang: Lang) -> Response {
    let sel = match ViewFilter::from_request(l, req, lang) {
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
        lang,
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

/// Libera la marca de "subida en curso" al terminar (también si hay error).
struct UploadSlot<'a>(&'a AtomicBool);

impl Drop for UploadSlot<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Descuenta una conexión activa al terminar su hilo.
struct ConnSlot(Arc<Server>);

impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.0.conns.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Atiende una conexión: primero la cabecera, después Host, token y ruta
/// y solo entonces el cuerpo. Así nadie sin el token de la página puede
/// hacer que el servidor reserve memoria; y solo `POST /api/open` admite un
/// cuerpo grande, de una subida en una subida.
fn handle(stream: TcpStream, server: &Arc<Server>) {
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(60))).ok();
    let Ok(write_half) = stream.try_clone() else {
        return;
    };
    let mut reader = std::io::BufReader::new(stream);
    let resp = match respond(&mut reader, server) {
        Some(resp) => resp,
        None => return,
    };
    if write_response(&write_half, &resp).is_ok() && resp.status >= 400 {
        linger_close(&write_half);
    }
}

/// Tiempo máximo que se sigue leyendo (y descartando) tras un rechazo.
const LINGER_TIME: Duration = Duration::from_secs(1);
/// Bytes máximos que se descartan tras un rechazo. Generoso a propósito:
/// si el cliente sigue mandando después del tope, el cierre vuelve a ser un
/// RST y (en Windows) se pierde la respuesta; con 1 MiB, un POST de 2 MiB
/// ya la perdía. Lo que acota el abuso es [`LINGER_TIME`]: descartar en
/// un búfer fijo no reserva memoria.
const LINGER_BYTES: usize = 16 * 1024 * 1024;

/// Cierre "con espera" tras responder a una petición rechazada sin leer su
/// cuerpo (403, 413, 421, 431...). Si se cierra el socket con datos sin
/// leer, el sistema (Windows sobre todo) manda un RST y el cliente pierde
/// la respuesta que ya estaba en camino: ve "connection reset" en vez del
/// error. Así que se cierra la escritura (FIN: la respuesta llega entera)
/// y se descarta lo que siga llegando hasta que el cliente cierre, pase
/// [`LINGER_TIME`] o se descarten [`LINGER_BYTES`], lo primero que ocurra.
/// El coste por conexión queda acotado (1 s, 16 MiB) y el número de
/// conexiones ya lo limita [`MAX_CONNS`].
fn linger_close(stream: &TcpStream) {
    use std::io::Read;
    if stream.shutdown(std::net::Shutdown::Write).is_err() {
        return;
    }
    let deadline = std::time::Instant::now() + LINGER_TIME;
    let mut buf = [0u8; 16 * 1024];
    let mut drained = 0usize;
    while drained < LINGER_BYTES {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
            break;
        }
        match (&*stream).read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

/// Lee y despacha una petición; `None` si el cliente se fue sin más.
fn respond(reader: &mut impl std::io::BufRead, server: &Arc<Server>) -> Option<Response> {
    let bad = |e: ReadError| match e {
        ReadError::Bad(status, msg) => Some(Response::error(status, msg)),
        ReadError::Io => None,
    };
    let mut req = match read_head(reader) {
        Ok(req) => req,
        Err(e) => return bad(e),
    };
    if let Err(resp) = server.authorize(&req) {
        return Some(resp);
    }
    let upload = req.method == "POST" && req.path == "/api/open";
    let _slot = if upload {
        if server
            .uploading
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Some(Response::error(503, "ya se está abriendo otra captura"));
        }
        Some(UploadSlot(&server.uploading))
    } else {
        None
    };
    let max_body = if upload { MAX_UPLOAD } else { MAX_SMALL_BODY };
    if let Err(e) = read_body(reader, &mut req, max_body) {
        return bad(e);
    }
    Some(server.route(&req))
}

/// Atiende conexiones para siempre, una por hilo y como mucho
/// [`MAX_CONNS`] a la vez: el resto recibe un 503 inmediato y se cierra.
fn serve(listener: TcpListener, server: Arc<Server>) {
    for stream in listener.incoming().flatten() {
        if server.conns.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
            server.conns.fetch_sub(1, Ordering::SeqCst);
            // Sin bloquear el bucle de aceptación: la respuesta cabe en el
            // búfer del socket; si no, se pierde y la conexión se cierra.
            stream.set_nonblocking(true).ok();
            write_response(&stream, &Response::error(503, "demasiadas conexiones")).ok();
            continue;
        }
        let slot = ConnSlot(Arc::clone(&server));
        std::thread::spawn(move || {
            handle(stream, &slot.0);
            drop(slot);
        });
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
        // Chrome y compañía se niegan a arrancar como root (sudo): entonces,
        // el navegador por defecto.
        if !running_as_root() {
            let app = format!("--app={url}");
            for exe in [
                "google-chrome",
                "google-chrome-stable",
                "chromium",
                "chromium-browser",
                "microsoft-edge",
                "brave-browser",
            ] {
                if in_path(exe)
                    && Command::new(exe)
                        .args([app.as_str(), "--window-size=1440,900"])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                        .is_ok()
                {
                    return;
                }
            }
        }
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn in_path(exe: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|dir| dir.join(exe).is_file()))
}

/// UID efectivo 0, leído de `/proc` (sin FFI).
#[cfg(all(unix, not(target_os = "macos")))]
fn running_as_root() -> bool {
    std::fs::read_to_string("/proc/self/status").is_ok_and(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|ids| ids.split_whitespace().nth(1))
            == Some("0")
    })
}

/// `socshark gui`: analiza (si se indicó) la captura, sirve la interfaz y
/// abre la ventana. Termina con Ctrl-C.
pub fn run(opts: GuiOptions) -> Result<()> {
    let listener = bind(opts.port)?;
    let port = listener.local_addr()?.port();
    let mut server = Server::new(port, opts.cfg.clone());
    server.nicknames = Mutex::new(Nicknames::load());
    if opts.cfg.intel_feodo.is_some() || opts.cfg.intel_tor.is_some() {
        let db = ThreatIntelDb::from_paths(
            opts.cfg.intel_feodo.as_deref(),
            opts.cfg.intel_tor.as_deref(),
        )
        .context("no se pudo cargar la lista de threat intel")?;
        for w in &db.warnings {
            eprintln!("[!] {w}");
        }
        server.intel = Some(db);
    }
    let server = Arc::new(server);
    if let Some(path) = &opts.read {
        let name = display_name(&path.to_string_lossy());
        server.replace_session(server.load(path, name)?);
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

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn busca_navegadores_en_el_path() {
        assert!(in_path("sh"));
        assert!(!in_path("socshark-navegador-que-no-existe"));
        // Leer el UID no falla (sea root o no).
        let _ = running_as_root();
    }

    fn server_with(packets: &[(u64, Vec<u8>)], name: &str) -> (Arc<Server>, PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "socshark-gui-test-{}-{:?}-{name}",
            std::process::id(),
            std::thread::current().id()
        ));
        write_pcap(&path, 1, packets).unwrap();
        let cfg = PipelineConfig {
            file_carving: true,
            ..PipelineConfig::default()
        };
        let server = Arc::new(Server::new(8787, cfg));
        server.replace_session(server.load(&path, name.into()).unwrap());
        (server, path)
    }

    fn demo_server() -> (Arc<Server>, PathBuf) {
        server_with(&sample_pcap_packets(), "demo.pcap")
    }

    #[test]
    fn mapa_de_la_red_de_casa() {
        let (s, path) = server_with(&socshark_testgen::home_pcap_packets(), "casa.pcap");
        let t = s.token.clone();
        let h = "127.0.0.1:8787";
        let (st, map) = get(&s, "/api/map", Some(&t), h);
        assert_eq!(st, 200);
        let nodes = map["nodes"].as_array().unwrap();
        let node = |id: &str| nodes.iter().find(|n| n["id"] == id).cloned();
        assert_eq!(map["router"], "192.168.1.1");
        let router = node("192.168.1.1").unwrap();
        assert_eq!(
            (router["column"].as_str(), router["icon"].as_str()),
            (Some("router"), Some("router"))
        );
        let printer = node("192.168.1.40").unwrap();
        assert_eq!(printer["icon"], "printer");
        assert_eq!(printer["label"], "HP OfficeJet Pro 8020");
        assert_eq!(node("192.168.1.50").unwrap()["icon"], "computer");
        assert_eq!(node("192.168.1.30").unwrap()["icon"], "phone");
        assert_eq!(node("192.168.1.60").unwrap()["icon"], "tv");
        // Internet por su nombre; los anuncios, en «toda la red».
        assert_eq!(node("8.8.8.8").unwrap()["label"], "DNS de Google");
        assert!(
            node("192.168.1.255").is_none(),
            "difusión de la red: «toda la red»"
        );
        let insta = node("157.240.5.174").unwrap();
        assert_eq!(
            (insta["column"].as_str(), insta["label"].as_str()),
            (Some("internet"), Some("www.instagram.com"))
        );
        assert_eq!(node("grupo").unwrap()["column"], "group");
        assert!(
            node("0.0.0.0").is_none(),
            "el DHCP sin dirección va al equipo por su MAC"
        );
        // El Telnet al router es el enlace marcado como peligro.
        let links = map["links"].as_array().unwrap();
        let pc_router = links
            .iter()
            .find(|l| {
                let (a, b) = (l["a"].as_str().unwrap(), l["b"].as_str().unwrap());
                (a, b) == ("192.168.1.1", "192.168.1.50")
            })
            .unwrap();
        assert_eq!(pc_router["level"], "peligro");
        // Mismos recortes que el resto: con filtro, solo lo del móvil.
        let (_, only) = get(
            &s,
            "/api/map?filter=ip.addr+%3D%3D+192.168.1.30",
            Some(&t),
            h,
        );
        assert!(only["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|n| n["id"] != "192.168.1.40"));
        let (st, _) = get(&s, "/api/map?filter=ip.addr+%3D%3D", Some(&t), h);
        assert_eq!(st, 400);
        std::fs::remove_file(path).ok();
    }

    /// Quién es quién de extremo a extremo: directorio, nombres en las
    /// frases y en las tablas, y apodos que rehacen las frases.
    #[test]
    fn quien_es_quien_y_apodos() {
        let (s, path) = server_with(&socshark_testgen::home_pcap_packets(), "casa.pcap");
        let t = s.token.clone();
        let h = "127.0.0.1:8787";

        let (st, hosts) = get(&s, "/api/hosts", Some(&t), h);
        assert_eq!(st, 200);
        let find = |ip: &str| {
            hosts
                .as_array()
                .unwrap()
                .iter()
                .find(|x| x["ip"] == ip)
                .cloned()
                .unwrap_or_else(|| panic!("{ip} en {hosts:#}"))
        };
        let phone = find("192.168.1.30");
        assert_eq!(phone["name"], "iPhone-de-Ana");
        assert_eq!(phone["random_mac"], true);
        assert!(phone["key"].as_str().unwrap().starts_with("mac:"));
        assert_eq!(find("192.168.1.1")["role"], "router");
        assert_eq!(find("192.168.1.40")["vendor"], "HP");

        let (_, flows) = get(&s, "/api/flows", Some(&t), h);
        let rows = flows["flows"].as_array().unwrap();
        assert!(rows.iter().any(|r| r["src_name"] == "iPhone-de-Ana"));
        let headlines = || -> Vec<String> {
            let (_, flows) = get(&s, "/api/flows", Some(&t), h);
            flows["flows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["explain"]["headline"].as_str().unwrap().to_string())
                .collect()
        };
        assert!(headlines().iter().any(|x| x.contains("«iPhone-de-Ana»")));

        let (_, stats) = get(&s, "/api/stats", Some(&t), h);
        let ep = stats["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["ip"] == "192.168.1.30")
            .unwrap();
        assert_eq!(ep["host"]["short"], "iPhone-de-Ana");

        // Apodo: las frases pasan a usarlo y la sesión cambia de foto.
        let (_, before) = get(&s, "/api/session", Some(&t), h);
        let key = phone["key"].as_str().unwrap();
        let r = call(
            &s,
            "POST",
            &format!("/api/hosts/nick?key={key}&name=M%C3%B3vil%20de%20Ana"),
            Some(&t),
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let (_, after) = get(&s, "/api/session", Some(&t), h);
        assert!(after["generation"].as_u64() > before["generation"].as_u64());
        assert!(headlines()
            .iter()
            .any(|x| x.contains("«Móvil de Ana» (192.168.1.30)")));
        assert!(!headlines().iter().any(|x| x.contains("iPhone-de-Ana")));
        // Quitarlo devuelve el nombre anunciado; claves raras, rechazadas.
        let r = call(
            &s,
            "POST",
            &format!("/api/hosts/nick?key={key}&name="),
            Some(&t),
        );
        assert_eq!(r.status, 200);
        assert!(headlines().iter().any(|x| x.contains("«iPhone-de-Ana»")));
        let r = call(&s, "POST", "/api/hosts/nick?key=../../etc&name=x", Some(&t));
        assert_eq!(r.status, 400);
        assert_eq!(call(&s, "GET", "/api/hosts/nick", Some(&t)).status, 405);
        std::fs::remove_file(path).ok();
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
    fn la_api_habla_ingles_sin_cambiar_los_datos() {
        let (s, path) = demo_server();
        let t = s.token.clone();
        let h = "127.0.0.1:8787";
        let (_, es) = get(&s, "/api/flows", Some(&t), h);
        let (_, en) = get(&s, "/api/flows?lang=en", Some(&t), h);
        let (es, en) = (
            es["flows"].as_array().unwrap(),
            en["flows"].as_array().unwrap(),
        );
        assert_eq!(es.len(), en.len());
        for (a, b) in es.iter().zip(en) {
            // Mismos datos, mismos niveles e ids de alerta; otras frases.
            assert_eq!(a["flow"]["flow_id"], b["flow"]["flow_id"]);
            assert_eq!(a["explain"]["level"], b["explain"]["level"]);
            let ids = |v: &Value| -> Vec<Value> {
                v["explain"]["alerts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x["id"].clone())
                    .collect()
            };
            assert_eq!(ids(a), ids(b));
            assert_ne!(a["explain"]["headline"], b["explain"]["headline"]);
            assert!(
                !b["explain"]["headline"].as_str().unwrap().contains('«'),
                "{b}"
            );
        }
        let tcp = |v: &Value| v["flow"]["transport"] == "Tcp";
        let es_tcp = es.iter().find(|f| tcp(f)).unwrap();
        let en_tcp = en.iter().find(|f| tcp(f)).unwrap();
        assert!(es_tcp["flow"]["human_summary"]
            .as_str()
            .unwrap()
            .contains(" paq "));
        assert!(en_tcp["flow"]["human_summary"]
            .as_str()
            .unwrap()
            .contains(" pkts "));

        let (_, stories) = get(&s, "/api/stories?lang=en", Some(&t), h);
        let scan = stories
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["alert_id"] == "PORT-SCAN")
            .unwrap();
        assert!(
            scan["title"].as_str().unwrap().contains(" scanned "),
            "{scan}"
        );

        // Paquetes y capas, con la cabecera que manda la ventana.
        let req = |path: &str| {
            let (p, q) = path.split_once('?').unwrap_or((path, ""));
            let r = s.route(&Request {
                method: "GET".into(),
                path: p.into(),
                query: q.into(),
                headers: vec![
                    ("Host".into(), h.into()),
                    ("X-Socshark-Token".into(), t.clone()),
                    ("X-Socshark-Lang".into(), "en-US".into()),
                ],
                body: vec![],
            });
            (r.status, r.body)
        };
        let tls = en
            .iter()
            .find(|f| f["flow"]["l7_protocol"] == "Tls")
            .unwrap();
        let (_, body) = req(&format!("/api/flows/{}/packets", tls["idx"]));
        let pk: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            pk["packets"][0]["summary"],
            "Asks to open a connection (SYN)"
        );
        let (_, body) = req(&format!("/api/packets/{}", pk["packets"][0]["n"]));
        let det: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(det["layers"][2]["fields"][0]["name"], "Source port");
        let (st, body) = req("/api/flows?filter=tcp.port+%3D%3D");
        assert_eq!(st, 400);
        let err: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(err["error"], "the expression ends too early");
        let (st, body) = req("/api/report.html?tz=60");
        assert_eq!(st, 200);
        let html = String::from_utf8(body).unwrap();
        assert!(html.contains("<html lang=\"en\">"));
        assert!(html.contains("What happened") && html.contains("What to do"));
        assert!(!html.contains("Qué hacer"));
        // El diccionario de la ventana se sirve como el resto.
        let r = call(&s, "GET", "/i18n.js", None);
        assert_eq!(r.status, 200);
        assert!(String::from_utf8_lossy(&r.body).contains("SOCSHARK_I18N"));
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
        // Con un filtro del usuario inválido, el error es el suyo (legible).
        // Solo se comprueba si la interfaz llegó a abrirse: sin permisos de
        // captura (CI en macOS) el error es otro, y además menciona
        // «ChmodBPF», así que no basta con buscar «BPF».
        let lo = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let r = call(
            &s,
            "POST",
            &format!("/api/live/start?iface={lo}&bpf=port+%3D%3D"),
            Some(&t),
        );
        let body = String::from_utf8_lossy(&r.body);
        if r.status == 400 && body.contains("filtro BPF inválido") {
            assert!(body.contains("port =="), "{body}");
        }
    }

    /// La lista de interfaces trae lo que una persona necesita para elegir:
    /// direcciones y estado (si hay libpcap en este entorno).
    #[test]
    fn interfaces_con_direcciones_y_estado() {
        let s = Arc::new(Server::new(8787, PipelineConfig::default()));
        let t = s.token.clone();
        let (st, ifaces) = get(&s, "/api/live/ifaces", Some(&t), "127.0.0.1:8787");
        if st != 200 {
            eprintln!("sin libpcap aquí: {ifaces}");
            return;
        }
        for i in ifaces.as_array().unwrap() {
            assert!(
                i["addresses"].is_array() && i["loopback"].is_boolean() && i["up"].is_boolean()
            );
        }
        #[cfg(target_os = "linux")]
        if let Some(lo) = ifaces
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["name"] == "lo")
        {
            assert_eq!(lo["loopback"], true);
            assert!(lo["addresses"]
                .as_array()
                .unwrap()
                .contains(&json!("127.0.0.1")));
        }
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
        assert!(msg.contains("no es una captura pcap ni pcapng"), "{msg}");
        assert!(
            !msg.contains("socshark-gui-"),
            "sin rutas temporales: {msg}"
        );

        // Lo que guarda Wireshark por defecto (pcapng) se abre igual.
        let ng = socshark_testgen::pcapng_bytes(1, &sample_pcap_packets(), Default::default());
        let r = post(ng, "de-wireshark.pcapng");
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let session = get(&s, "/api/session", Some(&t), "127.0.0.1:8787").1;
        assert_eq!(session["packets"], 45);
        assert_eq!(session["name"], "de-wireshark.pcapng");

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
    fn el_cuerpo_solo_se_lee_tras_validar_host_token_y_ruta() {
        let s = Arc::new(Server::new(8787, PipelineConfig::default()));
        let t = s.token.clone();
        let status = |raw: String| {
            let mut r = std::io::BufReader::new(std::io::Cursor::new(raw.into_bytes()));
            respond(&mut r, &s).map(|resp| resp.status)
        };
        let grande = 512 * 1024 * 1024;
        // Sin token / Host ajeno: se responde sin esperar ni reservar el
        // cuerpo anunciado (antes 50 conexiones así tumbaban el proceso).
        assert_eq!(
            status(format!(
                "POST /api/open HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nContent-Length: {grande}\r\n\r\n"
            )),
            Some(403)
        );
        assert_eq!(
            status(format!(
                "POST /api/open HTTP/1.1\r\nHost: evil:8787\r\nX-Socshark-Token: {t}\r\nContent-Length: {grande}\r\n\r\n"
            )),
            Some(421)
        );
        // Con token, cualquier ruta que no sea la subida tiene un límite
        // pequeño.
        assert_eq!(
            status(format!(
                "POST /api/hosts/nick HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nX-Socshark-Token: {t}\r\nContent-Length: {}\r\n\r\n",
                MAX_SMALL_BODY + 1
            )),
            Some(413)
        );
        // Solo una subida a la vez.
        s.uploading.store(true, Ordering::SeqCst);
        assert_eq!(
            status(format!(
                "POST /api/open HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nX-Socshark-Token: {t}\r\nContent-Length: 4\r\n\r\nabcd"
            )),
            Some(503)
        );
        s.uploading.store(false, Ordering::SeqCst);
        // Subida legítima (no es un pcap): se lee, se intenta y se libera
        // la marca de subida en curso.
        assert_eq!(
            status(format!(
                "POST /api/open HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nX-Socshark-Token: {t}\r\nContent-Length: 4\r\n\r\nabcd"
            )),
            Some(400)
        );
        assert!(!s.uploading.load(Ordering::SeqCst));
        // Cuerpo anunciado pero no enviado: el cliente se fue, sin respuesta.
        assert_eq!(
            status(format!(
                "POST /api/open HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nX-Socshark-Token: {t}\r\nContent-Length: {grande}\r\n\r\nab"
            )),
            None
        );
        assert!(!s.uploading.load(Ordering::SeqCst));
    }

    #[test]
    fn el_rechazo_llega_entero_aunque_quede_cuerpo_sin_leer() {
        // Host ajeno + cuerpo grande ya enviado en parte: el servidor no lo
        // lee, pero el cliente debe recibir el 421 y no un RST.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let s = Arc::new(Server::new(port, PipelineConfig::default()));
        std::thread::spawn(move || serve(listener, s));
        for _ in 0..3 {
            let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            c.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
            write!(
                c,
                "POST /api/open HTTP/1.1\r\nHost: evil:{port}\r\nContent-Length: {}\r\n\r\n",
                10 * 1024 * 1024
            )
            .unwrap();
            // El envío puede cortarse cuando el servidor deja de leer: da
            // igual, lo que importa es la respuesta.
            let chunk = vec![b'a'; 64 * 1024];
            for _ in 0..32 {
                if c.write_all(&chunk).is_err() {
                    break;
                }
            }
            let mut resp = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match c.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => resp.extend_from_slice(&buf[..n]),
                    Err(e) => panic!("lectura fallida ({e}) tras {} bytes", resp.len()),
                }
            }
            let resp = String::from_utf8_lossy(&resp);
            assert!(resp.starts_with("HTTP/1.1 421 "), "{resp}");
            assert!(resp.contains("host no permitido"), "{resp}");
        }
    }

    #[test]
    fn demasiadas_conexiones_reciben_503() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let s = Arc::new(Server::new(port, PipelineConfig::default()));
        s.conns.store(MAX_CONNS, Ordering::SeqCst);
        std::thread::spawn(move || serve(listener, s));
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut resp = String::new();
        c.read_to_string(&mut resp).ok();
        assert!(resp.starts_with("HTTP/1.1 503 "), "{resp}");
    }

    #[test]
    fn bpf_con_parentesis_desequilibrados_se_rechaza() {
        assert!(parens_balanced("tcp and (port 80 or port 443)"));
        assert!(parens_balanced("udp"));
        assert!(!parens_balanced("tcp) or (udp"));
        assert!(!parens_balanced("(tcp"));
        assert!(!parens_balanced("tcp)"));
        let s = Arc::new(Server::new(8787, PipelineConfig::default()));
        let t = s.token.clone();
        let r = call(
            &s,
            "POST",
            "/api/live/start?iface=lo&bpf=tcp)%20or%20(udp",
            Some(&t),
        );
        assert_eq!(r.status, 400);
        assert!(String::from_utf8_lossy(&r.body).contains("paréntesis"));
    }

    #[test]
    fn archivo_temporal_nuevo_y_privado() {
        let s = Server::new(8787, PipelineConfig::default());
        let a = s.write_temp(b"uno").unwrap();
        let b = s.write_temp(b"dos").unwrap();
        assert_ne!(a, b);
        assert_eq!(std::fs::read(&a).unwrap(), b"uno");
        assert_eq!(std::fs::read(&b).unwrap(), b"dos");
        // El nombre lleva una parte aleatoria: no se puede adivinar el
        // siguiente a partir del PID y el contador.
        let name = a.file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(name.split('-').count(), 5, "{name}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&a).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_file(a).ok();
        std::fs::remove_file(b).ok();
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
