//! GUI de soc-shark: `socshark gui` (ADR-013).
//!
//! La interfaz es una página web local que sirve el propio binario y que se
//! abre en una ventana de aplicación (Edge o Chrome en modo `--app`, o el
//! navegador por defecto). Así hay GUI en Windows, macOS y Linux sin
//! dependencias nuevas (ADR-003) y el mismo frontend podrá empaquetarse más
//! adelante en Tauri sin reescribirlo.
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
pub mod packets;

use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use socshark_core::config::PipelineConfig;
use socshark_core::EnrichedFlow;
use socshark_flow::PipelineStats;
use socshark_soc::explain::{explain, stories, Explanation, Level, Story};

use crate::pipeline::run_capture;
use http::{read_request, write_response, ReadError, Request, Response};
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
struct Loaded {
    name: String,
    flows: Vec<EnrichedFlow>,
    explanations: Vec<Explanation>,
    stories: Vec<Story>,
    stats: PipelineStats,
    packets: PacketIndex,
}

struct Server {
    token: String,
    host_ok: [String; 3],
    cfg: PipelineConfig,
    session: RwLock<Option<Loaded>>,
    upload_seq: AtomicU64,
}

/// Analiza una captura con el pipeline completo (ruido incluido: la
/// interfaz decide si lo muestra) y prepara su índice de paquetes.
fn load(path: &Path, name: String, cfg: &PipelineConfig) -> Result<Loaded> {
    let out = run_capture(path, None, true, cfg)?;
    let packets = PacketIndex::build(path)?;
    let explanations = out.flows.iter().map(explain).collect();
    let stories = stories(&out.flows);
    Ok(Loaded {
        name,
        flows: out.flows,
        explanations,
        stories,
        stats: out.stats,
        packets,
    })
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

impl Server {
    fn new(port: u16, cfg: PipelineConfig) -> Self {
        Self {
            token: new_token(),
            host_ok: [
                format!("127.0.0.1:{port}"),
                format!("localhost:{port}"),
                format!("[::1]:{port}"),
            ],
            cfg,
            session: RwLock::new(None),
            upload_seq: AtomicU64::new(0),
        }
    }

    fn route(&self, req: &Request) -> Response {
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
            ("GET", ["flows", i, "packets"]) => self.with_loaded(|l| {
                let Some(flow) = i.parse::<usize>().ok().and_then(|i| l.flows.get(i)) else {
                    return Response::error(404, "flujo inexistente");
                };
                let (rows, more) = l.packets.list(flow);
                Response::json(
                    200,
                    &json!({ "packets": rows, "more": more, "truncated": l.packets.truncated }),
                )
            }),
            ("GET", ["packets", n]) => self.with_loaded(|l| {
                match n.parse::<usize>().ok().and_then(|n| l.packets.detail(n)) {
                    Some(d) => Response::json(200, &serde_json::to_value(d).unwrap_or(Value::Null)),
                    None => Response::error(404, "paquete inexistente"),
                }
            }),
            ("POST", ["open"]) => self.open_upload(req),
            (_, ["session" | "stories" | "flows" | "packets" | "open", ..]) => {
                Response::error(405, "método no permitido")
            }
            _ => Response::error(404, "no existe"),
        }
    }

    fn with_session(&self, f: impl FnOnce(Option<&Loaded>) -> Response) -> Response {
        match self.session.read() {
            Ok(s) => f(s.as_ref()),
            Err(_) => Response::error(500, "estado interno inconsistente"),
        }
    }

    fn with_loaded(&self, f: impl FnOnce(&Loaded) -> Response) -> Response {
        self.with_session(|s| match s {
            Some(l) => f(l),
            None => Response::error(404, "no hay ninguna captura abierta"),
        })
    }

    /// Analiza una captura subida desde la ventana ("Abrir captura…").
    fn open_upload(&self, req: &Request) -> Response {
        if req.body.is_empty() {
            return Response::error(400, "el archivo está vacío");
        }
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
                let body = session_json(Some(&loaded));
                match self.session.write() {
                    Ok(mut s) => *s = Some(loaded),
                    Err(_) => return Response::error(500, "estado interno inconsistente"),
                }
                Response::json(200, &body)
            }
            // Solo la causa: la ruta del archivo temporal no le dice nada a
            // quien subió la captura.
            Err(e) => Response::error(400, &e.root_cause().to_string()),
        }
    }
}

fn session_json(s: Option<&Loaded>) -> Value {
    let Some(l) = s else {
        return json!({ "loaded": false, "version": env!("CARGO_PKG_VERSION") });
    };
    let count = |lv: Level| l.explanations.iter().filter(|e| e.level == lv).count();
    json!({
        "loaded": true,
        "version": env!("CARGO_PKG_VERSION"),
        "name": l.name,
        "packets": l.stats.total_packets,
        "parsed": l.stats.parsed_packets,
        "skipped": l.stats.skipped_packets,
        "flows": l.flows.len(),
        "noise": l.flows.iter().filter(|f| f.is_background_noise).count(),
        "levels": { "ok": count(Level::Ok), "raro": count(Level::Raro), "peligro": count(Level::Peligro) },
        "stories": l.stories.len(),
        "first_seen": l.flows.iter().map(|f| f.first_seen_micros).min(),
        "last_seen": l.flows.iter().map(|f| f.last_seen_micros).max(),
        "packets_truncated": l.packets.truncated,
    })
}

fn flows_json(l: &Loaded, filter: Option<String>) -> Response {
    let filter = filter.filter(|f| !f.trim().is_empty());
    let expr = match filter.as_deref().map(socshark_filter::parse).transpose() {
        Ok(e) => e,
        Err(e) => {
            return Response::json(
                400,
                &json!({ "error": e.message, "pos": e.pos, "filter": filter }),
            )
        }
    };
    let matching: Vec<usize> = (0..l.flows.len())
        .filter(|&i| match &expr {
            Some(e) => socshark_filter::eval(e, &l.flows[i]),
            None => true,
        })
        .collect();
    let rows: Vec<Value> = matching
        .iter()
        .take(MAX_FLOWS)
        .map(|&i| json!({ "idx": i, "flow": &l.flows[i], "explain": &l.explanations[i] }))
        .collect();
    Response::json(
        200,
        &json!({ "flows": rows, "total": matching.len(), "truncated": matching.len() > MAX_FLOWS }),
    )
}

fn handle(mut stream: TcpStream, server: &Server) {
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(30))).ok();
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
    let server = Arc::new(Server::new(port, opts.cfg.clone()));
    if let Some(path) = &opts.read {
        let name = display_name(&path.to_string_lossy());
        let loaded = load(path, name, &opts.cfg)?;
        *server
            .session
            .write()
            .map_err(|_| anyhow::anyhow!("estado interno inconsistente"))? = Some(loaded);
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

    fn demo_server() -> (Server, PathBuf) {
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
        let server = Server::new(8787, cfg.clone());
        *server.session.write().unwrap() = Some(load(&path, "demo.pcap".into(), &cfg).unwrap());
        (server, path)
    }

    fn get(server: &Server, path: &str, token: Option<&str>, host: &str) -> (u16, Value) {
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
        // La página lleva el token incrustado y no queda el marcador.
        let page = s.route(&Request {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![("Host".into(), "127.0.0.1:8787".into())],
            ..Request::default()
        });
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

        // Paquetes de un flujo y detalle de uno de ellos.
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

        assert_eq!(get(&s, "/api/flows/9999/packets", Some(&t), h).0, 404);
        assert_eq!(get(&s, "/api/packets/0", Some(&t), h).0, 404);
        assert_eq!(get(&s, "/api/nada", Some(&t), h).0, 404);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn abrir_desde_la_ventana_y_errores_legibles() {
        let s = Server::new(8787, PipelineConfig::default());
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
        let (s, path) = demo_server();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let token = s.token.clone();
        // El Server de prueba se creó para el 8787: se rehace para este puerto.
        let mut s = s;
        s.host_ok = Server::new(port, PipelineConfig::default()).host_ok;
        std::thread::spawn(move || serve(listener, Arc::new(s)));

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
        assert!(resp.contains("\"packets\":45"));
        std::fs::remove_file(path).ok();
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
