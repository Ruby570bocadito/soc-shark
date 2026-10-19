//! Informe de red en lenguaje claro: un HTML de un solo archivo, sin
//! scripts, que se puede guardar, imprimir o mandar a quien lo necesite.
//!
//! Lo usan la ventana («Informe») y `socshark report -r captura.pcap`.
//! Todo dato de la captura pasa por [`esc`]: un dominio o un nombre de
//! equipo pueden traer HTML malicioso. Además el archivo declara una CSP
//! que no deja ejecutar ni cargar nada.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use socshark_capture::{CaptureSource, PcapFileReader};
use socshark_core::config::PipelineConfig;
use socshark_core::{EnrichedFlow, L7Protocol};
use socshark_dissectors::DissectorPipeline;
use socshark_soc::explain::{
    explain_with, stories_with, well_known_name, Explanation, Level, Story,
};
use socshark_soc::hosts::{HostBook, HostDirectory};
use socshark_soc::summarize::fmt_bytes;

use crate::pipeline::run_capture;

/// Lo que hace falta para escribir el informe.
pub struct ReportInput<'a> {
    pub name: &'a str,
    pub flows: &'a [EnrichedFlow],
    pub explanations: &'a [Explanation],
    pub stories: &'a [Story],
    pub hosts: &'a HostDirectory,
    pub packets: u64,
    /// Minutos a sumar a UTC para la hora local (España en verano: 120).
    pub tz_offset_minutes: i32,
    /// Cuándo se genera (µs epoch).
    pub generated_micros: u64,
}

/// Escapa texto para HTML (contenido y atributos).
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

const MONTHS: [&str; 12] = [
    "ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic",
];

/// Fecha y hora legibles (`14 nov 2023, 22:13`) con el desfase dado.
pub fn fmt_date(micros: u64, tz_offset_minutes: i32) -> String {
    let secs = (micros / 1_000_000) as i64 + i64::from(tz_offset_minutes) * 60;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Días desde 1970 → fecha civil (algoritmo de Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{day} {} {year}, {:02}:{:02}",
        MONTHS[(month - 1) as usize],
        rem / 3600,
        (rem % 3600) / 60
    )
}

fn fmt_duration(micros: u64) -> String {
    let s = micros / 1_000_000;
    match s {
        0 => "menos de un segundo".into(),
        1..=119 => format!("{s} segundos"),
        120..=7_199 => format!("{} minutos", s / 60),
        _ => format!("{} h {} min", s / 3600, (s % 3600) / 60),
    }
}

fn level_badge(level: Level) -> &'static str {
    match level {
        Level::Peligro => r#"<span class="badge peligro">✕ Peligro</span>"#,
        Level::Raro => r#"<span class="badge raro">! Raro</span>"#,
        Level::Ok => r#"<span class="badge ok">✓ Normal</span>"#,
    }
}

fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => (v4.is_private() || v4.is_link_local()) && v4.octets()[3] != 255,
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            (s0 & 0xfe00) == 0xfc00 || (s0 & 0xffc0) == 0xfe80
        }
    }
}

fn is_internet(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified())
        }
        IpAddr::V6(v6) => (v6.segments()[0] & 0xe000) == 0x2000,
    }
}

#[derive(Default)]
struct Traffic {
    flows: u64,
    bytes: u64,
    level: Option<Level>,
    name: Option<String>,
}

impl Traffic {
    fn add(&mut self, bytes: u64, level: Level) {
        self.flows += 1;
        self.bytes += bytes;
        self.level = Some(self.level.map_or(level, |l| l.max(level)));
    }
}

const STYLE: &str = r#"
:root { --bg:#f4f6f9; --panel:#fff; --text:#141b26; --muted:#5a6577; --border:#dde2ea; --accent:#0e7490;
  --ok:#15803d; --ok-bg:#dcfce7; --raro:#b45309; --raro-bg:#fef3c7; --peligro:#b91c1c; --peligro-bg:#fee2e2; color-scheme: light; }
@media (prefers-color-scheme: dark) { :root { --bg:#0d1218; --panel:#141b24; --text:#e5eaf1; --muted:#98a3b5; --border:#263142;
  --accent:#22b8cf; --ok:#4ade80; --ok-bg:#11301e; --raro:#fbbf24; --raro-bg:#3a2a0a; --peligro:#f87171; --peligro-bg:#3d1414; color-scheme: dark; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.55 "Segoe UI", system-ui, -apple-system, Roboto, Arial, sans-serif; }
main { max-width: 980px; margin: 0 auto; padding: 28px 18px 48px; }
h1 { font-size: 26px; margin: 0 0 4px; } h2 { font-size: 19px; margin: 32px 0 10px; }
.sub, .muted { color: var(--muted); } .sub { font-size: 13.5px; }
.verdict { border-radius: 12px; padding: 16px 18px; margin: 18px 0; border: 1px solid var(--border); background: var(--panel); }
.verdict.peligro { background: var(--peligro-bg); border-color: transparent; } .verdict.raro { background: var(--raro-bg); border-color: transparent; }
.verdict.ok { background: var(--ok-bg); border-color: transparent; } .verdict b { font-size: 17px; display: block; margin-bottom: 4px; }
.facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 14px 0; }
.fact { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; }
.fact .n { font-size: 22px; font-weight: 700; display: block; } .fact .l { color: var(--muted); font-size: 13px; }
.story { background: var(--panel); border: 1px solid var(--border); border-left: 5px solid var(--muted); border-radius: 10px; padding: 12px 14px; margin: 10px 0; break-inside: avoid; }
.story.peligro { border-left-color: var(--peligro); } .story.raro { border-left-color: var(--raro); }
.story h3 { margin: 0 0 6px; font-size: 16px; } .story p { margin: 6px 0; overflow-wrap: anywhere; }
.todo { background: var(--bg); border-radius: 8px; padding: 8px 10px; } .todo b { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .5px; display: block; }
table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; font-size: 14px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: top; overflow-wrap: break-word; }
th { font-size: 12.5px; color: var(--muted); background: var(--bg); } td.num, th.num { text-align: right; white-space: nowrap; }
.mono { font-family: Consolas, "Cascadia Mono", ui-monospace, Menlo, monospace; font-size: 13px; }
.badge { display: inline-block; border-radius: 999px; padding: 0 8px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.badge.ok { background: var(--ok-bg); color: var(--ok); } .badge.raro { background: var(--raro-bg); color: var(--raro); } .badge.peligro { background: var(--peligro-bg); color: var(--peligro); }
a { color: var(--accent); } footer { margin-top: 36px; color: var(--muted); font-size: 13px; border-top: 1px solid var(--border); padding-top: 12px; }
ul.list { padding-left: 20px; } ul.list li { margin: 4px 0; overflow-wrap: anywhere; }
@media print { body { background: #fff; } .story, table, .fact, .verdict { box-shadow: none; } h2 { break-after: avoid; } }
"#;

/// Escribe el informe completo.
pub fn render(r: &ReportInput) -> String {
    let flows = r.flows;
    // El veredicto cuenta historias: un escaneo de 14 puertos es una cosa.
    let count = |lv: Level| r.stories.iter().filter(|s| s.level == lv).count();
    let (peligros, raros) = (count(Level::Peligro), count(Level::Raro));
    let first = flows.iter().map(|f| f.first_seen_micros).min();
    let last = flows.iter().map(|f| f.last_seen_micros).max();
    let total_bytes: u64 = flows.iter().map(|f| f.bytes + f.bytes_rev).sum();

    // Equipos de casa y sitios de Internet, con su tráfico.
    let mut lan: HashMap<IpAddr, Traffic> = HashMap::new();
    let mut net: HashMap<IpAddr, Traffic> = HashMap::new();
    let mut protos: HashMap<&'static str, (u64, u64)> = HashMap::new();
    for (f, e) in flows.iter().zip(r.explanations) {
        let bytes = f.bytes + f.bytes_rev;
        for ip in [f.src_ip, f.dst_ip] {
            if is_lan(ip) {
                lan.entry(ip).or_default().add(bytes, e.level);
            } else if is_internet(ip) {
                net.entry(ip).or_default().add(bytes, e.level);
            }
        }
        if is_internet(f.dst_ip) {
            let named = match f.l7_protocol {
                L7Protocol::Dns => None,
                _ => f.tls_sni.clone().or_else(|| f.resolved_domain.clone()),
            };
            let t = net.entry(f.dst_ip).or_default();
            if t.name.is_none() {
                t.name = named.or_else(|| well_known_name(f.dst_ip).map(str::to_string));
            }
        }
        let p = if f.l7_protocol == L7Protocol::Unknown {
            f.transport.as_str()
        } else {
            f.l7_protocol.as_str()
        };
        let acc = protos.entry(p).or_default();
        acc.0 += 1;
        acc.1 += bytes;
    }

    let mut h = String::with_capacity(32 * 1024);
    let _ = write!(
        h,
        "<!doctype html>\n<html lang=\"es\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n\
         <title>Informe de red · {}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n<main>\n",
        esc(r.name)
    );
    let _ = write!(
        h,
        "<h1>Informe de tu red</h1>\n<p class=\"sub\">Captura <b>{}</b>",
        esc(r.name)
    );
    if let (Some(a), Some(b)) = (first, last) {
        let _ = write!(
            h,
            " · del {} al {} ({})",
            fmt_date(a, r.tz_offset_minutes),
            fmt_date(b, r.tz_offset_minutes),
            fmt_duration(b.saturating_sub(a))
        );
    }
    let _ = writeln!(
        h,
        " · generado el {}</p>",
        fmt_date(r.generated_micros, r.tz_offset_minutes)
    );

    let (cls, title, text) = if peligros > 0 {
        (
            "peligro",
            format!(
                "Hay {} que revisar",
                if peligros == 1 {
                    "1 cosa peligrosa".to_string()
                } else {
                    format!("{peligros} cosas peligrosas")
                }
            ),
            "Lee abajo «Lo que ha pasado»: cada punto dice qué pasó y qué hacer.",
        )
    } else if raros > 0 {
        (
            "raro",
            format!(
                "Nada grave, pero hay {} que conviene mirar",
                if raros == 1 {
                    "1 cosa rara".to_string()
                } else {
                    format!("{raros} cosas raras")
                }
            ),
            "No tiene por qué ser un problema; abajo se explica cada una.",
        )
    } else {
        (
            "ok",
            "No hemos visto nada preocupante".to_string(),
            "Todo lo que pasó por la red parece normal.",
        )
    };
    let _ = writeln!(
        h,
        "<div class=\"verdict {cls}\"><b>{}</b>{}</div>",
        esc(&title),
        esc(text)
    );
    let _ = writeln!(
        h,
        "<div class=\"facts\">\
         <div class=\"fact\"><span class=\"n\">{}</span><span class=\"l\">conversaciones</span></div>\
         <div class=\"fact\"><span class=\"n\">{}</span><span class=\"l\">equipos de tu red</span></div>\
         <div class=\"fact\"><span class=\"n\">{}</span><span class=\"l\">sitios de Internet</span></div>\
         <div class=\"fact\"><span class=\"n\">{}</span><span class=\"l\">paquetes</span></div>\
         <div class=\"fact\"><span class=\"n\">{}</span><span class=\"l\">datos</span></div></div>",
        flows.len(),
        lan.len(),
        net.len(),
        r.packets,
        esc(&fmt_bytes(total_bytes))
    );

    // Historias.
    let _ = writeln!(h, "<h2>Lo que ha pasado</h2>");
    if r.stories.is_empty() {
        let _ = writeln!(
            h,
            "<p class=\"muted\">Ninguna alerta: no hay nada que contar.</p>"
        );
    }
    for st in r.stories {
        let cls = match st.level {
            Level::Peligro => "peligro",
            Level::Raro => "raro",
            Level::Ok => "ok",
        };
        let mitre = st
            .mitre
            .as_deref()
            .filter(|m| {
                m.len() <= 9
                    && m.starts_with('T')
                    && m[1..].chars().all(|c| c.is_ascii_digit() || c == '.')
            })
            .map(|m| {
                format!(
                    " · <a href=\"https://attack.mitre.org/techniques/{}/\">MITRE {}</a>",
                    m.replace('.', "/"),
                    m
                )
            })
            .unwrap_or_default();
        let _ = writeln!(
            h,
            "<div class=\"story {cls}\"><h3>{} {}</h3><p>{}</p>\
             <p class=\"todo\"><b>Qué hacer</b>{}</p><p class=\"sub\">{} {}{mitre}</p></div>",
            level_badge(st.level),
            esc(&st.title),
            esc(&st.story),
            esc(&st.action),
            st.flows.len(),
            if st.flows.len() == 1 {
                "conversación"
            } else {
                "conversaciones"
            },
        );
    }

    // Equipos de la red.
    let _ = writeln!(h, "<h2>Equipos de tu red</h2>");
    let mut lan: Vec<(IpAddr, Traffic)> = lan.into_iter().collect();
    lan.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then(a.0.cmp(&b.0)));
    if lan.is_empty() {
        let _ = writeln!(
            h,
            "<p class=\"muted\">No aparece ningún equipo de la red local.</p>"
        );
    } else {
        let _ = writeln!(
            h,
            "<table><thead><tr><th>Equipo</th><th>Dirección</th><th>Marca</th><th>Sistema</th>\
             <th class=\"num\">Conversaciones</th><th class=\"num\">Datos</th><th></th></tr></thead><tbody>"
        );
        for (ip, t) in &lan {
            let host = r.hosts.get(*ip);
            let name = host.and_then(|x| x.short()).unwrap_or_else(|| "—".into());
            let mac = host
                .and_then(|x| x.mac.clone())
                .map(|m| format!("<div class=\"sub mono\">MAC {}</div>", esc(&m)))
                .unwrap_or_default();
            let vendor = host
                .and_then(|x| {
                    x.vendor.map(|v| match x.vendor_hint {
                        Some(hint) => format!("{v} (suele ser {hint})"),
                        None => v.to_string(),
                    })
                })
                .or_else(|| {
                    host.filter(|x| x.random_mac)
                        .map(|_| "MAC aleatoria (móvil o portátil)".to_string())
                })
                .unwrap_or_default();
            let os = host.and_then(|x| x.os).unwrap_or("");
            let _ = writeln!(
                h,
                "<tr><td><b>{}</b></td><td class=\"mono\">{}{mac}</td><td>{}</td><td>{}</td>\
                 <td class=\"num\">{}</td><td class=\"num\">{}</td><td>{}</td></tr>",
                esc(&name),
                esc(&ip.to_string()),
                esc(&vendor),
                esc(os),
                t.flows,
                esc(&fmt_bytes(t.bytes)),
                t.level
                    .filter(|l| *l > Level::Ok)
                    .map(level_badge)
                    .unwrap_or(""),
            );
        }
        let _ = writeln!(h, "</tbody></table>");
    }

    // Internet.
    let _ = writeln!(h, "<h2>Con quién habló en Internet</h2>");
    let mut net: Vec<(IpAddr, Traffic)> = net.into_iter().collect();
    net.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then(a.0.cmp(&b.0)));
    if net.is_empty() {
        let _ = writeln!(
            h,
            "<p class=\"muted\">Ninguna conversación salió a Internet.</p>"
        );
    } else {
        let _ = writeln!(
            h,
            "<table><thead><tr><th>Sitio</th><th>Dirección</th><th class=\"num\">Conversaciones</th>\
             <th class=\"num\">Datos</th><th></th></tr></thead><tbody>"
        );
        for (ip, t) in net.iter().take(25) {
            let _ = writeln!(
                h,
                "<tr><td>{}</td><td class=\"mono\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td>{}</td></tr>",
                esc(t.name.as_deref().unwrap_or("—")),
                esc(&ip.to_string()),
                t.flows,
                esc(&fmt_bytes(t.bytes)),
                t.level.filter(|l| *l > Level::Ok).map(level_badge).unwrap_or(""),
            );
        }
        let _ = writeln!(h, "</tbody></table>");
        if net.len() > 25 {
            let _ = writeln!(h, "<p class=\"sub\">Y {} sitios más.</p>", net.len() - 25);
        }
    }

    // Protocolos.
    let _ = writeln!(h, "<h2>Qué tipo de tráfico hubo</h2>");
    let mut protos: Vec<(&str, (u64, u64))> = protos.into_iter().collect();
    protos.sort_by(|a, b| b.1 .1.cmp(&a.1 .1).then(a.0.cmp(b.0)));
    let _ = writeln!(
        h,
        "<table><thead><tr><th>Protocolo</th><th class=\"num\">Conversaciones</th>\
         <th class=\"num\">Datos</th><th class=\"num\">%</th></tr></thead><tbody>"
    );
    for (name, (n, bytes)) in &protos {
        let pct = (bytes * 100).checked_div(total_bytes).unwrap_or(0);
        let _ = writeln!(
            h,
            "<tr><td>{}</td><td class=\"num\">{n}</td><td class=\"num\">{}</td><td class=\"num\">{pct} %</td></tr>",
            esc(name),
            esc(&fmt_bytes(*bytes))
        );
    }
    let _ = writeln!(h, "</tbody></table>");

    // Conversaciones a mirar.
    let notable: Vec<&Explanation> = r
        .explanations
        .iter()
        .filter(|e| e.level > Level::Ok)
        .collect();
    if !notable.is_empty() {
        let _ = writeln!(
            h,
            "<h2>Conversaciones que conviene mirar</h2><ul class=\"list\">"
        );
        for e in notable.iter().take(60) {
            let _ = writeln!(h, "<li>{} {}</li>", level_badge(e.level), esc(&e.headline));
        }
        let _ = writeln!(h, "</ul>");
        if notable.len() > 60 {
            let _ = writeln!(h, "<p class=\"sub\">Y {} más.</p>", notable.len() - 60);
        }
    }

    let _ = write!(
        h,
        "<footer>Informe generado por soc-shark {}. Describe solo lo que se vio en esta captura: \
         lo que no pasó por el punto donde se capturó no aparece. Los nombres de los equipos son \
         los que ellos mismos anuncian y podrían no ser ciertos.</footer>\n</main>\n</body>\n</html>\n",
        env!("CARGO_PKG_VERSION")
    );
    h
}

/// Quién es quién de una captura de archivo (una pasada rápida).
fn learn_hosts(path: &Path) -> Result<HostDirectory> {
    let mut reader = PcapFileReader::open(path)
        .with_context(|| format!("no se pudo abrir {}", path.display()))?;
    let link = reader.link_type();
    let dissectors = DissectorPipeline::new();
    let mut book = HostBook::new();
    while let Some(pkt) = reader.next_packet().context("error leyendo paquetes")? {
        if let Some(dp) = dissectors.dissect(&pkt, link) {
            book.observe(&dp);
        }
    }
    Ok(book.directory())
}

/// `socshark report`: analiza la captura y escribe el informe.
pub fn from_file(path: &Path, cfg: &PipelineConfig, tz_offset_minutes: i32) -> Result<String> {
    let out = run_capture(path, None, true, cfg)?;
    let hosts = learn_hosts(path)?;
    let explanations: Vec<Explanation> =
        out.flows.iter().map(|f| explain_with(f, &hosts)).collect();
    let stories = stories_with(&out.flows, &hosts);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "captura".into());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0);
    Ok(render(&ReportInput {
        name: &name,
        flows: &out.flows,
        explanations: &explanations,
        stories: &stories,
        hosts: &hosts,
        packets: out.stats.total_packets,
        tz_offset_minutes,
        generated_micros: now,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_testgen::{home_pcap_packets, sample_pcap_packets, write_pcap};

    fn report_of(packets: &[(u64, Vec<u8>)], name: &str) -> String {
        let path =
            std::env::temp_dir().join(format!("socshark-report-{}-{name}", std::process::id()));
        write_pcap(&path, 1, packets).unwrap();
        let cfg = PipelineConfig {
            file_carving: true,
            ..PipelineConfig::default()
        };
        let html = from_file(&path, &cfg, 60).unwrap();
        std::fs::remove_file(path).ok();
        html
    }

    #[test]
    fn fechas_legibles() {
        // 2023-11-14T22:13:20Z
        assert_eq!(fmt_date(1_700_000_000_000_000, 0), "14 nov 2023, 22:13");
        assert_eq!(fmt_date(1_700_000_000_000_000, 120), "15 nov 2023, 00:13");
        assert_eq!(fmt_date(0, 0), "1 ene 1970, 00:00");
        assert_eq!(fmt_date(951_782_400_000_000, 0), "29 feb 2000, 00:00");
    }

    #[test]
    fn informe_de_la_demo() {
        let html = report_of(&sample_pcap_packets(), "demo.pcap");
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("Hay 2 cosas peligrosas que revisar"));
        assert!(html.contains("Posible fuga de datos escondida en DNS"));
        assert!(html.contains("Qué hacer"));
        assert!(html.contains("https://attack.mitre.org/techniques/T1046/"));
        assert!(html.contains("Con quién habló en Internet"));
        assert!(html.contains("DNS de Google"));
        assert!(!html.contains("<script"), "sin scripts");
        assert!(html.contains("default-src 'none'"));
    }

    #[test]
    fn informe_de_casa_con_nombres() {
        let html = report_of(&home_pcap_packets(), "casa.pcap");
        assert!(html.contains("<b>iPhone-de-Ana</b>"));
        assert!(html.contains("<b>HP OfficeJet Pro 8020</b>"));
        assert!(html.contains("<b>Router</b>"));
        assert!(html.contains("Arcadyan (suele ser router de operadora)"));
        assert!(html.contains("www.instagram.com"));
        assert!(html.contains("Hay 1 cosa peligrosa que revisar"));
    }

    #[test]
    fn un_escaneo_es_una_sola_cosa_rara() {
        use socshark_testgen::{
            flags, frame_tcp, GATEWAY, HOST_C, MAC_HOST_C, MAC_ROUTER, SCAN_PORTS,
        };
        let t0 = 1_700_000_000_000_000u64;
        let pkts: Vec<(u64, Vec<u8>)> = SCAN_PORTS
            .iter()
            .enumerate()
            .map(|(i, &p)| {
                (
                    t0 + i as u64 * 1000,
                    frame_tcp(
                        MAC_HOST_C,
                        MAC_ROUTER,
                        HOST_C,
                        GATEWAY,
                        40001,
                        p,
                        1,
                        0,
                        flags::SYN,
                        &[],
                    ),
                )
            })
            .collect();
        let html = report_of(&pkts, "escaneo.pcap");
        assert!(
            html.contains("Nada grave, pero hay 1 cosa rara que conviene mirar"),
            "{html}"
        );
    }

    #[test]
    fn el_html_de_la_captura_se_escapa() {
        use socshark_testgen::{dns_query, frame_udp, DNS_EXT, HOST_A, MAC_HOST_A, MAC_ROUTER};
        let evil = "<img src=x onerror=alert(1)>.example";
        let pkt = frame_udp(
            MAC_HOST_A,
            MAC_ROUTER,
            HOST_A,
            DNS_EXT,
            5300,
            53,
            &dns_query(1, evil, 1),
        );
        let html = report_of(&[(1_700_000_000_000_000, pkt)], "trampa.pcap");
        assert!(!html.contains("<img"), "nada de HTML de la captura");
        // El nombre de la captura (en Windows no puede llevar «<», pero
        // la ventana lo recibe de quien sube el archivo).
        let html = render(&ReportInput {
            name: "<i>trampa.pcap",
            flows: &[],
            explanations: &[],
            stories: &[],
            hosts: &HostDirectory::default(),
            packets: 0,
            tz_offset_minutes: 0,
            generated_micros: 0,
        });
        assert!(!html.contains("<i>trampa"));
        assert!(html.contains("&lt;i&gt;trampa.pcap"));
        assert_eq!(
            esc(r#"<a href="x">'&'</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }
}
