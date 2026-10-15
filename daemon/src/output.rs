//! Salida del daemon: informe de terminal (radar SOC + tabla de flujos),
//! JSON completo, eventos JSONL y exportación ECS.

use crate::bridge::{FlowFacts, PacketFacts};
use crate::pipeline::{self, CaptureReport, ReadOpts};
use socshark_common::ansi::Palette;
use socshark_common::json::Json;
use socshark_common::soc_types::Severity;
use socshark_common::timefmt;
use socshark_dissectors::view::{AppInfo, DissectedPacket};
use socshark_filter_dsl::Expr;
use socshark_storage_index::session_db;

/// `soc-shark fields`: catálogo del DSL.
pub fn print_fields() {
    use socshark_filter_dsl::registry::FIELDS;
    println!("CAMPO                    TIPO  NIVEL  DESCRIPCIÓN");
    println!("──────────────────────── ───── ────── ────────────────────────────────────");
    for f in FIELDS {
        println!("{:<24} {:<5} {:<6} {}", f.path, f.kind, f.level, f.desc);
    }
}

/// `soc-shark read`: punto de entrada de análisis.
pub fn cmd_read(args: &[String]) -> Result<std::process::ExitCode, String> {
    let mut opts = ReadOpts::default();
    let mut path: Option<String> = None;
    let mut json = false;
    let mut events = false;
    let mut export_ecs: Option<String> = None;
    let mut export_suricata: Option<String> = None;
    let mut no_color = false;

    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--json" => json = true,
            "--events" => events = true,
            "--no-color" => no_color = true,
            "--include-noise" => opts.include_noise = true,
            "--filter" => {
                i += 1;
                opts.filter = Some(args.get(i).ok_or("--filter requiere un argumento")?.clone());
            }
            "--export-ecs" => {
                i += 1;
                export_ecs = Some(
                    args.get(i)
                        .ok_or("--export-ecs requiere un archivo")?
                        .clone(),
                );
            }
            "--export-suricata" => {
                i += 1;
                export_suricata = Some(
                    args.get(i)
                        .ok_or("--export-suricata requiere un archivo")?
                        .clone(),
                );
            }
            "--iocs" => {
                i += 1;
                opts.iocs = Some(args.get(i).ok_or("--iocs requiere un archivo")?.clone());
            }
            "--min-risk" => {
                i += 1;
                let v = args.get(i).ok_or("--min-risk requiere un número")?;
                opts.min_risk = v.parse().map_err(|_| format!("--min-risk inválido: {v}"))?;
            }
            "--limit" => {
                i += 1;
                let v = args.get(i).ok_or("--limit requiere un número")?;
                opts.limit = v.parse().map_err(|_| format!("--limit inválido: {v}"))?;
            }
            other if !other.starts_with("--") => {
                if path.is_some() {
                    return Err(format!("archivo duplicado: {other}"));
                }
                path = Some(other.to_string());
            }
            other => return Err(format!("opción desconocida: {other}")),
        }
        i += 1;
    }
    let Some(path) = path else {
        return Err("read requiere un archivo de captura".into());
    };
    let palette = Palette::auto(no_color);

    // Modo eventos: JSONL por paquete (no requiere tabla de flujos).
    if events {
        let expr: Option<Expr> = match &opts.filter {
            Some(f) => Some(socshark_filter_dsl::parse(f)?),
            None => None,
        };
        pipeline::for_each_packet(&path, |dp| {
            if pipeline::packet_matches(dp, &expr) {
                println!("{}", packet_json(dp).to_string());
            }
        })?;
        return Ok(std::process::ExitCode::SUCCESS);
    }

    let report = pipeline::analyze(&path, &opts)?;
    let visible = pipeline::visible_flows(&report, &opts)?;

    if let Some(file) = export_ecs {
        export_ecs_file(&report, &visible, &file)?;
        eprintln!("ecs: {} flujos exportados a {}", visible.len(), file);
    }
    if let Some(file) = export_suricata {
        let best = visible
            .first()
            .map(|&i| &report.table.flows()[i])
            .ok_or("no hay flujos para generar regla")?;
        std::fs::write(
            &file,
            socshark_soc_engine::siem_exporter::suricata_rule(best) + "\n",
        )
        .map_err(|e| format!("no se pudo escribir {file}: {e}"))?;
        eprintln!("suricata: regla escrita en {file}");
    }

    if json {
        let j = report_json(&report, &visible);
        println!("{}", j.to_pretty());
    } else {
        render_text(&report, &visible, &opts, &palette);
    }
    Ok(std::process::ExitCode::SUCCESS)
}

/// JSON por paquete (modo --events).
pub fn packet_json(dp: &DissectedPacket) -> Json {
    let mut obj = Vec::new();
    obj.push(("frame", Json::Int(dp.index as i64)));
    obj.push(("ts", Json::s(timefmt::format_ts_us(dp.ts_us))));
    obj.push(("cap_len", Json::Int(dp.cap_len as i64)));
    if let Some(t) = &dp.five_tuple {
        obj.push(("src", Json::s(format!("{}:{}", t.src, t.src_port))));
        obj.push(("dst", Json::s(format!("{}:{}", t.dst, t.dst_port))));
        obj.push(("proto", Json::Int(t.proto as i64)));
    }
    obj.push(("l7", Json::s(dp.l7_proto)));
    if let (Some(s), Some(d)) = (dp.src_mac, dp.dst_mac) {
        obj.push(("eth", Json::s(format!("{s} → {d}"))));
    }
    match dp.app.as_ref() {
        Some(AppInfo::Dns(d)) => {
            let mut m = Vec::new();
            if let Some(q) = d.qname() {
                m.push(("qname", Json::s(q)));
            }
            m.push(("is_response", Json::Bool(d.is_response)));
            m.push(("answers", Json::Int(d.answers.len() as i64)));
            obj.push(("dns", Json::obj(m)));
        }
        Some(AppInfo::Http(h)) => match h {
            socshark_dissectors::layer7::http::HttpMessage::Request(r) => {
                obj.push((
                    "http",
                    Json::obj(vec![
                        ("method", Json::s(r.method.clone())),
                        ("target", Json::s(r.target.clone())),
                        (
                            "host",
                            match r.header("host") {
                                Some(h) => Json::s(h),
                                None => Json::Null,
                            },
                        ),
                    ]),
                ));
            }
            socshark_dissectors::layer7::http::HttpMessage::Response(r) => {
                obj.push((
                    "http",
                    Json::obj(vec![
                        ("status", Json::Int(r.status as i64)),
                        ("reason", Json::s(r.reason.clone())),
                    ]),
                ));
            }
        },
        Some(AppInfo::Tls(t)) => {
            if let Some(ch) = &t.client_hello {
                obj.push((
                    "tls",
                    Json::obj(vec![
                        (
                            "sni",
                            match &ch.sni {
                                Some(s) => Json::s(s.clone()),
                                None => Json::Null,
                            },
                        ),
                        ("ja4_like", Json::s(ch.ja4_like(t.version))),
                    ]),
                ));
            } else {
                obj.push(("tls", Json::s("handshake/record")));
            }
        }
        None => {}
    }
    if let Some(p) = dp.app_payload {
        if !p.is_empty() {
            let head = &p[..p.len().min(64)];
            let printable: String = head
                .iter()
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            obj.push(("payload_preview", Json::s(printable)));
            obj.push((
                "payload_entropy",
                Json::Num(socshark_common::entropy::shannon_entropy(head)),
            ));
        }
    }
    Json::obj(obj)
}

/// Informe JSON completo.
pub fn report_json(report: &CaptureReport, visible: &[usize]) -> Json {
    let flows: Vec<Json> = visible
        .iter()
        .map(|&i| report.table.flows()[i].to_json())
        .collect();
    let hidden = report.table.len() - visible.len();
    Json::obj(vec![
        ("tool", Json::s("soc-shark")),
        ("version", Json::s(env!("CARGO_PKG_VERSION"))),
        (
            "capture",
            Json::obj(vec![
                ("path", Json::s(report.path.clone())),
                ("link", Json::s(report.link.as_str())),
                ("packets", Json::Int(report.packets as i64)),
                ("packet_errors", Json::Int(report.packet_errors as i64)),
                ("bytes", Json::Int(report.bytes as i64)),
                (
                    "first_ts",
                    Json::s(timefmt::format_ts_us(report.first_ts_us)),
                ),
                ("last_ts", Json::s(timefmt::format_ts_us(report.last_ts_us))),
            ]),
        ),
        (
            "summary",
            Json::obj(vec![
                ("flows", Json::Int(report.table.len() as i64)),
                ("flows_visible", Json::Int(visible.len() as i64)),
                ("flows_hidden", Json::Int(hidden as i64)),
                ("alerts", Json::Int(report.engine_stats.alerts as i64)),
                ("artifacts", Json::Int(report.engine_stats.artifacts as i64)),
                (
                    "beacon_flows",
                    Json::Int(report.engine_stats.beacon_flows as i64),
                ),
                (
                    "passive_dns_pairs",
                    Json::Int(report.engine_stats.passive_dns_pairs as i64),
                ),
            ]),
        ),
        ("protocols", {
            let hist = session_db::protocol_histogram(report.table.flows());
            Json::Obj(
                hist.into_iter()
                    .map(|(k, n)| (k.to_string(), Json::Int(n as i64)))
                    .collect(),
            )
        }),
        ("flows", Json::Arr(flows)),
    ])
}

/// Exportación ECS JSONL.
pub fn export_ecs_file(
    report: &CaptureReport,
    visible: &[usize],
    path: &str,
) -> Result<(), String> {
    use std::io::Write;
    let mut out =
        std::fs::File::create(path).map_err(|e| format!("no se pudo crear {path}: {e}"))?;
    for &i in visible {
        let f = &report.table.flows()[i];
        writeln!(
            out,
            "{}",
            socshark_soc_engine::siem_exporter::flow_to_ecs(f).to_string()
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Render de texto: cabecera + radar + tabla + detalle de alertas.
pub fn render_text(report: &CaptureReport, visible: &[usize], opts: &ReadOpts, pal: &Palette) {
    let flows = report.table.flows();
    let n_alerts: usize = flows.iter().map(|f| f.alerts.len()).sum();
    let crit = flows
        .iter()
        .flat_map(|f| &f.alerts)
        .filter(|a| a.severity == Severity::Critical)
        .count();
    let high = flows
        .iter()
        .flat_map(|f| &f.alerts)
        .filter(|a| a.severity == Severity::High)
        .count();
    let medium = flows
        .iter()
        .flat_map(|f| &f.alerts)
        .filter(|a| a.severity == Severity::Medium)
        .count();
    let low = flows
        .iter()
        .flat_map(|f| &f.alerts)
        .filter(|a| a.severity == Severity::Low)
        .count();
    let noise = flows.iter().filter(|f| f.is_background_noise).count();
    let artifacts: Vec<&socshark_common::soc_types::Artifact> =
        flows.iter().flat_map(|f| &f.extracted_files).collect();

    println!(
        "{}",
        pal.bold(&format!(
            "═══ soc-shark {} — Informe SOC ═══",
            env!("CARGO_PKG_VERSION")
        ))
    );
    println!(
        "Captura: {} · {} paquetes{} · {} · enlace {}",
        report.path,
        report.packets,
        if report.packet_errors > 0 {
            format!(" ({} err.)", report.packet_errors)
        } else {
            String::new()
        },
        format_bytes(report.bytes),
        report.link.as_str(),
    );
    println!(
        "Flujos: {} (ruido {} oculto) · Alertas: {} {}{}{}{} · Artefactos: {} · PassiveDNS: {} pares",
        report.table.len(),
        noise,
        n_alerts,
        pal.red(&format!("C{crit}")),
        pal.red(&format!(" A{high}")),
        pal.yellow(&format!(" M{medium}")),
        pal.cyan(&format!(" L{low}")),
        artifacts.len(),
        report.engine_stats.passive_dns_pairs,
    );
    println!("{}", pal.gray(&"─".repeat(118)));

    // Tabla de flujos.
    let shown = visible.len().min(opts.limit);
    println!(
        "{:<4} {:<12} {:<8} {:<22} {:<22} {:<5} {:<34} {}",
        "#", "TIEMPO", "DUR", "ORIGEN", "DESTINO", "PROTO", "RESUMEN", "RIESGO"
    );
    for &i in visible.iter().take(shown) {
        let f = &flows[i];
        let tiempo = timefmt::format_ts_short(f.first_seen_us);
        let dur = timefmt::format_duration_us(f.duration_ms * 1000);
        let origen = format!("{}:{}", f.key.src, f.key.sport);
        let mut destino = format!("{}:{}", f.key.dst, f.key.dport);
        if let Some(d) = &f.resolved_domain {
            destino.push_str(&format!(" [{d}]"));
        }
        let destino = trunc(&destino, 22);
        let proto = f.l7_protocol;
        let resumen = trunc(&f.human_summary, 34);
        let riesgo = risk_cell(f.risk_score, pal);
        let line = format!(
            "{:<4} {:<12} {:<8} {:<22} {:<22} {:<5} {:<34} {}",
            f.flow_id,
            tiempo,
            dur,
            trunc(&origen, 22),
            destino,
            proto,
            resumen,
            riesgo
        );
        let line = if f.risk_score >= 60 {
            pal.red(&line)
        } else if f.risk_score >= 30 {
            pal.yellow(&line)
        } else {
            line
        };
        println!("{line}");
    }
    if visible.len() > shown {
        println!(
            "{} ({} flujos más; usa --limit o refina el filtro)",
            pal.gray("…"),
            visible.len() - shown
        );
    }

    // Radar: alertas agrupadas.
    let mut alerts: Vec<(&socshark_common::soc_types::SocAlert, u64)> = Vec::new();
    for f in flows {
        for a in &f.alerts {
            if let Some(slot) = alerts
                .iter_mut()
                .find(|(x, _)| x.id == a.id && x.title == a.title)
            {
                slot.1 += 1;
            } else {
                alerts.push((a, 1));
            }
        }
    }
    alerts.sort_by_key(|(a, _)| std::cmp::Reverse(a.severity));
    if !alerts.is_empty() {
        println!("{}", pal.bold("── Radar SOC ──"));
        for (a, n) in alerts.iter().take(12) {
            let (icon, colored) = match a.severity {
                Severity::Critical | Severity::High => ("🚨", pal.red(a.severity.label_es())),
                Severity::Medium => ("⚠️ ", pal.yellow(a.severity.label_es())),
                Severity::Low => ("ℹ️ ", pal.cyan(a.severity.label_es())),
            };
            let mitre = a.mitre.map(|m| format!(" [{m}]")).unwrap_or_default();
            println!("  {icon} {colored} {} ×{n}{mitre}", a.title);
            println!("     {}", pal.gray(&trunc(&a.detail, 100)));
        }
    }
    if !artifacts.is_empty() {
        println!("{}", pal.bold("── Artefactos extraídos ──"));
        for a in artifacts.iter().take(10) {
            let flag: String = if a.masquerade {
                pal.red(" ¡MASQUERADE!")
            } else {
                String::new()
            };
            println!(
                "  📦 {} ({} bytes, magic {}){} sha256={}",
                a.name,
                a.size,
                a.magic,
                flag,
                &a.sha256[..16.min(a.sha256.len())]
            );
        }
    }
    if visible.is_empty() {
        println!("{}", pal.gray("Sin flujos visibles con el filtro actual."));
    }
}

fn risk_cell(risk: u8, pal: &Palette) -> String {
    if risk == 0 {
        return pal.gray("0");
    }
    let s = format!("{risk:>3}");
    if risk >= 60 {
        pal.red(&s)
    } else if risk >= 30 {
        pal.yellow(&s)
    } else {
        s
    }
}

pub fn trunc(s: &str, w: usize) -> String {
    // Cuenta caracteres, no bytes (importante con emojis y acentos).
    if s.chars().count() <= w {
        s.to_string()
    } else {
        let head: String = s.chars().take(w.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

fn format_bytes(b: u64) -> String {
    if b >= 1_048_576 {
        format!("{:.1} MiB", b as f64 / 1_048_576.0)
    } else if b >= 1024 {
        format!("{:.1} KiB", b as f64 / 1024.0)
    } else {
        format!("{b} B")
    }
}

// Referencia para mantener el import usado en futuras extensiones de filtro
// por paquete dentro del informe textual.
#[allow(dead_code)]
fn _facts_used(_p: &PacketFacts<'_>, _f: &FlowFacts<'_>) {}
