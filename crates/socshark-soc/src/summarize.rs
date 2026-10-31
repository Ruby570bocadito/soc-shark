//! Traducción semántica: de estructura de datos a lenguaje humano.
//!
//! El `human_summary` es la columna "qué está pasando" de la UI (Session
//! Accordion del diseño SOC): una línea que un analista de guardia entiende
//! sin abrir el paquete. Las fases posteriores añadirán contextos más ricos
//! (nombres de proceso de eBPF, dominio geográfico, banners HTTP).

use socshark_core::{dns_rcode_str, dns_type_str, EnrichedFlow, FlowState, L7Protocol, Transport};

use crate::{tr, Lang};

/// Genera el `human_summary` del flujo (en español: es el que se exporta).
pub fn summarize(flow: &EnrichedFlow) -> String {
    summarize_in(flow, Lang::Es)
}

/// Como [`summarize`], en el idioma dado (para mostrarlo en la GUI; el
/// JSONL guarda siempre el español).
pub fn summarize_in(flow: &EnrichedFlow, lang: Lang) -> String {
    let mut out = String::new();
    if flow.is_background_noise {
        out.push_str(lang.pick("[ruido] ", "[noise] "));
    }

    match flow.l7_protocol {
        L7Protocol::Dns => summarize_dns(flow, &mut out, lang),
        _ => summarize_transport(flow, &mut out, lang),
    }

    if let Some(domain) = &flow.resolved_domain {
        if flow.l7_protocol != L7Protocol::Dns {
            out.push_str(&tr!(
                lang,
                " · destino: {domain}",
                " · destination: {domain}"
            ));
        }
    }
    if !flow.alerts.is_empty() {
        let worst = flow
            .alerts
            .iter()
            .map(|a| a.severity)
            .max()
            .unwrap_or(Severity::Info);
        let worst = match lang {
            Lang::Es => worst.as_str(),
            Lang::En => severity_en(worst),
        };
        out.push_str(&tr!(
            lang,
            " · ⚠ {} alerta(s), la peor {}",
            " · ⚠ {} alert(s), worst {}",
            flow.alerts.len(),
            worst
        ));
    }
    out
}

fn summarize_dns(flow: &EnrichedFlow, out: &mut String, lang: Lang) {
    let dir = endpoint_str(flow);
    match flow.dns.as_ref() {
        Some(dns) if dns.is_response && !dns.answers.is_empty() => {
            let a = &dns.answers[0];
            let objetivo = a
                .address
                .map(|ip| ip.to_string())
                .or_else(|| a.target.clone())
                .unwrap_or_else(|| a.name.clone());
            let qname = dns
                .queries
                .first()
                .map(|q| q.name.as_str())
                .unwrap_or(a.name.as_str());
            out.push_str(&format!(
                "DNS {}: {} → {} ({})",
                dir,
                qname,
                objetivo,
                dns_type_str(a.rtype)
            ));
        }
        Some(dns) if dns.is_response => {
            let qname = dns.queries.first().map(|q| q.name.as_str()).unwrap_or("?");
            out.push_str(&tr!(
                lang,
                "DNS {}: {} sin respuesta (rcode {})",
                "DNS {}: {} no answer (rcode {})",
                dir,
                qname,
                dns.rcode
                    .map(|r| dns_rcode_str(r).to_string())
                    .unwrap_or_else(|| "?".into())
            ));
        }
        Some(dns) => {
            // Un mensaje con QDCOUNT=0 (malformado pero parseable, visto por
            // el fuzzer) no lleva consultas: se describe sin qname.
            match dns.queries.first() {
                Some(q) => out.push_str(&tr!(
                    lang,
                    "DNS {}: consulta {} ({})",
                    "DNS {}: query {} ({})",
                    dir,
                    q.name,
                    dns_type_str(q.qtype)
                )),
                None => out.push_str(&tr!(
                    lang,
                    "DNS {}: consulta sin qname",
                    "DNS {}: query without qname",
                    dir
                )),
            }
        }
        None => out.push_str(&format!("DNS {dir}")),
    }
}

fn summarize_transport(flow: &EnrichedFlow, out: &mut String, lang: Lang) {
    let dir = endpoint_str(flow);
    let proto = match flow.l7_protocol {
        L7Protocol::Unknown => flow.transport.as_str().to_string(),
        other => format!("{}/{}", flow.transport.as_str(), other.as_str()),
    };
    let volumen = fmt_bytes(flow.bytes + flow.bytes_rev);
    let paquetes = flow.packets + flow.packets_rev;
    out.push_str(&tr!(
        lang,
        "{proto} {dir} · {paquetes} paq · {volumen}",
        "{proto} {dir} · {paquetes} pkts · {volumen}"
    ));

    if flow.transport == Transport::Tcp {
        let state = match (lang, flow.state) {
            (Lang::Es, s) => s.as_str(),
            (Lang::En, FlowState::Active) => "active",
            (Lang::En, FlowState::Idle) => "idle",
            (Lang::En, FlowState::Closed) => "closed",
        };
        out.push_str(&format!(" · {state}"));
        if flow.tcp_flags.rst > 0 {
            out.push_str(" (RST)");
        }
    }
}

/// Severidad en inglés (la de `Severity::as_str` es la del contrato).
pub fn severity_en(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// `ip:puerto → ip:puerto`, sin puertos para tráfico sin L4 (ICMP).
fn endpoint_str(flow: &EnrichedFlow) -> String {
    if flow.transport == Transport::Icmp || (flow.src_port == 0 && flow.dst_port == 0) {
        format!("{} → {}", flow.src_ip, flow.dst_ip)
    } else {
        format!(
            "{}:{} → {}:{}",
            flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port
        )
    }
}

/// Formatea bytes con unidades legibles (`512 B`, `5.2 KB`, `1.3 MB`, ...).
pub fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0usize;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

use socshark_core::Severity;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::flujo_basico;
    use socshark_core::FlowState;

    #[test]
    fn unidades_de_bytes() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(2048), "2.0 KB");
        assert_eq!(fmt_bytes(1_572_864), "1.5 MB");
    }

    #[test]
    fn ruido_va_prefijado() {
        let mut f = flujo_basico(17, 123, 123);
        f.is_background_noise = true;
        assert!(summarize(&f).starts_with("[ruido] "));
    }

    #[test]
    fn resumen_tcp_incluye_estado_y_volumen() {
        let mut f = flujo_basico(6, 52000, 443);
        f.state = FlowState::Closed;
        f.l7_protocol = L7Protocol::Tls;
        f.tcp_flags.rst = 1;
        let s = summarize(&f);
        assert!(s.contains("TLS"));
        assert!(s.contains("cerrado"));
        assert!(s.contains("RST"));
        let en = summarize_in(&f, Lang::En);
        assert!(en.contains("closed") && en.contains("pkts"), "{en}");
        assert_eq!(summarize(&f), summarize_in(&f, Lang::Es));
    }
}
