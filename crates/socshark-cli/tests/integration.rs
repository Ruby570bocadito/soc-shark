//! Test de integración del pipeline completo sobre el escenario demo.
//!
//! Ejecuta la MISMA ruta de código que el binario (la lib `socshark_cli`),
//! así que estos tests son la red de seguridad del CLI completo.

use std::path::PathBuf;

use socshark_cli::pipeline::run_capture;
use socshark_core::config::PipelineConfig;
use socshark_core::{FlowState, L7Protocol};
use socshark_testgen::{sample_pcap_packets, write_pcap};

/// Genera el pcap demo en el directorio temporal del proceso.
fn demo_pcap(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("socshark-demo-{tag}-{}.pcap", std::process::id()));
    write_pcap(&path, 1, &sample_pcap_packets()).unwrap();
    path
}

#[test]
fn pipeline_end_to_end_sin_ruido() {
    let path = demo_pcap("e2e");
    let cfg = PipelineConfig::default();
    let out = run_capture(&path, None, false, &cfg).unwrap();

    // El ruido (NTP + mDNS) no debe aparecer por defecto.
    assert!(out.flows.iter().all(|f| !f.is_background_noise));

    // Escenario esperado: 1 DNS + 1 TLS + 1 túnel DNS + 5 escaneo + 1 SSH
    // + 1 HTTP = 10 flujos.
    let ids: Vec<String> = out.flows.iter().map(|f| f.flow_id.0.clone()).collect();
    assert_eq!(out.flows.len(), 10, "flujos obtenidos: {ids:#?}");

    // Túnel DNS detectado con su mapeo MITRE.
    let tunel = out
        .flows
        .iter()
        .find(|f| f.alerts.iter().any(|a| a.id == "DNS-TUNNELING"))
        .expect("debe detectar el túnel DNS");
    assert!(tunel.risk_score >= 45);
    assert_eq!(tunel.alerts[0].mitre.as_deref(), Some("T1048.003"));

    // Los 5 SYNs del escaneo deben quedar alertados (uno por flujo).
    let escaneos = out
        .flows
        .iter()
        .filter(|f| f.alerts.iter().any(|a| a.id == "PORT-SCAN"))
        .count();
    assert_eq!(escaneos, 5, "los 5 SYNs del escaneo deben marcarse");

    // El flujo TLS debe estar cerrado limpiamente con sus direcciones bien.
    let tls = out
        .flows
        .iter()
        .find(|f| f.l7_protocol == L7Protocol::Tls)
        .expect("debe existir el flujo TLS");
    assert_eq!(tls.state, FlowState::Closed);
    assert_eq!(
        tls.packets, 4,
        "SYN, ACK, PSH(client hello) y FIN del cliente"
    );
    assert_eq!(tls.packets_rev, 3, "SYN-ACK, PSH(server hello) y FIN-ACK");
    assert!(tls.human_summary.contains("TLS"));

    // DNS pasivo: HTTP hacia la IP de example.com queda etiquetado.
    let http = out
        .flows
        .iter()
        .find(|f| f.l7_protocol == L7Protocol::Http)
        .expect("debe existir el flujo HTTP");
    assert_eq!(http.resolved_domain.as_deref(), Some("example.com"));
    assert!(http.human_summary.contains("destino: example.com"));

    // Serialización JSONL estable (clave flow_id presente).
    let js = serde_json::to_string(&out.flows[0]).unwrap();
    assert!(js.contains("\"flow_id\""));

    std::fs::remove_file(&path).ok();
}

#[test]
fn filtro_dsl_y_ruido() {
    let path = demo_pcap("filtro");
    let cfg = PipelineConfig::default();

    // Con ruido: 10 + NTP + mDNS = 12.
    let todo = run_capture(&path, None, true, &cfg).unwrap();
    assert_eq!(todo.flows.len(), 12);
    assert!(todo.flows.iter().any(|f| f.is_background_noise));

    // DSL: solo el flujo TLS toca el 443.
    let filtrado = run_capture(&path, Some("tcp.port == 443"), false, &cfg).unwrap();
    assert_eq!(filtrado.flows.len(), 1);
    assert!(filtrado.flows[0].flow_id.0.contains("443"));

    // DSL: el qname del túnel contiene "evil".
    let por_qname = run_capture(&path, Some("dns.qname contains \"evil\""), false, &cfg).unwrap();
    assert_eq!(por_qname.flows.len(), 1);
    assert!(por_qname.flows[0].risk_score >= 45);

    // DSL: riesgo alto.
    let por_riesgo = run_capture(&path, Some("flow.risk >= 30"), false, &cfg).unwrap();
    assert_eq!(por_riesgo.flows.len(), 6); // 5 escaneo + 1 túnel

    std::fs::remove_file(&path).ok();
}

#[test]
fn jsonl_se_escribe_correctamente() {
    let path = demo_pcap("jsonl");
    let cfg = PipelineConfig::default();
    let out = run_capture(&path, None, false, &cfg).unwrap();

    let destino = std::env::temp_dir().join(format!("socshark-out-{}.jsonl", std::process::id()));
    socshark_cli::output::write_jsonl(&destino, &out.flows).unwrap();

    let contenido = std::fs::read_to_string(&destino).unwrap();
    let lineas: Vec<&str> = contenido.lines().collect();
    assert_eq!(lineas.len(), out.flows.len());
    // Cada línea debe ser JSON válido con flow_id.
    for linea in &lineas {
        let v: serde_json::Value = serde_json::from_str(linea).unwrap();
        assert!(v.get("flow_id").is_some());
    }

    std::fs::remove_file(&destino).ok();
    std::fs::remove_file(&path).ok();
}
