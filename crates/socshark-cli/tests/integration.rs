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
    // + 1 HTTP + 1 DNS-IPv6 (Fase 2) = 11 flujos.
    let ids: Vec<String> = out.flows.iter().map(|f| f.flow_id.0.clone()).collect();
    assert_eq!(out.flows.len(), 11, "flujos obtenidos: {ids:#?}");

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

    // Con ruido: 11 + NTP + mDNS = 13.
    let todo = run_capture(&path, None, true, &cfg).unwrap();
    assert_eq!(todo.flows.len(), 13);
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

// ------------------------------------------------------------ Fase 2

#[test]
fn ipv6_del_escenario_y_dsl_ip_version() {
    let path = demo_pcap("v6");
    let cfg = PipelineConfig::default();

    // El DSL separa la familia IPv6 sin ambigüedad.
    let v6 = run_capture(&path, Some("ip.version == 6"), false, &cfg).unwrap();
    assert_eq!(v6.flows.len(), 1);
    let f = &v6.flows[0];
    assert_eq!(f.ip_version, 6);
    assert_eq!(f.l7_protocol, L7Protocol::Dns);
    assert!(f.flow_id.0.contains("2001:4860:4860::8888"));
    let dns = f.dns.as_ref().expect("resumen DNS v6");
    assert_eq!(dns.queries[0].name, "v6.example.com");

    // Y su respuesta AAAA alimenta el DNS pasivo con una dirección v6.
    let sin_filtro = run_capture(&path, None, false, &cfg).unwrap();
    let flujos_v6_resueltos: Vec<_> = sin_filtro
        .flows
        .iter()
        .filter(|f| f.resolved_domain.as_deref() == Some("v6.example.com") && f.ip_version == 6)
        .collect();
    assert_eq!(flujos_v6_resueltos.len(), 1);

    // Literal IPv6 nativo como bareword del DSL (sin comillas).
    let literal = run_capture(&path, Some("ip.dst == 2001:4860:4860::8888"), false, &cfg).unwrap();
    assert_eq!(literal.flows.len(), 1);

    std::fs::remove_file(&path).ok();
}

#[test]
fn follow_reensambla_stream_http_con_segmentos_desordenados() {
    // Pcap propio: el servidor responde con la parte 2 ANTES que la parte 1
    // (reordenado en la captura); `follow` debe reconstruir el orden lógico.
    let (sp, cseq, sseq) = (41000u16, 2000u32, 8000u32);
    let part1: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
    let part2: &[u8] = b"RESPUESTA-DEL-SERVIDOR-12345678901234567890123456789";

    let mut pkts: Vec<(u64, Vec<u8>)> = Vec::new();
    #[allow(clippy::vec_init_then_push)]
    {
        pkts.push((
            1,
            socshark_testgen::frame_tcp(
                socshark_testgen::MAC_HOST_B,
                socshark_testgen::MAC_ROUTER,
                socshark_testgen::HOST_B,
                socshark_testgen::WEB,
                sp,
                80,
                cseq,
                sseq,
                socshark_testgen::flags::PSH_ACK,
                b"GET /a.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
            ),
        ));
        // Parte 2 (fuera de orden)...
        pkts.push((
            2,
            socshark_testgen::frame_tcp(
                socshark_testgen::MAC_ROUTER,
                socshark_testgen::MAC_HOST_B,
                socshark_testgen::WEB,
                socshark_testgen::HOST_B,
                80,
                sp,
                sseq + part1.len() as u32,
                cseq + 43,
                socshark_testgen::flags::PSH_ACK,
                part2,
            ),
        ));
        // ...y luego la parte 1.
        pkts.push((
            3,
            socshark_testgen::frame_tcp(
                socshark_testgen::MAC_ROUTER,
                socshark_testgen::MAC_HOST_B,
                socshark_testgen::WEB,
                socshark_testgen::HOST_B,
                80,
                sp,
                sseq,
                cseq + 43,
                socshark_testgen::flags::PSH_ACK,
                part1,
            ),
        ));
    }

    let path = std::env::temp_dir().join(format!("socshark-follow-{}.pcap", std::process::id()));
    socshark_testgen::write_pcap(&path, 1, &pkts).unwrap();

    let cfg = PipelineConfig {
        collect_streams: true,
        ..PipelineConfig::default()
    };
    let (flow, stream) = socshark_cli::pipeline::run_follow(&path, "tcp/93.184.216.34:80", &cfg)
        .unwrap()
        .expect("el flujo HTTP debe existir");

    assert_eq!(flow.l7_protocol, L7Protocol::Http);
    assert_eq!(
        stream.client,
        b"GET /a.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    );
    let esperado = [part1, part2].concat();
    assert_eq!(
        stream.server, esperado,
        "partes reordenadas en orden de seq"
    );
    assert!(!stream.server_lossy);

    std::fs::remove_file(&path).ok();
}

// ------------------------------------------------- Fase 2: pool concurrente

#[test]
fn el_pool_concurrente_produce_la_misma_salida_que_el_camino_secuencial() {
    // Contrato de determinismo del pool (ADR-010): con workers > 1 la
    // disección corre en hilos, pero la agregación es ordenada, así que los
    // flujos exportados (JSON) deben ser idénticos byte a byte.
    let path = demo_pcap("pool");

    let seq_cfg = PipelineConfig::default();
    let seq = run_capture(&path, None, true, &seq_cfg).unwrap();

    let par_cfg = PipelineConfig {
        workers: 4,
        ..PipelineConfig::default()
    };
    let par = run_capture(&path, None, true, &par_cfg).unwrap();

    assert_eq!(seq.stats, par.stats, "las estadísticas deben coincidir");
    assert_eq!(seq.flows.len(), par.flows.len());

    let json_seq: Vec<String> = seq
        .flows
        .iter()
        .map(|f| serde_json::to_string(f).unwrap())
        .collect();
    let json_par: Vec<String> = par
        .flows
        .iter()
        .map(|f| serde_json::to_string(f).unwrap())
        .collect();
    assert_eq!(json_seq, json_par, "JSONL idéntico entre workers 1 y 4");

    std::fs::remove_file(&path).ok();
}
