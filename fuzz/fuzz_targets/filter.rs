//! DSL de filtrado: `lex` + `parse` sobre UTF-8 arbitrario y, si compila,
//! `eval` contra un flujo con todos los campos poblados (DNS, TLS, proceso,
//! alertas, archivos) para recorrer cada rama del evaluador.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use socshark_core::EnrichedFlow;

/// Flujo de referencia. Se construye desde JSON para que los campos nuevos
/// con `#[serde(default)]` no rompan este objetivo (no está en el workspace
/// y el CI estable no lo compila).
fn flow() -> &'static EnrichedFlow {
    static FLOW: OnceLock<EnrichedFlow> = OnceLock::new();
    FLOW.get_or_init(|| {
        serde_json::from_str(
            r#"{
                "flow_id": "udp/192.168.1.10:53000-8.8.8.8:53",
                "state": "Closed",
                "transport": "Udp",
                "l7_protocol": "Dns",
                "ip_version": 4,
                "src_ip": "192.168.1.10",
                "src_port": 53000,
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "66:77:88:99:aa:bb",
                "first_seen_micros": 1700000000000000,
                "last_seen_micros": 1700000030000000,
                "duration_micros": 30000000,
                "packets": 10,
                "bytes": 1200,
                "packets_rev": 9,
                "bytes_rev": 3400,
                "tcp_flags": {"syn": 1, "ack": 5, "fin": 1, "rst": 0, "psh": 2, "urg": 0},
                "process_name": "curl",
                "pid": 4242,
                "user": "analista",
                "resolved_domain": "example.com",
                "dns": {
                    "is_response": true,
                    "rcode": 0,
                    "queries": [{"name": "example.com", "qtype": 1}],
                    "answers": [
                        {"name": "example.com", "rtype": 1, "ttl": 300, "address": "93.184.216.34", "target": null},
                        {"name": "www.example.com", "rtype": 5, "ttl": 300, "address": null, "target": "example.com"}
                    ]
                },
                "ja4_fingerprint": "t13d1516h2_8daaf6152771_02713d6af862",
                "tls_sni": "example.com",
                "interval_stats": {"intervals": 9, "mean_micros": 3000000, "std_micros": 1000},
                "threat_intel": ["TOR-EXIT"],
                "is_background_noise": false,
                "human_summary": "consulta DNS",
                "risk_score": 42,
                "alerts": [{"id": "DNS-TUNNELING", "name": "Túnel DNS", "severity": "High", "detail": "x", "mitre": "T1071.004"}],
                "extracted_files": [{"name": "factura.jpg", "size": 1024, "sha256": null, "magic": "PE32", "masquerading_suspect": true}]
            }"#,
        )
        .expect("flujo de referencia válido")
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let _ = socshark_filter::lex(input);
    if let Ok(expr) = socshark_filter::parse(input) {
        let _ = socshark_filter::eval(&expr, flow());
    }
});
