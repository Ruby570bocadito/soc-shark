//! Test de integración del pipeline completo: pcap sintético → informe SOC.
//!
//! Reproduce en Rust el escenario del demo (`tools/gen_demo_pcap.py`) en
//! versión mínima: ruido NTP + beaconing C2 + descarga disfrazada, y
//! verifica que el motor completo (dissect → flows → SOC → filtro DSL)
//! produce el triaje esperado.

use socshark_capture_core::{LinkType, PacketRecord};
use socshark_dissectors::view::dissect;

// ── Helpers de construcción de tramas ──────────────────────────────────────

fn eth(src: [u8; 6], dst: [u8; 6], etype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&etype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn ip4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut h = vec![
        0x45u8,
        0,
        (total >> 8) as u8,
        total as u8,
        0,
        1,
        0x40,
        0,
        64,
        proto,
        0,
        0,
    ];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let mut sum = 0u32;
    for w in h[0..20].chunks(2) {
        sum += u16::from_be_bytes([w[0], w[1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    h[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    h.extend_from_slice(payload);
    h
}

fn tcp_seg(sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&100u32.to_be_bytes());
    t.extend_from_slice(&200u32.to_be_bytes());
    t.push(0x50);
    t.push(flags);
    t.extend_from_slice(&64_000u16.to_be_bytes());
    t.extend_from_slice(&0u16.to_be_bytes());
    t.extend_from_slice(&0u16.to_be_bytes());
    t.extend_from_slice(payload);
    t
}

fn udp_seg(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    u.extend_from_slice(&0u16.to_be_bytes());
    u.extend_from_slice(payload);
    u
}

fn frame_c2s(ts: u64, sport: u16, dport: u16, flags: u8, payload: &[u8], dst: [u8; 4]) -> Vec<u8> {
    let _ = ts;
    let ip = ip4(
        [192, 168, 1, 50],
        dst,
        6,
        &tcp_seg(sport, dport, flags, payload),
    );
    eth([0xaa; 6], [0xbb; 6], 0x0800, &ip)
}

fn frame_s2c(sport: u16, dport: u16, flags: u8, payload: &[u8], src: [u8; 4]) -> Vec<u8> {
    let ip = ip4(
        src,
        [192, 168, 1, 50],
        6,
        &tcp_seg(sport, dport, flags, payload),
    );
    eth([0xbb; 6], [0xaa; 6], 0x0800, &ip)
}

/// pcap LE con: 1 flujo NTP (ruido) + beaconing C2 cada 10 s + GET disfrazado.
fn build_pcap() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65_535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    let base: u64 = 1_735_689_600_000_000; // 2025-01-01T00:00:00Z

    let mut add = |ts_us: u64, frame: &[u8], out: &mut Vec<u8>| {
        out.extend_from_slice(&((ts_us / 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&((ts_us % 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(frame);
    };

    // Ruido: NTP x4 (udp 123).
    for i in 0..4 {
        let ip = ip4(
            [192, 168, 1, 50],
            [162, 159, 200, 123],
            17,
            &udp_seg(123, 123, &[0x1b; 48]),
        );
        add(
            base + i * 10_000_000,
            &eth([0xaa; 6], [0xbb; 6], 0x0800, &ip),
            &mut out,
        );
    }

    // Beaconing: HTTP POST cada 10 s al 4444 (6 llamadas).
    let beacon = b"POST /gate.php HTTP/1.1\r\nHost: c2.evil-domain.ru\r\nUser-Agent: \r\nContent-Length: 4\r\n\r\nABCD";
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    for i in 0..6usize {
        let t = base + 60_000_000 + (i as u64) * 10_000_000;
        let f = frame_c2s(t, 49_820, 4444, 0x18, beacon, [185, 22, 1, 9]);
        add(t, &f, &mut out);
        let f = frame_s2c(4444, 49_820, 0x18, reply, [185, 22, 1, 9]);
        add(t + 600_000, &f, &mut out);
    }

    // Descarga disfrazada: factura.pdf con magic MZ (respuesta del servidor).
    let t = base + 200_000_000;
    let req = b"GET /factura.pdf HTTP/1.1\r\nHost: docs.evil-cdn.ru\r\n\r\n";
    let f = frame_c2s(t, 49_815, 80, 0x18, req, [45, 33, 32, 156]);
    add(t, &f, &mut out);
    let mut body = b"MZ\x90\x00PE\x00\x00".to_vec();
    body.extend_from_slice(&[0u8; 80]);
    let mut res =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: 88\r\n\r\n".to_vec();
    res.extend_from_slice(&body);
    let f = frame_s2c(80, 49_815, 0x18, &res, [45, 33, 32, 156]);
    add(t + 500_000, &f, &mut out);

    out
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn pipeline_end_to_end_triage() {
    let pcap = build_pcap();
    let path = std::env::temp_dir().join(format!("socshark_it_{}.pcap", std::process::id()));
    std::fs::write(&path, &pcap).unwrap();

    let opts = socshark_daemon::pipeline::ReadOpts::default();
    let report = socshark_daemon::pipeline::analyze(path.to_str().unwrap(), &opts).unwrap();

    // Paquetes y flujos.
    assert_eq!(report.packets, 4 + 12 + 2, "todos los paquetes se leyeron");
    // La conversación bidireccional del beacon y la de factura se fusionan
    // en UNA fila cada una (propiedad Flow-First) → 3 flujos en total.
    assert_eq!(
        report.table.len(),
        3,
        "NTP + beacon(fusionado) + factura(fusionada)"
    );

    // Ruido: el flujo NTP (udp 123) queda etiquetado.
    let ntp = report
        .table
        .flows()
        .iter()
        .find(|f| f.key.dport == 123)
        .expect("flujo NTP presente");
    assert!(ntp.is_background_noise);

    // Beaconing detectado con CV perfecto.
    let beacon = report
        .table
        .flows()
        .iter()
        .find(|f| f.key.dport == 4444 && f.key.proto == 6 && f.bytes_c2s > 0)
        .expect("flujo C2 presente");
    assert!(
        beacon.alerts.iter().any(|a| a.id == "C2-BEACON"),
        "beaconing no detectado: {:?}",
        beacon.alerts.iter().map(|a| a.id).collect::<Vec<_>>()
    );
    assert!(beacon.alerts.iter().any(|a| a.id == "PORT-MISMATCH"));

    // Artefacto disfrazado (factura.pdf con MZ → Masquerading T1036).
    let factura = report
        .table
        .flows()
        .iter()
        .find(|f| f.http_target.as_deref() == Some("/factura.pdf"))
        .expect("flujo factura presente");
    assert_eq!(factura.extracted_files.len(), 1);
    assert_eq!(factura.extracted_files[0].magic, "MZ");
    assert!(factura.extracted_files[0].masquerade);
    assert!(factura.alerts.iter().any(|a| a.mitre == Some("T1036")));

    // Filtro DSL a nivel de flujo.
    let opts_f = socshark_daemon::pipeline::ReadOpts {
        filter: Some("flow.has_alert and not flow.noise".into()),
        ..Default::default()
    };
    let visible = socshark_daemon::pipeline::visible_flows(&report, &opts_f).unwrap();
    assert!(visible.len() >= 2, "al menos C2 y factura");
    assert!(visible
        .iter()
        .all(|&i| !report.table.flows()[i].is_background_noise));

    // Con min-risk: solo flujos con riesgo >= 60.
    let opts_r = socshark_daemon::pipeline::ReadOpts {
        min_risk: 60,
        ..Default::default()
    };
    let risky = socshark_daemon::pipeline::visible_flows(&report, &opts_r).unwrap();
    assert!(risky
        .iter()
        .all(|&i| report.table.flows()[i].risk_score >= 60));

    // Dissect directo: el paquete HTTP del beacon se identifica como HTTP.
    use socshark_capture_core::PacketSource as _;
    let mut src = socshark_capture_core::pcap::PcapFileSource::new(&pcap).unwrap();
    let mut http_seen = false;
    while let Some(item) = src.next_packet() {
        let rec: PacketRecord = item.unwrap();
        let dp = dissect(&rec, LinkType::Ethernet);
        if dp.l7_proto == "HTTP" {
            http_seen = true;
        }
    }
    assert!(http_seen, "el disector vio HTTP");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn ecs_y_suricata_exportables() {
    let pcap = build_pcap();
    let path = std::env::temp_dir().join(format!("socshark_it2_{}.pcap", std::process::id()));
    std::fs::write(&path, &pcap).unwrap();
    let report = socshark_daemon::pipeline::analyze(
        path.to_str().unwrap(),
        &socshark_daemon::pipeline::ReadOpts::default(),
    )
    .unwrap();
    let visible = socshark_daemon::pipeline::visible_flows(
        &report,
        &socshark_daemon::pipeline::ReadOpts::default(),
    )
    .unwrap();
    assert!(!visible.is_empty());
    let f = &report.table.flows()[visible[0]];
    let ecs = socshark_soc_engine::siem_exporter::flow_to_ecs(f);
    let s = ecs.to_string();
    assert!(s.contains("\"source\""));
    assert!(s.contains("\"destination\""));
    let rule = socshark_soc_engine::siem_exporter::suricata_rule(f);
    assert!(rule.starts_with("alert "));
    let _ = std::fs::remove_file(&path);
}
