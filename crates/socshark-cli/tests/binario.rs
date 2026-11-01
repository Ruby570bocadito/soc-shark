//! Tests del binario `socshark` de punta a punta: códigos de salida,
//! tuberías rotas y protección de la evidencia original.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn socshark() -> Command {
    Command::new(env!("CARGO_BIN_EXE_socshark"))
}

/// Copia de la demo en el temporal (los tests intentan pisarla).
fn demo_copia(tag: &str) -> PathBuf {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo.pcap");
    let dst = std::env::temp_dir().join(format!("socshark-bin-{tag}-{}.pcap", std::process::id()));
    std::fs::copy(&src, &dst).unwrap();
    dst
}

#[test]
fn tuberia_rota_sale_limpio_sin_panico() {
    // Equivale a `socshark capture -r demo --json - | head -0`: el lector se
    // va antes de leer nada. Antes `println!` entraba en pánico.
    let demo = demo_copia("pipe");
    for args in [
        vec!["capture", "-r", demo.to_str().unwrap(), "--json", "-"],
        vec!["capture", "-r", demo.to_str().unwrap()],
        vec!["export", "-r", demo.to_str().unwrap(), "--format", "ecs"],
    ] {
        let mut child = socshark()
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        let out = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!err.contains("panicked"), "{args:?}: {err}");
        assert!(out.status.success(), "{args:?}: {:?} {err}", out.status);
    }
    std::fs::remove_file(&demo).ok();
}

#[test]
fn ninguna_salida_pisa_la_captura_de_entrada() {
    let demo = demo_copia("pisar");
    let original = std::fs::read(&demo).unwrap();
    let d = demo.to_str().unwrap();
    for args in [
        vec!["report", "-r", d, "-o", d],
        vec!["capture", "-r", d, "--json", d],
        vec!["export", "-r", d, "-o", d],
    ] {
        let out = socshark().args(&args).output().unwrap();
        assert!(!out.status.success(), "{args:?} debía fallar");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("evidencia original"), "{args:?}: {err}");
        assert_eq!(std::fs::read(&demo).unwrap(), original, "{args:?}");
    }
    std::fs::remove_file(&demo).ok();
}

#[cfg(target_os = "linux")]
#[test]
fn export_con_disco_lleno_no_sale_con_cero() {
    let demo = demo_copia("lleno");
    let out = socshark()
        .args(["export", "-r", demo.to_str().unwrap(), "-o", "/dev/full"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    std::fs::remove_file(&demo).ok();
}

#[test]
fn report_en_ingles_sin_salida_escribe_report_html() {
    // Sin -o, el nombre sigue al idioma: report.html con --lang en.
    let demo = demo_copia("lang");
    let dir = std::env::temp_dir().join(format!("socshark-bin-lang-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = socshark()
        .current_dir(&dir)
        .args(["report", "-r", demo.to_str().unwrap(), "--lang", "en"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let html = std::fs::read_to_string(dir.join("report.html")).unwrap();
    assert!(html.contains("<html lang=\"en\">") && html.contains("What happened"));
    assert!(!dir.join("informe.html").exists());
    // Un idioma que no existe es un error de uso, no un informe en español.
    let bad = socshark()
        .current_dir(&dir)
        .args(["report", "-r", demo.to_str().unwrap(), "--lang", "fr"])
        .output()
        .unwrap();
    assert!(!bad.status.success());
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&demo).ok();
}
