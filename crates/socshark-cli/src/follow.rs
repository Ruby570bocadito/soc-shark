//! Salida de `socshark follow` (Fase 2): stream TCP reensamblado en modo
//! legible o hexdump, con la misma estética que la tabla de `capture`.

use std::io::{self, Write};

use socshark_core::EnrichedFlow;
use socshark_flow::ReassembledStream;

use crate::output::sanitize_terminal;

/// Imprime el stream reensamblado en stdout (ver [`write_follow`]).
pub fn print_follow(
    flow: &EnrichedFlow,
    s: &ReassembledStream,
    hex: bool,
    max_bytes: usize,
) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    write_follow(&mut stdout, flow, s, hex, max_bytes)?;
    stdout.flush()
}

/// Escribe el stream reensamblado por direcciones con contexto del flujo.
/// El resumen (que lleva dominios del tráfico) se neutraliza para el
/// terminal; los datos ya salen como ASCII imprimible o hexdump.
pub fn write_follow(
    w: &mut impl Write,
    flow: &EnrichedFlow,
    s: &ReassembledStream,
    hex: bool,
    max_bytes: usize,
) -> io::Result<()> {
    writeln!(
        w,
        "═══ Follow Stream · {} ═══",
        sanitize_terminal(&flow.flow_id.0)
    )?;
    writeln!(
        w,
        "    {} · riesgo {} · alertas {} · estado {}",
        flow.l7_protocol.as_str(),
        flow.risk_score,
        flow.alerts.len(),
        flow.state.as_str()
    )?;
    if !flow.human_summary.is_empty() {
        writeln!(w, "    {}", sanitize_terminal(&flow.human_summary))?;
    }
    write_direction(
        w,
        "cliente → servidor",
        &s.client,
        s.client_lossy,
        hex,
        max_bytes,
    )?;
    write_direction(
        w,
        "servidor → cliente",
        &s.server,
        s.server_lossy,
        hex,
        max_bytes,
    )
}

fn write_direction(
    w: &mut impl Write,
    title: &str,
    data: &[u8],
    lossy: bool,
    hex: bool,
    max: usize,
) -> io::Result<()> {
    let nota = if lossy {
        " · con huecos o descartes"
    } else {
        ""
    };
    writeln!(w, "\n── {title} · {} bytes{nota} ──", data.len())?;
    if data.is_empty() {
        return writeln!(w, "(sin datos)");
    }
    let slice = &data[..data.len().min(max)];
    if hex {
        write!(w, "{}", render_hexdump(slice))?;
    } else {
        write!(w, "{}", render_text(slice))?;
    }
    if data.len() > max {
        writeln!(w, "[... {} bytes restantes truncados]", data.len() - max)?;
    }
    Ok(())
}

/// Convierte bytes a texto: ASCII imprimible se respeta, el resto se
/// sustituye por `.` (los `\n` delimitan líneas).
pub fn render_text(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() + 16);
    let mut line = String::new();
    for &b in data {
        match b {
            b'\n' => {
                out.push_str("> ");
                out.push_str(&line);
                out.push('\n');
                line.clear();
            }
            b'\t' => line.push('\t'),
            0x20..=0x7e => line.push(b as char),
            _ => line.push('.'),
        }
    }
    if !line.is_empty() {
        out.push_str("> ");
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// Hexdump clásico: offset, 16 bytes en hex y columna ASCII.
pub fn render_hexdump(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let mut hex_part = String::with_capacity(48);
        let mut ascii = String::with_capacity(16);
        for &b in chunk {
            hex_part.push_str(&format!("{b:02x} "));
            ascii.push(if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            });
        }
        for _ in chunk.len()..16 {
            hex_part.push_str("   ");
        }
        out.push_str(&format!("{:08x}  {hex_part} |{ascii}|\n", i * 16));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn texto_imprimible_con_no_imprimibles() {
        let out = render_text(b"GET / HTTP/1.1\r\nHost: x\x00\xff");
        // \r desaparece (no es imprimible → '.'), \n delimita la línea.
        assert!(out.contains("> GET / HTTP/1.1."), "salida: {out:?}");
        assert!(out.contains("> Host: x.."));
    }

    #[test]
    fn hexdump_formato_clasico() {
        let out = render_hexdump(b"AB");
        assert_eq!(
            out,
            "00000000  41 42                                            |AB|\n"
        );
    }

    #[test]
    fn truncado_y_resumen_neutralizado() {
        let flow: EnrichedFlow = serde_json::from_str(
            r#"{
                "flow_id": "tcp/10.0.0.1:5000-10.0.0.2:80",
                "state": "Idle", "transport": "Tcp", "l7_protocol": "Http",
                "src_ip": "10.0.0.1", "src_port": 5000,
                "dst_ip": "10.0.0.2", "dst_port": 80,
                "first_seen_micros": 0, "last_seen_micros": 1, "duration_micros": 1,
                "packets": 1, "bytes": 80, "packets_rev": 1, "bytes_rev": 100,
                "tcp_flags": {"syn":0,"ack":0,"fin":0,"rst":0,"psh":0,"urg":0},
                "human_summary": "HTTP a evil\u001b[2J.example", "risk_score": 0,
                "alerts": [], "extracted_files": []
            }"#,
        )
        .unwrap();
        let s = ReassembledStream {
            client: vec![b'x'; 100],
            server: Vec::new(),
            client_lossy: false,
            server_lossy: false,
        };
        let mut out = Vec::new();
        write_follow(&mut out, &flow, &s, false, 10).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains('\x1b'), "{out:?}");
        assert!(out.contains("evil\\x1b[2J.example"));
        assert!(out.contains("[... 90 bytes restantes truncados]"));
        assert!(out.contains("(sin datos)"));
    }
}
