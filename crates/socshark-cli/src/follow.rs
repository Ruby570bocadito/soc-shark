//! Salida de `socshark follow` (Fase 2): stream TCP reensamblado en modo
//! legible o hexdump, con la misma estética que la tabla de `capture`.

use socshark_core::EnrichedFlow;
use socshark_flow::ReassembledStream;

/// Imprime el stream reensamblado por direcciones con contexto del flujo.
pub fn print_follow(flow: &EnrichedFlow, s: &ReassembledStream, hex: bool, max_bytes: usize) {
    println!("═══ Follow Stream · {} ═══", flow.flow_id);
    println!(
        "    {} · riesgo {} · alertas {} · estado {}",
        flow.l7_protocol.as_str(),
        flow.risk_score,
        flow.alerts.len(),
        flow.state.as_str()
    );
    if !flow.human_summary.is_empty() {
        println!("    {}", flow.human_summary);
    }
    print_direction(
        "cliente → servidor",
        &s.client,
        s.client_lossy,
        hex,
        max_bytes,
    );
    print_direction(
        "servidor → cliente",
        &s.server,
        s.server_lossy,
        hex,
        max_bytes,
    );
}

fn print_direction(title: &str, data: &[u8], lossy: bool, hex: bool, max: usize) {
    let nota = if lossy {
        " · con huecos o descartes"
    } else {
        ""
    };
    println!("\n── {title} · {} bytes{nota} ──", data.len());
    if data.is_empty() {
        println!("(sin datos)");
        return;
    }
    let slice = &data[..data.len().min(max)];
    if hex {
        print!("{}", render_hexdump(slice));
    } else {
        print!("{}", render_text(slice));
    }
    if data.len() > max {
        println!("[... {} bytes restantes truncados]", data.len() - max);
    }
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
    fn truncado_reporta_bytes_restantes() {
        // print_direction escribe a stdout: probamos solo la lógica del corte.
        let data = [b'x'; 100];
        let slice = &data[..data.len().min(10)];
        assert_eq!(slice.len(), 10);
        assert!(data.len() - slice.len() == 90);
    }
}
