//! Formateo de timestamps (epoch en microsegundos) y duraciones.
//!
//! La captura usa UTC por trazabilidad de evidencias; el desplazamiento a la
//! zona horaria local del analista es responsabilidad de la UI (fase 4) o de
//! herramientas externas al exportar a SIEM.

/// Formatea un timestamp en microsegundos como ISO-8601 UTC:
/// `2025-06-10T08:14:02.123456Z`.
pub fn format_ts_us(epoch_us: u64) -> String {
    let secs = epoch_us / 1_000_000;
    let frac = epoch_us % 1_000_000;
    let (y, mo, d) = civil_from_days((secs / 86_400) as i64);
    let sod = secs % 86_400;
    let (h, mi, s) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{frac:06}Z")
}

/// Versión corta para tablas de terminal: `08:14:02.123`.
pub fn format_ts_short(epoch_us: u64) -> String {
    let secs = epoch_us / 1_000_000;
    let ms = (epoch_us % 1_000_000) / 1000;
    let sod = secs % 86_400;
    let (h, mi, s) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{h:02}:{mi:02}:{s:02}.{ms:03}")
}

/// Formatea una duración en microsegundos de forma legible:
/// `120.4us`, `3.50ms`, `45.2s`, `1m 12s`, `2h 03m`.
pub fn format_duration_us(us: u64) -> String {
    let total_secs = us as f64 / 1_000_000.0;
    if total_secs < 0.001 {
        format!("{us}us")
    } else if total_secs < 1.0 {
        format!("{:.2}ms", total_secs * 1000.0)
    } else if total_secs < 60.0 {
        format!("{total_secs:.1}s")
    } else if total_secs < 3600.0 {
        let m = (total_secs / 60.0).floor() as u64;
        let s = total_secs - m as f64 * 60.0;
        if s < 1.0 {
            format!("{m}m")
        } else {
            format!("{m}m {s:.0}s")
        }
    } else {
        let h = (total_secs / 3600.0).floor() as u64;
        let m = ((total_secs - h as f64 * 3600.0) / 60.0).floor() as u64;
        format!("{h}h {m:02}m")
    }
}

/// Conversión días-desde-época → (año, mes, día).
/// Algoritmo de Howard Hinnant (`civil_from_days`), dominio público.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoca_y_fechas_conocidas() {
        assert_eq!(format_ts_us(0), "1970-01-01T00:00:00.000000Z");
        // 2025-01-01T00:00:00Z == 1735689600
        assert_eq!(
            format_ts_us(1_735_689_600_000_000),
            "2025-01-01T00:00:00.000000Z"
        );
        // 2000-02-29 (bisiesto) == 951782400
        assert_eq!(
            format_ts_us(951_782_400_000_000),
            "2000-02-29T00:00:00.000000Z"
        );
    }

    #[test]
    fn duraciones_legibles() {
        assert_eq!(format_duration_us(120), "120us");
        assert_eq!(format_duration_us(3_500), "3.50ms");
        assert_eq!(format_duration_us(45_200_000), "45.2s");
        assert_eq!(format_duration_us(72_400_000), "1m 12s");
        assert_eq!(format_duration_us(7_380_000_000), "2h 03m");
    }

    #[test]
    fn corto_para_tablas() {
        assert_eq!(format_ts_short(1_735_689_600_123_456), "00:00:00.123");
    }
}
