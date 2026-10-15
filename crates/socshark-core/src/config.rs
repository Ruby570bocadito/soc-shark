//! Configuración del pipeline de procesamiento.
//!
//! Una única estructura gobierna el comportamiento del pipeline completo
//! (CLI hoy, daemon en Fase 2). Los umbrales de las heurísticas SOC viven
//! aquí para poder afinarlos sin tocar el código de las reglas.

/// Parámetros de ejecución del pipeline.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Máximo de flujos en memoria antes de forzar expulsión de los más
    /// antiguos (protección contra memory pressure en capturas largas).
    pub max_flows: usize,
    /// Segundos sin tráfico antes de considerar un flujo inactivo y
    /// expulsarlo en modo streaming (Fase 2).
    pub idle_timeout_secs: u64,
    /// Habilitar la clasificación de ruido de fondo (`is_background_noise`).
    pub detect_noise: bool,
    /// Umbral de entropía de Shannon (bits/carácter) para sospecha de túnel DNS.
    pub dns_entropy_threshold: f64,
    /// Longitud mínima del qname (caracteres) para sospecha de túnel DNS.
    pub dns_tunnel_min_len: usize,
    /// Número de SYNs "en seco" (sin ACK de respuesta) desde una misma origen
    /// hacia un mismo puerto destino antes de alertar posible escaneo.
    pub scan_syn_threshold: u32,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            max_flows: 50_000,
            idle_timeout_secs: 120,
            detect_noise: true,
            dns_entropy_threshold: 3.5,
            dns_tunnel_min_len: 30,
            scan_syn_threshold: 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valores_por_defecto_razonables() {
        let cfg = PipelineConfig::default();
        assert!(cfg.max_flows > 0);
        assert!(cfg.dns_entropy_threshold > 3.0 && cfg.dns_entropy_threshold < 4.0);
        assert!(cfg.scan_syn_threshold >= 3);
    }
}
