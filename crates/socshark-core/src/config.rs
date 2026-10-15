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
    /// Recolectar segmentos TCP por dirección para el reensamblado
    /// (`socshark follow`). Añade hasta 1 MiB de memoria por dirección
    /// activa, así que va desactivado por defecto.
    pub collect_streams: bool,
    /// Número de hilos de disección (`> 1` activa el pool concurrente de
    /// `socshark-dissectors::pool`). El resultado es idéntico al camino
    /// secuencial (ADR-010: lotes con entrega ordenada); con 1 no se copia
    /// payload (zero-copy estricto).
    pub workers: usize,
    /// Intervalos consecutivos (≥) necesarios para evaluar beaconing.
    /// Con 6, un beacon de 30 s se alerta a los 3 minutos (criterio de
    /// Fase 3: < 5 min).
    pub beacon_min_intervals: u32,
    /// Intervalo medio mínimo (segundos) para considerar beaconing: por
    /// debajo están las retransmisiones y el tráfico interactivo.
    pub beacon_min_interval_secs: u64,
    /// Intervalo medio máximo (segundos): por encima están los keepalives
    /// TCP (2 h) y los polls de mantenimiento (NTP 1024 s).
    pub beacon_max_interval_secs: u64,
    /// Coeficiente de variación máximo (std/mean) para considerar los
    /// intervalos "programados". 0.15 deja fuera el tráfico humano (CV >
    /// 0.3) y capta beacons con jitter moderado.
    pub beacon_max_cv: f64,
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
            collect_streams: false,
            workers: 1,
            beacon_min_intervals: 6,
            beacon_min_interval_secs: 5,
            beacon_max_interval_secs: 3600,
            beacon_max_cv: 0.15,
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
