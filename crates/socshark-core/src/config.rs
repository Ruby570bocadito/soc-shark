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
    /// Túnel DNS por volumen: subdominios únicos de un mismo dominio
    /// registrable que un cliente debe consultar dentro de la ventana para
    /// alertar. Cubre túneles con codificación de baja entropía que la
    /// regla por consulta no ve (dnscat2/iodine con etiquetas cortas).
    pub dns_volume_threshold: u32,
    /// Ventana deslizante (segundos) del conteo de subdominios únicos.
    pub dns_volume_window_secs: u64,
    /// Longitud mínima del subdominio (caracteres, sin puntos) para contarlo:
    /// `www`, `api` o `img1` no pueden transportar datos útiles.
    pub dns_volume_min_subdomain_len: usize,
    /// Puertos distintos de un mismo host que un origen debe probar sin
    /// llegar a establecer conexión para alertar escaneo vertical (T1046).
    pub scan_port_threshold: u32,
    /// Hosts distintos en un mismo puerto que un origen debe probar sin
    /// llegar a establecer conexión para alertar barrido horizontal (T1046).
    /// Más alto que el vertical: el descubrimiento de red de Windows
    /// (SMB/NetBIOS) toca muchos hosts del mismo puerto de forma legítima.
    pub scan_host_threshold: u32,
    /// Intentos fallidos del mismo origen al mismo servicio (host:puerto)
    /// para avisar de reintentos (servicio caído, C2 muerto o sondeo
    /// insistente) cuando no llegan a ser un escaneo.
    pub repeated_attempt_threshold: u32,
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
    /// Beaconing con jitter aleatorio (Cobalt Strike `jitter`): intervalos
    /// mínimos para la prueba tolerante a jitter. Más que la estricta: con
    /// más dispersión hace falta más muestra para no confundir el azar.
    pub beacon_jitter_min_intervals: u32,
    /// CV máximo de la prueba con jitter cuando solo hay media/desviación
    /// (intervalos dentro de un flujo). Jitter uniforme ±50% da CV ≈ 0.29.
    pub beacon_jitter_max_cv: f64,
    /// Dispersión robusta máxima (MAD/mediana) de la prueba con jitter sobre
    /// los intervalos crudos (entre conexiones). Jitter uniforme ±50% da
    /// ≈ 0.25; el tráfico humano, de cola pesada, queda muy por encima.
    pub beacon_jitter_max_mad_ratio: f64,
    /// File carving HTTP (Fase 4): extrae archivos de las respuestas HTTP de
    /// los streams TCP reensamblados (Content-Length y chunked), calcula su
    /// SHA-256 y detecta encubrimiento T1036 (magic bytes ≠ extensión).
    /// Exige recolectar streams (hasta 1 MiB por dirección), así que va
    /// desactivada por defecto; la CLI la activa con `--carve-files`.
    pub file_carving: bool,
    /// Presupuesto global de reensamblado TCP en MiB (todos los flujos).
    /// Con *carving* y sin `follow`, al acercarse al tope se tallan y
    /// liberan los streams de las conexiones ya cerradas, así que una
    /// captura grande no agota el presupuesto a mitad.
    pub stream_budget_mib: u64,
    /// Ruta a una lista de IPs/CIDR de C2 tipo Feodo (threat intel offline,
    /// Fase 4). `None` = sin base Feodo.
    pub intel_feodo: Option<std::path::PathBuf>,
    /// Ruta a una lista de nodos de salida de Tor (threat intel offline,
    /// Fase 4). `None` = sin base Tor.
    pub intel_tor: Option<std::path::PathBuf>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            max_flows: 50_000,
            idle_timeout_secs: 120,
            detect_noise: true,
            dns_entropy_threshold: 3.5,
            dns_tunnel_min_len: 30,
            dns_volume_threshold: 50,
            dns_volume_window_secs: 600,
            dns_volume_min_subdomain_len: 6,
            scan_port_threshold: 10,
            scan_host_threshold: 20,
            repeated_attempt_threshold: 4,
            collect_streams: false,
            workers: 1,
            beacon_min_intervals: 6,
            beacon_min_interval_secs: 5,
            beacon_max_interval_secs: 3600,
            beacon_max_cv: 0.15,
            beacon_jitter_min_intervals: 12,
            beacon_jitter_max_cv: 0.30,
            beacon_jitter_max_mad_ratio: 0.35,
            file_carving: false,
            stream_budget_mib: 256,
            intel_feodo: None,
            intel_tor: None,
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
        assert!(cfg.scan_port_threshold >= 5);
        assert!(cfg.scan_host_threshold >= cfg.scan_port_threshold);
        assert!(cfg.repeated_attempt_threshold >= 3);
        assert!(cfg.dns_volume_threshold >= 20 && cfg.dns_volume_window_secs >= 60);
        assert!(cfg.beacon_jitter_min_intervals >= cfg.beacon_min_intervals);
        assert!(cfg.beacon_jitter_max_cv > cfg.beacon_max_cv);
    }
}
