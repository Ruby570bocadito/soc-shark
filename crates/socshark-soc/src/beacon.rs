//! Beaconing **entre flujos**: regularidad de los inicios de conexión.
//!
//! La regla R5 mide los intervalos entre paquetes *dentro* de un flujo. Un
//! implante que "llama a casa" cada 5-60 minutos no produce un flujo largo:
//! el agregador lo cierra por inactividad (120 s en el daemon) y cada
//! llamada acaba en un flujo de uno o pocos paquetes, sin estadística útil.
//! Aquí se recuerdan los instantes de inicio de los flujos por servicio
//! (origen, destino, puerto destino, transporte) — el puerto origen cambia
//! en cada conexión — y se aplica el mismo criterio de regularidad (CV) a
//! los intervalos entre inicios.
//!
//! Estado acotado para el daemon: [`MAX_BEACON_KEYS`] servicios con
//! desalojo de la mitad menos reciente y [`MAX_STARTS_PER_KEY`] inicios por
//! servicio.

use std::collections::HashMap;
use std::net::IpAddr;

use socshark_core::{EnrichedFlow, IntervalStats, L7Protocol, Transport};

use crate::evict_oldest_half;

/// Servicios (origen, destino, puerto, transporte) recordados como máximo.
pub const MAX_BEACON_KEYS: usize = 65_536;
/// Inicios de flujo recordados por servicio (33 = 32 intervalos).
pub const MAX_STARTS_PER_KEY: usize = 33;

type Key = (IpAddr, IpAddr, u16, Transport);

/// Rastreador de inicios de flujo por servicio.
#[derive(Default)]
pub struct FlowStartTracker {
    /// Inicios (µs, ordenados) y reloj lógico de la última actualización.
    starts: HashMap<Key, (Vec<u64>, u64)>,
    tick: u64,
}

fn key(flow: &EnrichedFlow) -> Key {
    (flow.src_ip, flow.dst_ip, flow.dst_port, flow.transport)
}

/// ¿Tiene sentido buscar beacon entre flujos de este servicio? DNS se
/// excluye (los resolutores reciben consultas periódicas legítimas de todo
/// tipo) y también el ruido de fondo (NTP, mDNS... son periódicos por diseño).
fn eligible(flow: &EnrichedFlow) -> bool {
    !flow.is_background_noise
        && !crate::noise::is_background_noise(flow)
        && flow.l7_protocol != L7Protocol::Dns
        && flow.dst_port != 53
        && matches!(flow.transport, Transport::Tcp | Transport::Udp)
}

impl FlowStartTracker {
    /// Registra el inicio de un flujo exportado.
    pub fn observe(&mut self, flow: &EnrichedFlow) {
        if !eligible(flow) {
            return;
        }
        self.tick += 1;
        let k = key(flow);
        if self.starts.len() >= MAX_BEACON_KEYS && !self.starts.contains_key(&k) {
            evict_oldest_half(&mut self.starts, |v| v.1);
        }
        let e = self.starts.entry(k).or_default();
        e.1 = self.tick;
        let t = flow.first_seen_micros;
        // El mismo flujo visto dos veces (fotos sucesivas) no cuenta doble.
        if let Err(pos) = e.0.binary_search(&t) {
            e.0.insert(pos, t);
            if e.0.len() > MAX_STARTS_PER_KEY {
                e.0.remove(0);
            }
        }
    }

    /// Estadística de intervalos entre inicios de flujo del servicio de
    /// `flow` (`None` con menos de 3 inicios).
    pub fn stats(&self, flow: &EnrichedFlow) -> Option<IntervalStats> {
        if !eligible(flow) {
            return None;
        }
        let ts = &self.starts.get(&key(flow))?.0;
        if ts.len() < 3 {
            return None;
        }
        let deltas: Vec<u64> = ts.windows(2).map(|w| w[1] - w[0]).collect();
        let n = deltas.len() as f64;
        let mean = deltas.iter().sum::<u64>() as f64 / n;
        let var = deltas
            .iter()
            .map(|&d| {
                let x = d as f64 - mean;
                x * x
            })
            .sum::<f64>()
            / n;
        Some(IntervalStats {
            intervals: deltas.len() as u32,
            mean_micros: mean.round() as u64,
            std_micros: var.sqrt().round() as u64,
        })
    }

    /// Servicios recordados (para métricas y tests).
    pub fn len(&self) -> usize {
        self.starts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.starts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::flujo_basico;

    fn conexion(sport: u16, t_secs: u64) -> EnrichedFlow {
        let mut f = flujo_basico(6, sport, 443);
        f.dst_ip = "203.0.113.50".parse().unwrap();
        f.first_seen_micros = t_secs * 1_000_000;
        f
    }

    #[test]
    fn inicios_regulares_dan_estadistica() {
        let mut t = FlowStartTracker::default();
        for i in 0..8u64 {
            t.observe(&conexion(40000 + i as u16, 1000 + i * 300));
        }
        // Repetir un flujo no cuenta doble.
        t.observe(&conexion(40000, 1000));
        let s = t.stats(&conexion(1, 0)).unwrap();
        assert_eq!(s.intervals, 7);
        assert_eq!(s.mean_micros, 300_000_000);
        assert_eq!(s.std_micros, 0);
    }

    #[test]
    fn dns_y_ruido_no_cuentan_y_estado_acotado() {
        let mut t = FlowStartTracker::default();
        let mut dns = flujo_basico(17, 40000, 53);
        dns.l7_protocol = L7Protocol::Dns;
        t.observe(&dns);
        assert!(t.is_empty());
        for i in 0..(MAX_BEACON_KEYS as u32 + 100) {
            let mut f = conexion(40000, 1);
            f.src_ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            t.observe(&f);
        }
        assert!(t.len() <= MAX_BEACON_KEYS);
    }
}
