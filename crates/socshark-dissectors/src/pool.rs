//! Pool de dissectors concurrente (Fase 2).
//!
//! La disección es la etapa CPU-intensiva del pipeline y es *pura*: un
//! [`RawPacket`] entra, un [`DissectedPacket`] sale, sin estado compartido.
//! Eso la hace trivialmente paralelizable; el único reto es mantener el
//! **determinismo**: los flujos deben formarse en el mismo orden que en el
//! camino secuencial para que timestamps, direcciones y alerts coincidan.
//!
//! Estrategia (ADR-010): paralelismo **por lotes con entrega ordenada**.
//! El hilo principal reparte lotes de `chunk_size` paquetes entre N workers
//! (round-robin) y alimenta al agregador estrictamente en el orden de
//! envío, almacenando en búfer los resultados que llegan adelantados. Con
//! eso, `--workers 4` produce exactamente la misma salida que `--workers 1`
//! (verificado por test de igualdad de JSONL).
//!
//! Para cruzar hilos, el pool entrega [`DissectedPacket`] con lifetime
//! `'static`: el worker convierte el payload prestado en `Cow::Owned`
//! ([`DissectedPacket::into_owned`]). Es la única copia extra del pipeline
//! y solo se paga cuando se pide paralelismo.

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use socshark_core::{LinkType, RawPacket};

use crate::{DissectedPacket, DissectorPipeline};

/// Trabajo enviado a un worker: índice global del lote, tipo de enlace y
/// los paquetes crudos del lote (se mueven; el worker toma propiedad).
type Job = (u64, LinkType, Vec<RawPacket>);

/// Resultado de un worker: índice global del lote y paquetes diseccionados
/// en el mismo orden que el lote de entrada (`None` = no interpretable).
type JobResult = (u64, Vec<Option<DissectedPacket<'static>>>);

/// Pool de workers que diseccionan lotes de paquetes en paralelo.
///
/// Ciclo de vida: [`DissectionPool::spawn`] arranca los hilos; el método
/// [`DissectionPool::process`] envía un lote y **bloquea** hasta devolver
/// sus disecciones en orden; [`Drop`] cierra el canal de trabajos y espera
/// (`join`) a los workers.
pub struct DissectionPool {
    job_tx: Option<Sender<Job>>,
    res_rx: Receiver<JobResult>,
    handles: Vec<JoinHandle<()>>,
    next_idx: u64,
    /// Resultados recibidos fuera de orden, a la espera de su turno.
    pending: HashMap<u64, Vec<Option<DissectedPacket<'static>>>>,
    chunk_size: usize,
}

impl DissectionPool {
    /// Arranca `workers` hilos de disección. `chunk_size` es el número de
    /// paquetes por lote (compromiso latencia/paralelismo; 256 es un valor
    /// razonable para tráfico mixto).
    ///
    /// Devuelve error si `workers == 0` o `chunk_size == 0`.
    pub fn spawn(workers: usize, chunk_size: usize) -> Result<Self, String> {
        if workers == 0 {
            return Err("el pool necesita al menos 1 worker".into());
        }
        if chunk_size == 0 {
            return Err("chunk_size debe ser mayor que 0".into());
        }

        let (job_tx, job_rx) = mpsc::channel::<Job>();
        let (res_tx, res_rx) = mpsc::channel::<JobResult>();
        // Los workers comparten el receptor de trabajos; std::sync::mpsc no
        // es Sync, así que se protege con un Mutex (la contención es mínima:
        // un `recv` por lote).
        let job_rx = Arc::new(Mutex::new(job_rx));

        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let job_rx = Arc::clone(&job_rx);
            let res_tx = res_tx.clone();
            let handle = std::thread::spawn(move || {
                let dissectors = DissectorPipeline::new();
                loop {
                    // Mutex temporal: solo cubre el `recv`; la disección
                    // corre fuera del lock.
                    let job = {
                        let rx = job_rx.lock().expect("mutex del pool envenenado");
                        rx.recv()
                    };
                    let Ok((idx, link, packets)) = job else {
                        break; // canal cerrado: el hilo termina limpio
                    };
                    let out = packets
                        .into_iter()
                        .map(|raw| {
                            dissectors
                                .dissect(&raw, link)
                                .map(DissectedPacket::into_owned)
                        })
                        .collect::<Vec<_>>();
                    if res_tx.send((idx, out)).is_err() {
                        break; // el principal ya no escucha: terminar
                    }
                }
            });
            handles.push(handle);
        }
        drop(res_tx); // el principal solo conserva el receptor

        Ok(Self {
            job_tx: Some(job_tx),
            res_rx,
            handles,
            next_idx: 0,
            pending: HashMap::new(),
            chunk_size,
        })
    }

    /// Tamaño de lote configurado.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Envía un lote y devuelve sus disecciones **en el orden de entrada**,
    /// bloqueando hasta que el lote esté listo (los resultados adelantados
    /// de lotes previos se almacenan en búfer para entregarlos en su turno).
    pub fn process(
        &mut self,
        link: LinkType,
        packets: Vec<RawPacket>,
    ) -> Vec<Option<DissectedPacket<'static>>> {
        let idx = self.next_idx;
        self.next_idx += 1;
        let n = packets.len();

        if let Some(tx) = self.job_tx.as_ref() {
            if tx.send((idx, link, packets)).is_err() {
                // Pool roto (worker en panic): devolver lote vacío; el
                // pipeline degradará a "paquetes no diseccionados".
                return (0..n).map(|_| None).collect();
            }
        }

        loop {
            if let Some(out) = self.pending.remove(&idx) {
                return out;
            }
            match self.res_rx.recv() {
                Ok((rid, rout)) => {
                    if rid == idx {
                        return rout;
                    }
                    self.pending.insert(rid, rout);
                }
                Err(_) => {
                    // Todos los workers murieron: sin resultados.
                    return (0..n).map(|_| None).collect();
                }
            }
        }
    }
}

impl Drop for DissectionPool {
    fn drop(&mut self) {
        // Soltar el emisor cierra el canal; los workers salen de `recv`.
        self.job_tx = None;
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_testgen as tg;

    fn lote(n: usize) -> Vec<RawPacket> {
        lote_con_base(0, n)
    }

    /// `base` hace los ids DNS únicos entre lotes para detectar cualquier
    /// desorden en la entrega.
    fn lote_con_base(base: u64, n: usize) -> Vec<RawPacket> {
        (0..n)
            .map(|i| RawPacket {
                ts_micros: 1_000 + base + i as u64,
                orig_len: 74,
                data: tg::frame_udp(
                    tg::MAC_HOST_A,
                    tg::MAC_ROUTER,
                    tg::HOST_A,
                    tg::DNS_EXT,
                    53000 + (i % 3) as u16,
                    53,
                    &tg::dns_query((base + i as u64 + 1) as u16, "pool.example", 1),
                ),
            })
            .collect()
    }

    #[test]
    fn el_pool_respeta_el_orden_de_lotes() {
        let mut pool = DissectionPool::spawn(4, 8).expect("pool arranca");
        // Enviamos 5 lotes; comprobamos que cada `process` devuelve el lote
        // pedido (los adelantados quedan en búfer y salen en su turno).
        for lote_idx in 0..5u64 {
            let out = pool.process(LinkType::Ethernet, lote_con_base(lote_idx * 16, 16));
            assert_eq!(out.len(), 16);
            for (i, dp) in out.iter().enumerate() {
                let dp = dp.as_ref().expect("trama testgen debe diseccionarse");
                let seq = (lote_idx * 16 + i as u64) as u16;
                assert_eq!(
                    dp.dns.as_ref().unwrap().id,
                    seq + 1,
                    "lote {lote_idx} paquete {i} desordenado"
                );
            }
        }
    }

    #[test]
    fn el_pool_es_equivalente_al_camino_secuencial() {
        // El determinismo es el contrato del pool (ADR-010): mismos paquetes,
        // misma disección que el pipeline secuencial.
        let paquetes = lote(40);
        let secuencial: Vec<Option<u16>> = paquetes
            .iter()
            .map(|raw| {
                DissectorPipeline::new()
                    .dissect(raw, LinkType::Ethernet)
                    .and_then(|dp| dp.dns)
                    .map(|d| d.id)
            })
            .collect();

        let mut pool = DissectionPool::spawn(3, 7).expect("pool arranca");
        let paralelo: Vec<Option<u16>> = pool
            .process(LinkType::Ethernet, paquetes)
            .into_iter()
            .map(|dp| dp.and_then(|d| d.dns).map(|d| d.id))
            .collect();

        assert_eq!(secuencial, paralelo);
    }

    #[test]
    fn lotes_parciales_y_vacios_no_rompen_el_pool() {
        let mut pool = DissectionPool::spawn(2, 4).unwrap();
        assert!(pool.process(LinkType::Ethernet, Vec::new()).is_empty());
        let out = pool.process(LinkType::Ethernet, lote(3));
        assert_eq!(out.len(), 3);
        // Y sigue vivo después de ambos casos extremos.
        let out = pool.process(LinkType::Ethernet, lote(5));
        assert_eq!(out.len(), 5);
    }

    #[test]
    fn tramas_invalidas_producen_none_en_paralelo() {
        let mut pool = DissectionPool::spawn(2, 4).unwrap();
        let mut paquetes = lote(4);
        paquetes.push(RawPacket {
            ts_micros: 9,
            orig_len: 3,
            data: vec![0xff, 0x00, 0x11], // Ethernet truncada
        });
        let out = pool.process(LinkType::Ethernet, paquetes);
        assert_eq!(out.len(), 5);
        assert!(out[0].is_some());
        assert!(out[4].is_none(), "la trama truncada debe dar None");
    }
}
