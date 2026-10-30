//! Benchmark reproducible de rendimiento (`socshark dev bench`).
//!
//! Genera una captura sintética grande y determinista (misma semilla →
//! mismos bytes), la escribe en un pcap temporal y la pasa por el pipeline
//! offline completo: lectura → disección (`--workers`) → agregación →
//! file carving → SOC. Mide solo esa última parte (la generación no
//! cuenta) e informa paquetes/s, Mbit/s (suma de bytes de trama), flujos,
//! tiempo y, donde es barato, el pico de memoria residente.
//!
//! Mezcla de tráfico (por índice de flujo, de 10 en 10):
//! - 5/10 HTTP: handshake, `GET`, respuesta con `Content-Length` y cuerpo
//!   en segmentos de 1000 bytes (lo talla el carving), cierre con FIN;
//! - 2/10 TLS: handshake, ClientHello con SNI y registros de datos;
//! - 2/10 DNS: consultas y respuestas alternas;
//! - 1/10 UDP genérico a puertos altos.
//!
//! Los flujos avanzan en oleadas de [`WAVE`] flujos entrelazados paquete a
//! paquete, como en una captura real (la tabla de flujos trabaja de verdad
//! y el reensamblado ve segmentos de muchos flujos mezclados).

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Serialize;
use socshark_core::config::PipelineConfig;
use socshark_testgen as tg;
use socshark_testgen::flags;
use socshark_testgen::fuzz::FuzzRng;

use crate::pipeline::run_capture;

/// Flujos activos a la vez (entrelazados) mientras se genera.
const WAVE: usize = 1000;
/// Paquetes mínimos por flujo (handshake + petición + datos + cierre).
const MIN_PER_FLOW: usize = 8;
/// Bytes de cuerpo por segmento de datos TCP.
const SEGMENT: usize = 1000;
/// Separación entre paquetes consecutivos (µs).
const TICK_MICROS: u64 = 10;

/// Parámetros del benchmark.
#[derive(Debug, Clone)]
pub struct BenchOptions {
    /// Paquetes aproximados (se reparten a partes iguales entre flujos).
    pub packets: usize,
    pub flows: usize,
    pub seed: u64,
    pub workers: usize,
}

/// Resultado medido (también es la salida `--json`).
#[derive(Debug, Clone, Serialize)]
pub struct BenchReport {
    pub seed: u64,
    pub workers: usize,
    /// Paquetes y bytes de trama generados (lo que lee el pipeline).
    pub packets: u64,
    pub bytes: u64,
    pub flows_generated: usize,
    /// Paquetes diseccionados y flujos agregados por el pipeline.
    pub parsed_packets: u64,
    pub flows: usize,
    pub alerts: usize,
    pub carved_files: usize,
    pub gen_secs: f64,
    pub wall_secs: f64,
    pub packets_per_sec: f64,
    pub mbit_per_sec: f64,
    /// Pico de memoria residente del proceso (Linux y Windows); `null` si
    /// no se puede obtener barato.
    pub peak_rss_bytes: Option<u64>,
}

/// Genera la captura, ejecuta el pipeline y mide.
pub fn run_bench(opts: &BenchOptions) -> Result<BenchReport> {
    let path = std::env::temp_dir().join(format!(
        "socshark-bench-{}-{:x}.pcap",
        std::process::id(),
        opts.seed
    ));
    let t0 = Instant::now();
    let generated = write_synthetic_pcap(&path, opts);
    let gen_secs = t0.elapsed().as_secs_f64();
    let generated = match generated {
        Ok(g) => g,
        Err(e) => {
            std::fs::remove_file(&path).ok();
            return Err(e);
        }
    };

    let cfg = PipelineConfig {
        workers: opts.workers.max(1),
        file_carving: true,
        max_flows: PipelineConfig::default().max_flows.max(opts.flows),
        ..PipelineConfig::default()
    };
    let t1 = Instant::now();
    let out = run_capture(&path, None, true, &cfg);
    let wall = t1.elapsed();
    std::fs::remove_file(&path).ok();
    let out = out?;

    let secs = wall.max(Duration::from_micros(1)).as_secs_f64();
    Ok(BenchReport {
        seed: opts.seed,
        workers: cfg.workers,
        packets: generated.packets,
        bytes: generated.bytes,
        flows_generated: generated.flows,
        parsed_packets: out.stats.parsed_packets,
        flows: out.flows.len(),
        alerts: out.flows.iter().map(|f| f.alerts.len()).sum(),
        carved_files: out.flows.iter().map(|f| f.extracted_files.len()).sum(),
        gen_secs,
        wall_secs: secs,
        packets_per_sec: generated.packets as f64 / secs,
        mbit_per_sec: generated.bytes as f64 * 8.0 / secs / 1e6,
        peak_rss_bytes: peak_rss(),
    })
}

/// Lo que se escribió en el pcap.
#[derive(Debug, Clone, Copy, Default)]
pub struct Generated {
    pub packets: u64,
    pub bytes: u64,
    pub flows: usize,
}

/// Escribe la captura sintética en `path` (pcap clásico Ethernet, en
/// streaming: no se guarda en memoria).
pub fn write_synthetic_pcap(path: &Path, opts: &BenchOptions) -> Result<Generated> {
    let file = File::create(path)
        .with_context(|| format!("no se pudo crear el pcap temporal {}", path.display()))?;
    let mut w = PcapWriter::new(BufWriter::with_capacity(1 << 20, file))?;
    let flows = opts.flows.max(1);
    let per_flow = (opts.packets / flows).max(MIN_PER_FLOW);

    let mut rng = FuzzRng::new(opts.seed);
    // Bloque pseudoaleatorio del que salen cuerpos y payloads (más barato
    // que pedir bytes al RNG para cada segmento).
    let noise: Vec<u8> = (0..64 * 1024 / 8)
        .flat_map(|_| rng.next_u64().to_le_bytes())
        .collect();

    let mut ts = 1_700_000_000_000_000u64;
    let mut wave_start = 0;
    while wave_start < flows {
        let wave: Vec<FlowPlan> = (wave_start..flows.min(wave_start + WAVE))
            .map(|i| FlowPlan::new(i, per_flow, &mut rng))
            .collect();
        for step in 0..per_flow {
            for plan in &wave {
                let frame = plan.packet(step, per_flow, &noise);
                w.write(ts, &frame)?;
                ts += TICK_MICROS;
            }
        }
        wave_start += WAVE;
    }
    let (packets, bytes) = w.finish()?;
    Ok(Generated {
        packets,
        bytes,
        flows,
    })
}

/// Tipo de flujo sintético.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Http,
    Tls,
    Dns,
    Udp,
}

/// Todo lo necesario para emitir cualquier paquete del flujo sin estado:
/// los números de secuencia se derivan del paso.
struct FlowPlan {
    kind: Kind,
    client: Ipv4Addr,
    server: Ipv4Addr,
    sport: u16,
    dport: u16,
    cseq: u32,
    sseq: u32,
    /// Petición del cliente (HTTP GET, ClientHello, consulta DNS...).
    request: Vec<u8>,
    /// Primer segmento del servidor: cabecera HTTP o registro TLS corto.
    head: Vec<u8>,
    qname: String,
    noise_off: usize,
}

impl FlowPlan {
    fn new(i: usize, per_flow: usize, rng: &mut FuzzRng) -> Self {
        let kind = match i % 10 {
            0..=4 => Kind::Http,
            5 | 6 => Kind::Tls,
            7 | 8 => Kind::Dns,
            _ => Kind::Udp,
        };
        // Clientes únicos por flujo (10.x.y.z) y 256 servidores públicos.
        let c = i as u32;
        let client = Ipv4Addr::new(10, (c >> 16) as u8, (c >> 8) as u8, c as u8);
        let server = Ipv4Addr::new(203, 0, 113, rng.below(256) as u8);
        let sport = 1024 + (rng.below(60_000) as u16);
        let host = format!("h{}.bench{}.example", rng.below(5000), rng.below(50));
        let (dport, request) = match kind {
            Kind::Http => (
                80,
                format!(
                    "GET /files/{i}.bin HTTP/1.1\r\nHost: {host}\r\nUser-Agent: socshark-bench\r\nAccept: */*\r\n\r\n"
                )
                .into_bytes(),
            ),
            Kind::Tls => (443, tg::client_hello(&host, b"h2")),
            Kind::Dns => (53, Vec::new()),
            Kind::Udp => (5000 + rng.below(1000) as u16, Vec::new()),
        };
        let head = match kind {
            // Cuerpo = todos los segmentos de datos menos el de cabecera.
            Kind::Http => format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                (per_flow - 7) * SEGMENT
            )
            .into_bytes(),
            // ServerHello simplificado: un registro handshake corto.
            _ => vec![0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00],
        };
        Self {
            kind,
            client,
            server,
            sport,
            dport,
            cseq: rng.next_u64() as u32,
            sseq: rng.next_u64() as u32,
            request,
            head,
            qname: host,
            noise_off: rng.below(32 * 1024),
        }
    }

    fn noise<'a>(&self, noise: &'a [u8], k: usize, len: usize) -> &'a [u8] {
        let start = (self.noise_off + k * 131) % (noise.len() - len);
        &noise[start..start + len]
    }

    /// Paquete número `step` de un flujo de `total` paquetes.
    fn packet(&self, step: usize, total: usize, noise: &[u8]) -> Vec<u8> {
        match self.kind {
            Kind::Http | Kind::Tls => self.tcp_packet(step, total, noise),
            Kind::Dns => {
                let id = self.sport ^ step as u16;
                let name = format!("q{}.{}", step / 2, self.qname);
                if step.is_multiple_of(2) {
                    let q = tg::dns_query(id, &name, 1);
                    self.c2s_udp(&q)
                } else {
                    let r = tg::dns_response(id, &name, 1, self.server);
                    self.s2c_udp(&r)
                }
            }
            Kind::Udp => {
                let p = self.noise(noise, step, 200);
                if step % 3 == 2 {
                    self.s2c_udp(p)
                } else {
                    self.c2s_udp(p)
                }
            }
        }
    }

    /// Guion TCP: SYN, SYN-ACK, ACK, petición, `total - 6` segmentos del
    /// servidor, FIN del cliente, FIN-ACK del servidor.
    fn tcp_packet(&self, step: usize, total: usize, noise: &[u8]) -> Vec<u8> {
        let data_segs = total - 6;
        let req_len = self.request.len() as u32;
        let c1 = self.cseq.wrapping_add(1);
        let s1 = self.sseq.wrapping_add(1);
        // Primer segmento del servidor: `head`; los siguientes, cuerpo de
        // SEGMENT bytes.
        let head = &self.head;
        let server_len = head.len() + (data_segs - 1) * SEGMENT;
        let c_end = c1.wrapping_add(req_len);
        let s_end = s1.wrapping_add(server_len as u32);
        match step {
            0 => self.c2s_tcp(self.cseq, 0, flags::SYN, &[]),
            1 => self.s2c_tcp(self.sseq, c1, flags::SYN_ACK, &[]),
            2 => self.c2s_tcp(c1, s1, flags::ACK, &[]),
            3 => self.c2s_tcp(c1, s1, flags::PSH_ACK, &self.request),
            s if s == total - 2 => self.c2s_tcp(c_end, s_end, flags::FIN_ACK, &[]),
            s if s == total - 1 => self.s2c_tcp(s_end, c_end.wrapping_add(1), flags::FIN_ACK, &[]),
            s => {
                let k = s - 4;
                if k == 0 {
                    self.s2c_tcp(s1, c_end, flags::PSH_ACK, head)
                } else {
                    let off = head.len() + (k - 1) * SEGMENT;
                    let body = self.noise(noise, k, SEGMENT);
                    let body = if self.kind == Kind::Tls {
                        tls_record(body)
                    } else {
                        body.to_vec()
                    };
                    self.s2c_tcp(s1.wrapping_add(off as u32), c_end, flags::ACK, &body)
                }
            }
        }
    }

    fn c2s_tcp(&self, seq: u32, ack: u32, fl: u8, payload: &[u8]) -> Vec<u8> {
        tg::frame_tcp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            self.client,
            self.server,
            self.sport,
            self.dport,
            seq,
            ack,
            fl,
            payload,
        )
    }

    fn s2c_tcp(&self, seq: u32, ack: u32, fl: u8, payload: &[u8]) -> Vec<u8> {
        tg::frame_tcp(
            tg::MAC_ROUTER,
            tg::MAC_HOST_A,
            self.server,
            self.client,
            self.dport,
            self.sport,
            seq,
            ack,
            fl,
            payload,
        )
    }

    fn c2s_udp(&self, payload: &[u8]) -> Vec<u8> {
        tg::frame_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            self.client,
            self.server,
            self.sport,
            self.dport,
            payload,
        )
    }

    fn s2c_udp(&self, payload: &[u8]) -> Vec<u8> {
        tg::frame_udp(
            tg::MAC_ROUTER,
            tg::MAC_HOST_A,
            self.server,
            self.client,
            self.dport,
            self.sport,
            payload,
        )
    }
}

/// Registro TLS de datos de aplicación con el cuerpo dado (los 5 bytes de
/// cabecera sustituyen al principio para no cambiar el tamaño).
fn tls_record(body: &[u8]) -> Vec<u8> {
    let mut rec = body.to_vec();
    let len = (body.len() - 5) as u16;
    rec[..5].copy_from_slice(&[0x17, 0x03, 0x03, (len >> 8) as u8, len as u8]);
    rec
}

/// Escritor pcap clásico en streaming (el de testgen exige tener todos los
/// paquetes en memoria: con un millón serían cientos de MB).
struct PcapWriter<W: Write> {
    w: W,
    packets: u64,
    bytes: u64,
}

impl<W: Write> PcapWriter<W> {
    fn new(mut w: W) -> std::io::Result<Self> {
        w.write_all(&0xa1b2_c3d4u32.to_le_bytes())?;
        w.write_all(&2u16.to_le_bytes())?;
        w.write_all(&4u16.to_le_bytes())?;
        w.write_all(&0i32.to_le_bytes())?; // thiszone
        w.write_all(&0u32.to_le_bytes())?; // sigfigs
        w.write_all(&65535u32.to_le_bytes())?; // snaplen
        w.write_all(&1u32.to_le_bytes())?; // Ethernet
        Ok(Self {
            w,
            packets: 0,
            bytes: 0,
        })
    }

    fn write(&mut self, ts_micros: u64, data: &[u8]) -> std::io::Result<()> {
        let len = data.len() as u32;
        self.w
            .write_all(&((ts_micros / 1_000_000) as u32).to_le_bytes())?;
        self.w
            .write_all(&((ts_micros % 1_000_000) as u32).to_le_bytes())?;
        self.w.write_all(&len.to_le_bytes())?;
        self.w.write_all(&len.to_le_bytes())?;
        self.w.write_all(data)?;
        self.packets += 1;
        self.bytes += data.len() as u64;
        Ok(())
    }

    fn finish(mut self) -> std::io::Result<(u64, u64)> {
        self.w.flush()?;
        Ok((self.packets, self.bytes))
    }
}

/// Pico de memoria residente del proceso, si es barato de obtener.
#[cfg(target_os = "linux")]
pub fn peak_rss() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}

/// Windows: `PeakWorkingSetSize` de `K32GetProcessMemoryInfo` (kernel32).
#[cfg(windows)]
pub fn peak_rss() -> Option<u64> {
    use std::ffi::c_void;

    /// `PROCESS_MEMORY_COUNTERS`.
    #[repr(C)]
    #[derive(Default)]
    struct Counters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn K32GetProcessMemoryInfo(process: *mut c_void, counters: *mut Counters, cb: u32) -> i32;
    }

    let mut c = Counters {
        cb: std::mem::size_of::<Counters>() as u32,
        ..Counters::default()
    };
    // SAFETY: pseudo-handle del propio proceso y estructura del tamaño
    // declarado en `cb`.
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) };
    (ok != 0).then_some(c.peak_working_set_size as u64)
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn peak_rss() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(workers: usize) -> BenchOptions {
        BenchOptions {
            packets: 4_000,
            flows: 100,
            seed: 7,
            workers,
        }
    }

    #[test]
    fn la_generacion_es_determinista() {
        let dir = std::env::temp_dir();
        let a = dir.join(format!("socshark-bench-a-{}.pcap", std::process::id()));
        let b = dir.join(format!("socshark-bench-b-{}.pcap", std::process::id()));
        let ga = write_synthetic_pcap(&a, &opts(1)).unwrap();
        let gb = write_synthetic_pcap(&b, &opts(1)).unwrap();
        assert_eq!(ga.packets, 4_000);
        assert_eq!(ga.packets, gb.packets);
        assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
        std::fs::remove_file(&a).ok();
        std::fs::remove_file(&b).ok();
    }

    #[test]
    fn el_pipeline_procesa_todo_y_talla_los_http() {
        let r1 = run_bench(&opts(1)).unwrap();
        assert_eq!(r1.packets, 4_000);
        assert_eq!(r1.parsed_packets, 4_000, "toda trama sintética es válida");
        assert_eq!(r1.flows, 100);
        // La mitad de los flujos son HTTP con cuerpo: el carving los ve.
        assert_eq!(r1.carved_files, 50);
        // El pool concurrente da el mismo resultado.
        let r4 = run_bench(&opts(4)).unwrap();
        assert_eq!(
            (r4.flows, r4.alerts, r4.carved_files),
            (r1.flows, r1.alerts, r1.carved_files)
        );
    }
}
