//! socshark-flow: agregación de paquetes en flujos bidireccionales.
//!
//! Es la etapa 3/4 del pipeline (etapa "Dissector Pool" + germen del
//! "Stream Reassembler"): consume [`socshark_dissectors::DissectedPacket`]
//! y produce [`socshark_core::EnrichedFlow`] listos para la capa SOC.
//!
//! Claves de diseño:
//! - **Bidireccionalidad canónica**: A→B y B→A comparten clave; los contadores
//!   se separan en dirección `fwd` (primer paquete observado) y `rev`.
//! - **IPv4 e IPv6 iguales ante la clave**: la clave canónica opera sobre
//!   `IpAddr`, así que la agregación v6 es exactamente la v4 (Fase 2).
//! - **Sin reordenar**: los timestamps fuera de orden solo empujan
//!   `first_seen` hacia atrás; nada se pierde.
//! - **Presión de memoria acotada**: `max_flows` con expulsión de los flujos
//!   más antiguos (que no se pierden: salen por la siguiente
//!   [`FlowAggregator::drain_expired`] o por `finish`), y reensamblado TCP
//!   opcional con tope de 1 MiB y de segmentos por dirección más un
//!   presupuesto global entre todos los flujos ([`ReassembledStream`]).

use std::collections::HashMap;
use std::net::IpAddr;

use socshark_core::{
    DnsAnswerSummary, DnsQuerySummary, DnsSummary, EnrichedFlow, FlowId, FlowState, IntervalStats,
    L7Protocol, TcpFlagCounts, Transport,
};
use socshark_dissectors::{ClientHelloCapture, DissectedPacket, DnsInfo};

/// Tope de bytes recolectados por dirección y flujo para el reensamblado.
/// Lo que exceda el tope se descarta y se marca el stream como `lossy`.
pub const MAX_STREAM_BYTES: u64 = 1024 * 1024;

/// Presupuesto global por defecto de bytes de reensamblado entre todos los
/// flujos vivos (payload + sobrecoste por segmento). Sin él, `max_flows`
/// flujos × 2 direcciones × 1 MiB podían sumar decenas de GiB.
pub const DEFAULT_STREAM_BUDGET: u64 = 256 * 1024 * 1024;

/// Sobrecoste contabilizado por segmento retenido (cabecera del `Vec`,
/// asignación y número de secuencia): un flujo de segmentos de 1 byte no
/// debe pasar por barato.
pub const SEGMENT_OVERHEAD: u64 = 64;

/// Segmentos retenidos como máximo por dirección y flujo.
pub const MAX_SEGMENTS_PER_DIR: usize = 8192;

/// Nombres DNS distintos que se acumulan como máximo en `dns.queries`.
pub const MAX_DNS_QUERIES: usize = 64;

/// Segmentos fuera de orden que se retienen para el ClientHello (JA4).
const MAX_HELLO_PENDING: usize = 8;
/// Bytes como máximo en esos segmentos adelantados.
const MAX_HELLO_PENDING_BYTES: usize = 16 * 1024;

/// Timestamps en dirección iniciador que se retienen por flujo para las
/// estadísticas de intervalos (33 muestras = 32 intervalos; a un beacon de
/// 30 s cubre ~16 minutos, más que suficiente para estimar el periodo).
const MAX_TIMES_FWD: usize = 33;

/// Clave canónica de flujo bidireccional: los extremos se ordenan para que
/// A→B y B→A compartan clave.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub low: IpAddr,
    pub low_port: u16,
    pub high: IpAddr,
    pub high_port: u16,
    pub transport: Transport,
}

impl FlowKey {
    /// Normaliza un par de extremos (IP, puerto) en una clave canónica.
    pub fn new(a: IpAddr, a_port: u16, b: IpAddr, b_port: u16, transport: Transport) -> Self {
        let (low, low_port, high, high_port) = if (a, a_port) <= (b, b_port) {
            (a, a_port, b, b_port)
        } else {
            (b, b_port, a, a_port)
        };
        Self {
            low,
            low_port,
            high,
            high_port,
            transport,
        }
    }

    /// Identificador legible y estable del flujo.
    pub fn flow_id(&self) -> FlowId {
        FlowId(format!(
            "{}/{}:{}-{}:{}",
            self.transport.as_str().to_ascii_lowercase(),
            self.low,
            self.low_port,
            self.high,
            self.high_port
        ))
    }
}

/// Estadísticas globales del pipeline.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineStats {
    pub total_packets: u64,
    pub parsed_packets: u64,
    pub skipped_packets: u64,
    pub flows_created: u64,
}

impl PipelineStats {
    /// Resumen en una línea para la barra de progreso de la CLI.
    pub fn summary(&self) -> String {
        format!(
            "{} paquetes leídos · {} diseccionados · {} descartados · {} flujos",
            self.total_packets, self.parsed_packets, self.skipped_packets, self.flows_created
        )
    }
}

// --------------------------------------------------- reensamblado TCP (Fase 2)

/// Contabilidad global del reensamblado (compartida por todos los flujos).
#[derive(Debug, Clone, Copy)]
struct StreamBudget {
    used: u64,
    limit: u64,
}

/// Buffer de una dirección: segmentos `(seq, datos)` con su ISN observado.
#[derive(Debug, Default, Clone)]
struct StreamBuf {
    /// Número de secuencia del primer segmento observado en la dirección.
    base: Option<u32>,
    segs: Vec<(u32, Vec<u8>)>,
    /// Coste contabilizado: payload + [`SEGMENT_OVERHEAD`] por segmento.
    collected: u64,
    truncated: bool,
}

impl StreamBuf {
    fn push(&mut self, seq: u32, data: &[u8], budget: &mut StreamBudget) {
        if data.is_empty() {
            return;
        }
        match self.base {
            None => self.base = Some(seq),
            Some(b) => {
                // Si el segmento es ANTERIOR a la base (comparación serial con
                // signo, RFC 9293 §3.3), la captura empezó a mitad de dirección:
                // se retrocede la base para que todos los offsets queden
                // ordenables hacia adelante.
                if (seq.wrapping_sub(b) as i32) < 0 {
                    self.base = Some(seq);
                }
            }
        }
        let cost = data.len() as u64 + SEGMENT_OVERHEAD;
        if self.collected + cost > MAX_STREAM_BYTES
            || self.segs.len() >= MAX_SEGMENTS_PER_DIR
            || budget.used + cost > budget.limit
        {
            self.truncated = true;
            return;
        }
        self.collected += cost;
        budget.used += cost;
        self.segs.push((seq, data.to_vec()));
    }

    /// Reensambla en orden de secuencia relativo al primer ISN observado:
    /// elimina retransmisiones solapadas, compara su contenido con lo ya
    /// visto (si difiere hay inyección o corrupción: `lossy`) y marca los
    /// huecos con un separador legible. Consume el buffer y ordena en sitio,
    /// sin clonar los segmentos. Devuelve `(bytes, hay_pérdida)`.
    fn reassemble(mut self) -> (Vec<u8>, bool) {
        let Some(base) = self.base else {
            return (Vec::new(), false);
        };
        // Orden estable: ante seq iguales gana el primero que llegó.
        self.segs.sort_by_key(|(seq, _)| seq.wrapping_sub(base));

        let payload: usize = self.segs.iter().map(|(_, d)| d.len()).sum();
        let mut out = Vec::with_capacity(payload);
        let mut cursor: u64 = 0; // offset relativo ya cubierto
                                 // Offset relativo desde el que `out` es contiguo (tras el último
                                 // separador de hueco): solo ahí se puede comparar un solape.
        let mut contiguous_from: u64 = 0;
        let mut lossy = self.truncated;
        for (seq, data) in &self.segs {
            let off = seq.wrapping_sub(base) as u64;
            let end = off + data.len() as u64;
            if off > cursor {
                let gap = off - cursor;
                out.extend_from_slice(format!("\n[{gap} bytes perdidos]\n").as_bytes());
                lossy = true;
                out.extend_from_slice(data);
                contiguous_from = off;
                cursor = end;
                continue;
            }
            // Solape con lo ya reensamblado: [max(off, contiguo), min(end, cursor)).
            let ov_start = off.max(contiguous_from);
            let ov_end = end.min(cursor);
            if ov_start < ov_end {
                let in_out = out.len() - (cursor - ov_start) as usize;
                let len = (ov_end - ov_start) as usize;
                let in_data = (ov_start - off) as usize;
                if out[in_out..in_out + len] != data[in_data..in_data + len] {
                    lossy = true; // retransmisión con contenido distinto
                }
            }
            if end > cursor {
                let skip = (cursor - off) as usize;
                out.extend_from_slice(&data[skip..]);
                cursor = end;
            }
        }
        (out, lossy)
    }
}

/// Par de streams de un flujo TCP (cliente = origen del primer paquete).
#[derive(Debug, Clone)]
struct StreamPair {
    fwd: StreamBuf,
    rev: StreamBuf,
}

/// Stream TCP reensamblado, listo para `socshark follow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledStream {
    /// Bytes del iniciador de la conexión (src del primer paquete).
    pub client: Vec<u8>,
    /// Bytes del otro extremo.
    pub server: Vec<u8>,
    /// True si hubo huecos de secuencia, retransmisiones inconsistentes o
    /// descartes por el tope de memoria.
    pub client_lossy: bool,
    pub server_lossy: bool,
}

// ------------------------------------------------------------ acumuladores

/// Acumulador interno por flujo.
#[derive(Debug, Clone)]
struct FlowAccum {
    key: FlowKey,
    /// Extremos según el PRIMER paquete observado (dirección "fwd").
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
    src_mac: Option<String>,
    dst_mac: Option<String>,
    first_seen: u64,
    last_seen: u64,
    packets_fwd: u64,
    bytes_fwd: u64,
    packets_rev: u64,
    bytes_rev: u64,
    flags: TcpFlagCounts,
    l7: L7Protocol,
    dns: Option<DnsSummary>,
    streams: Option<StreamPair>,
    /// Captura acotada del ClientHello del iniciador (Fase 3, JA4).
    hello: ClientHelloCapture,
    /// Siguiente seq esperado del iniciador para el ClientHello: solo se le
    /// dan segmentos en orden, sin retransmisiones.
    hello_next: Option<u32>,
    /// Segmentos del iniciador llegados antes de tiempo (acotado).
    hello_pending: Vec<(u32, Vec<u8>)>,
    /// Timestamps (µs) de los primeros paquetes en dirección iniciador
    /// (Fase 3, beaconing). No mantiene orden: se ordena al exportar.
    times_fwd: Vec<u64>,
}

impl FlowAccum {
    /// Copia del acumulador sin los segmentos TCP (que pesan hasta 1 MiB
    /// por dirección): lo que necesita una foto periódica en vivo.
    fn clone_without_streams(&self) -> FlowAccum {
        FlowAccum {
            key: self.key.clone(),
            src: self.src,
            src_port: self.src_port,
            dst: self.dst,
            dst_port: self.dst_port,
            src_mac: self.src_mac.clone(),
            dst_mac: self.dst_mac.clone(),
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            packets_fwd: self.packets_fwd,
            bytes_fwd: self.bytes_fwd,
            packets_rev: self.packets_rev,
            bytes_rev: self.bytes_rev,
            flags: self.flags,
            l7: self.l7,
            dns: self.dns.clone(),
            streams: None,
            hello: self.hello.clone(),
            hello_next: self.hello_next,
            hello_pending: Vec::new(),
            times_fwd: self.times_fwd.clone(),
        }
    }

    /// Coste de reensamblado que este flujo tiene contabilizado.
    fn stream_cost(&self) -> u64 {
        self.streams
            .as_ref()
            .map_or(0, |sp| sp.fwd.collected + sp.rev.collected)
    }

    /// Alimenta el ClientHello solo con datos en orden de secuencia: las
    /// retransmisiones se ignoran (o se recorta lo ya visto) y lo que llega
    /// adelantado espera en `hello_pending` hasta que se cierre el hueco.
    fn feed_hello(&mut self, seq: u32, payload: &[u8]) {
        if self.hello.is_done() {
            self.hello_pending = Vec::new();
            return;
        }
        if payload.is_empty() {
            return;
        }
        let next = *self.hello_next.get_or_insert(seq);
        let rel = seq.wrapping_sub(next) as i32;
        if rel > 0 {
            let pending: usize = self.hello_pending.iter().map(|(_, d)| d.len()).sum();
            if self.hello_pending.len() < MAX_HELLO_PENDING
                && pending + payload.len() <= MAX_HELLO_PENDING_BYTES
            {
                self.hello_pending.push((seq, payload.to_vec()));
            }
            return;
        }
        self.feed_hello_from(seq, payload);
        // Vacía los adelantados que ya encajan.
        while let Some(next) = self.hello_next {
            let Some(i) = self
                .hello_pending
                .iter()
                .position(|(s, _)| (s.wrapping_sub(next) as i32) <= 0)
            else {
                break;
            };
            let (s, d) = self.hello_pending.swap_remove(i);
            self.feed_hello_from(s, &d);
        }
    }

    /// Entrega a la captura la parte de `payload` posterior a `hello_next`.
    fn feed_hello_from(&mut self, seq: u32, payload: &[u8]) {
        let Some(next) = self.hello_next else { return };
        let skip = next.wrapping_sub(seq) as usize;
        if skip >= payload.len() {
            return; // retransmisión íntegra
        }
        self.hello.feed(&payload[skip..]);
        self.hello_next = Some(seq.wrapping_add(payload.len() as u32));
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        key: FlowKey,
        ts_micros: u64,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        dp: &DissectedPacket,
        collect_streams: bool,
    ) -> Self {
        let (src_mac, dst_mac) = dp
            .eth
            .as_ref()
            .map(|e| (Some(e.src_mac_str()), Some(e.dst_mac_str())))
            .unwrap_or((None, None));
        Self {
            key,
            src,
            src_port,
            dst,
            dst_port,
            src_mac,
            dst_mac,
            first_seen: ts_micros,
            last_seen: ts_micros,
            packets_fwd: 0,
            bytes_fwd: 0,
            packets_rev: 0,
            bytes_rev: 0,
            flags: TcpFlagCounts::default(),
            l7: dp.l7,
            dns: None,
            streams: if collect_streams && dp.transport == Transport::Tcp {
                Some(StreamPair {
                    fwd: StreamBuf::default(),
                    rev: StreamBuf::default(),
                })
            } else {
                None
            },
            hello: ClientHelloCapture::default(),
            hello_next: None,
            hello_pending: Vec::new(),
            times_fwd: Vec::new(),
        }
    }

    /// Fusiona un paquete DNS en el resumen del flujo: la consulta aporta
    /// `queries`, la respuesta aporta `rcode` + `answers` (y marca
    /// `is_response`). Así un flujo query+response queda completo.
    ///
    /// `queries` **acumula** todos los nombres preguntados en el flujo (sin
    /// duplicados, hasta [`MAX_DNS_QUERIES`]): un mismo 5-tupla puede llevar
    /// muchas consultas (resolutores con puerto fijo, túneles) y
    /// `dns.qname` debe verlas todas, no solo las del último paquete.
    fn merge_dns(&mut self, d: &DnsInfo) {
        let to_query = |q: &socshark_dissectors::DnsQuestion| DnsQuerySummary {
            name: q.name.clone(),
            qtype: q.qtype,
        };
        let to_answer = |r: &socshark_dissectors::DnsRecord| DnsAnswerSummary {
            name: r.name.clone(),
            rtype: r.rtype,
            ttl: r.ttl,
            address: r.address,
            target: r.target.clone(),
        };

        match self.dns.as_mut() {
            None => {
                self.dns = Some(DnsSummary {
                    is_response: d.is_response,
                    rcode: d.rcode,
                    queries: d
                        .queries
                        .iter()
                        .take(MAX_DNS_QUERIES)
                        .map(to_query)
                        .collect(),
                    answers: d.answers.iter().map(to_answer).collect(),
                });
            }
            Some(s) => {
                if d.is_response {
                    s.is_response = true;
                    s.rcode = d.rcode;
                    s.answers = d.answers.iter().map(to_answer).collect();
                }
                // La sección de preguntas viaja en consultas y respuestas.
                for q in &d.queries {
                    if s.queries.len() >= MAX_DNS_QUERIES {
                        break;
                    }
                    let dup = s
                        .queries
                        .iter()
                        .any(|e| e.qtype == q.qtype && e.name.eq_ignore_ascii_case(&q.name));
                    if !dup {
                        s.queries.push(to_query(q));
                    }
                }
            }
        }
    }
}

/// Agregador de flujos: convierte paquetes diseccionados en
/// [`EnrichedFlow`] listos para el enriquecimiento SOC.
pub struct FlowAggregator {
    flows: HashMap<FlowKey, FlowAccum>,
    max_flows: usize,
    idle_timeout_micros: u64,
    collect_streams: bool,
    stats: PipelineStats,
    budget: StreamBudget,
    /// Flujos expulsados por presión de memoria pendientes de entregar
    /// (con su stream y el coste que aún ocupa en el presupuesto).
    evicted: Vec<(EnrichedFlow, Option<ReassembledStream>, u64)>,
}

impl FlowAggregator {
    /// Crea un agregador con límite de tabla, timeout de inactividad y la
    /// opción de recolectar segmentos TCP para reensamblar streams.
    pub fn new(max_flows: usize, idle_timeout_secs: u64, collect_streams: bool) -> Self {
        Self {
            flows: HashMap::new(),
            max_flows,
            idle_timeout_micros: idle_timeout_secs * 1_000_000,
            collect_streams,
            stats: PipelineStats::default(),
            budget: StreamBudget {
                used: 0,
                limit: DEFAULT_STREAM_BUDGET,
            },
            evicted: Vec::new(),
        }
    }

    /// Cambia el presupuesto global de bytes de reensamblado (por defecto
    /// [`DEFAULT_STREAM_BUDGET`]). Lo que no quepa se descarta y el stream
    /// queda marcado `lossy`.
    pub fn with_stream_budget(mut self, bytes: u64) -> Self {
        self.budget.limit = bytes;
        self
    }

    /// Bytes de reensamblado contabilizados ahora mismo (todos los flujos).
    pub fn stream_bytes_used(&self) -> u64 {
        self.budget.used
    }

    /// Presupuesto global de reensamblado (ver [`Self::with_stream_budget`]).
    pub fn stream_budget(&self) -> u64 {
        self.budget.limit
    }

    /// Entrega y libera los streams de las conexiones TCP **terminadas**:
    /// FIN en las dos direcciones o RST, y al menos `quiet_micros` sin
    /// paquetes hasta `now_micros`. El flujo sigue en la tabla (contadores,
    /// estado, JA4 y resto intactos, así que el resultado final no cambia),
    /// pero deja de recolectar segmentos: su coste vuelve al presupuesto.
    ///
    /// Pensado para el *carving* de capturas grandes: tallar lo ya cerrado
    /// en vez de esperar al final evita que el presupuesto se agote y que
    /// los streams posteriores lleguen truncados. Quien necesite los streams
    /// completos al final (`follow`) no debe llamarlo.
    pub fn release_closed_streams(
        &mut self,
        now_micros: u64,
        quiet_micros: u64,
    ) -> Vec<(FlowId, L7Protocol, ReassembledStream)> {
        let mut out = Vec::new();
        for acc in self.flows.values_mut() {
            let finished = acc.flags.rst > 0 || acc.flags.fin >= 2;
            if !finished
                || acc.streams.is_none()
                || now_micros.saturating_sub(acc.last_seen) < quiet_micros
            {
                continue;
            }
            self.budget.used = self.budget.used.saturating_sub(acc.stream_cost());
            if let Some(sp) = acc.streams.take() {
                let (client, client_lossy) = sp.fwd.reassemble();
                let (server, server_lossy) = sp.rev.reassemble();
                out.push((
                    acc.key.flow_id(),
                    acc.l7,
                    ReassembledStream {
                        client,
                        server,
                        client_lossy,
                        server_lossy,
                    },
                ));
            }
        }
        out
    }

    /// Flujos vivos en la tabla (sin contar los expulsados pendientes).
    pub fn live_flows(&self) -> usize {
        self.flows.len()
    }

    /// Flujos expulsados por `max_flows` aún no entregados.
    pub fn evicted_pending(&self) -> usize {
        self.evicted.len()
    }

    /// Estadísticas acumuladas del pipeline.
    pub fn stats(&self) -> PipelineStats {
        self.stats
    }

    /// Registra un paquete ya diseccionado.
    ///
    /// `raw_len` es el tamaño capturado del paquete (cabeceras incluidas) y
    /// alimenta los contadores de bytes.
    pub fn on_packet(&mut self, ts_micros: u64, raw_len: usize, dp: &DissectedPacket) {
        self.stats.total_packets += 1;

        let (Some(src_ip), Some(dst_ip)) = (dp.src_ip(), dp.dst_ip()) else {
            self.stats.skipped_packets += 1;
            return;
        };
        let transport = dp.transport;
        let (sport, dport) = match (dp.tcp.as_ref(), dp.udp.as_ref()) {
            (Some(t), _) => (t.src_port, t.dst_port),
            (_, Some(u)) => (u.src_port, u.dst_port),
            _ => (0, 0),
        };
        self.stats.parsed_packets += 1;

        let key = FlowKey::new(src_ip, sport, dst_ip, dport, transport);
        if !self.flows.contains_key(&key) && self.flows.len() >= self.max_flows {
            self.force_expire();
        }

        let flows = &mut self.flows;
        let stats = &mut self.stats;
        let acc = flows.entry(key.clone()).or_insert_with(|| {
            stats.flows_created += 1;
            FlowAccum::new(
                key,
                ts_micros,
                src_ip,
                sport,
                dst_ip,
                dport,
                dp,
                self.collect_streams,
            )
        });

        // ¿El paquete va en la dirección del primer paquete (fwd) o en la opuesta?
        let forward = acc.src == src_ip && acc.src_port == sport;
        if forward {
            acc.packets_fwd += 1;
            acc.bytes_fwd += raw_len as u64;
        } else {
            acc.packets_rev += 1;
            acc.bytes_rev += raw_len as u64;
        }

        // Tolerancia a reordenamiento: first_seen solo retrocede.
        if ts_micros < acc.first_seen {
            acc.first_seen = ts_micros;
        }
        if ts_micros > acc.last_seen {
            acc.last_seen = ts_micros;
        }

        // Ventana acotada de timestamps del iniciador (Fase 3, beaconing).
        if forward && acc.times_fwd.len() < MAX_TIMES_FWD {
            acc.times_fwd.push(ts_micros);
        }

        if let Some(t) = dp.tcp.as_ref() {
            let f = t.flags;
            acc.flags.syn += f.syn as u32;
            acc.flags.ack += f.ack as u32;
            acc.flags.fin += f.fin as u32;
            acc.flags.rst += f.rst as u32;
            acc.flags.psh += f.psh as u32;
            acc.flags.urg += f.urg as u32;

            // Reensamblado (Fase 2): solo segmentos con payload.
            if let Some(sp) = acc.streams.as_mut() {
                if !dp.payload.is_empty() {
                    let dir = if forward { &mut sp.fwd } else { &mut sp.rev };
                    dir.push(t.seq, &dp.payload, &mut self.budget);
                }
            }

            // Captura del ClientHello (Fase 3, JA4): solo la dirección del
            // iniciador y en orden de secuencia; la máquina de estados
            // rechaza no-TLS por sí sola. El SYN fija el primer seq de datos
            // para que un segundo segmento adelantado no se tome por el
            // inicio.
            if forward {
                if f.syn && !f.ack && acc.hello_next.is_none() {
                    acc.hello_next = Some(t.seq.wrapping_add(1));
                }
                acc.feed_hello(t.seq, &dp.payload);
            }
        }

        if acc.l7 == L7Protocol::Unknown && dp.l7 != L7Protocol::Unknown {
            acc.l7 = dp.l7;
        }
        if let Some(d) = dp.dns.as_ref() {
            acc.merge_dns(d);
        }
    }

    /// Expulsa los flujos inactivos (last_seen + timeout < now) y los devuelve.
    ///
    /// Incluye también, primero, los flujos que se expulsaron antes por
    /// presión de memoria (`max_flows`): así ningún flujo se pierde sin
    /// exportar y los llamadores existentes no tienen que cambiar.
    pub fn drain_expired(&mut self, now_micros: u64) -> Vec<EnrichedFlow> {
        self.drain_expired_with_streams(now_micros).0
    }

    /// Como [`FlowAggregator::drain_expired`], pero devuelve además los
    /// streams reensamblados (clave: `flow_id`) si `collect_streams` estaba
    /// activo.
    pub fn drain_expired_with_streams(
        &mut self,
        now_micros: u64,
    ) -> (Vec<EnrichedFlow>, HashMap<String, ReassembledStream>) {
        let timeout = self.idle_timeout_micros;
        let expired: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, a)| now_micros.saturating_sub(a.last_seen) > timeout)
            .map(|(k, _)| k.clone())
            .collect();
        let mut out = Vec::with_capacity(self.evicted.len() + expired.len());
        let mut streams_out = HashMap::new();
        for (flow, stream, cost) in std::mem::take(&mut self.evicted) {
            self.budget.used = self.budget.used.saturating_sub(cost);
            if let Some(s) = stream {
                streams_out.insert(flow.flow_id.0.clone(), s);
            }
            out.push(flow);
        }
        for k in expired {
            if let Some(acc) = self.flows.remove(&k) {
                self.budget.used = self.budget.used.saturating_sub(acc.stream_cost());
                let (flow, stream) = Self::export_with_streams(acc);
                if let Some(s) = stream {
                    streams_out.insert(flow.flow_id.0.clone(), s);
                }
                out.push(flow);
            }
        }
        (out, streams_out)
    }

    /// Entrega solo los flujos expulsados por presión de memoria (sin
    /// tocar los vivos), con sus streams si los había.
    pub fn take_evicted(&mut self) -> Vec<(EnrichedFlow, Option<ReassembledStream>)> {
        std::mem::take(&mut self.evicted)
            .into_iter()
            .map(|(flow, stream, cost)| {
                self.budget.used = self.budget.used.saturating_sub(cost);
                (flow, stream)
            })
            .collect()
    }

    /// Foto de los flujos que siguen vivos, sin expulsarlos (vista en
    /// tiempo real). Los que no se han cerrado se marcan `Active`; no
    /// incluye streams reensamblados.
    pub fn snapshot(&self) -> Vec<EnrichedFlow> {
        let mut out: Vec<EnrichedFlow> = self
            .flows
            .values()
            .map(|acc| {
                let mut flow = Self::export_with_streams(acc.clone_without_streams()).0;
                if flow.state == FlowState::Idle {
                    flow.state = FlowState::Active;
                }
                flow
            })
            .collect();
        out.sort_by_key(|f| f.first_seen_micros);
        out
    }

    /// Finaliza la captura y exporta todos los flujos restantes, ordenados
    /// por primer avistamiento (el orden natural para el analista).
    pub fn finish(self) -> Vec<EnrichedFlow> {
        self.finish_with_streams().0
    }

    /// Como [`FlowAggregator::finish`], pero además devuelve los streams TCP
    /// reensamblados por flujo (solo si `collect_streams` estaba activo).
    /// La clave del mapa es el `flow_id` del flujo.
    /// Incluye los flujos expulsados por `max_flows` aún no drenados.
    pub fn finish_with_streams(self) -> (Vec<EnrichedFlow>, HashMap<String, ReassembledStream>) {
        let mut streams_out = HashMap::new();
        let mut out: Vec<EnrichedFlow> = Vec::with_capacity(self.flows.len() + self.evicted.len());
        for (flow, stream, _) in self.evicted {
            if let Some(s) = stream {
                streams_out.insert(flow.flow_id.0.clone(), s);
            }
            out.push(flow);
        }
        for acc in self.flows.into_values() {
            let (flow, streams) = Self::export_with_streams(acc);
            if let Some(s) = streams {
                streams_out.insert(flow.flow_id.0.clone(), s);
            }
            out.push(flow);
        }
        out.sort_by_key(|f| f.first_seen_micros);
        (out, streams_out)
    }

    /// Bajo presión de memoria: expulsa los `excess` flujos con `last_seen`
    /// más antiguo (independientemente de su timeout) hasta dejar la tabla
    /// al 90% de `max_flows`. Los expulsados se exportan a la cola
    /// `evicted`, que entregan `drain_expired` y `finish`.
    fn force_expire(&mut self) {
        let target = self.max_flows * 9 / 10;
        if self.flows.len() <= target {
            return;
        }
        let mut by_age: Vec<(FlowKey, u64)> = self
            .flows
            .iter()
            .map(|(k, v)| (k.clone(), v.last_seen))
            .collect();
        by_age.sort_by_key(|(_, ls)| *ls);
        let excess = self.flows.len() - target;
        for (k, _) in by_age.into_iter().take(excess) {
            if let Some(acc) = self.flows.remove(&k) {
                let cost = acc.stream_cost();
                let (flow, stream) = Self::export_with_streams(acc);
                self.evicted.push((flow, stream, cost));
            }
        }
    }

    /// Convierte un acumulador en el `EnrichedFlow` final y, si procede, su
    /// stream reensamblado. Los campos SOC (riesgo, alertas, resúmenes) los
    /// rellena después `socshark-soc`.
    fn export_with_streams(mut acc: FlowAccum) -> (EnrichedFlow, Option<ReassembledStream>) {
        let state = if acc.flags.fin > 0 || acc.flags.rst > 0 {
            FlowState::Closed
        } else {
            FlowState::Idle
        };
        let streams = acc.streams.take().map(|sp| {
            let (client, client_lossy) = sp.fwd.reassemble();
            let (server, server_lossy) = sp.rev.reassemble();
            ReassembledStream {
                client,
                server,
                client_lossy,
                server_lossy,
            }
        });
        let interval_stats = interval_stats_of(&acc.times_fwd);
        let (ja4_fingerprint, tls_sni) = match acc.hello.hello() {
            Some(ch) => (Some(ch.ja4()), ch.sni.clone()),
            None => (None, None),
        };
        let flow = EnrichedFlow {
            flow_id: acc.key.flow_id(),
            state,
            transport: acc.key.transport,
            l7_protocol: acc.l7,
            ip_version: match acc.src {
                IpAddr::V4(_) => 4,
                IpAddr::V6(_) => 6,
            },
            src_ip: acc.src,
            src_port: acc.src_port,
            dst_ip: acc.dst,
            dst_port: acc.dst_port,
            src_mac: acc.src_mac,
            dst_mac: acc.dst_mac,
            first_seen_micros: acc.first_seen,
            last_seen_micros: acc.last_seen,
            duration_micros: acc.last_seen.saturating_sub(acc.first_seen),
            packets: acc.packets_fwd,
            bytes: acc.bytes_fwd,
            packets_rev: acc.packets_rev,
            bytes_rev: acc.bytes_rev,
            tcp_flags: acc.flags,
            // eBPF (Fase 3) y threat intel (Fase 4): aún sin valor; el
            // enriquecimiento SOC rellena threat_intel si hay listas cargadas.
            process_name: None,
            pid: None,
            user: None,
            resolved_domain: None,
            dns: acc.dns,
            dst_geo_asn: None,
            ja4_fingerprint,
            tls_sni,
            interval_stats,
            threat_intel: Vec::new(),
            is_background_noise: false,
            human_summary: String::new(),
            risk_score: 0,
            alerts: Vec::new(),
            extracted_files: Vec::new(),
        };
        (flow, streams)
    }
}

/// Estadística de intervalos sobre los timestamps del iniciador.
///
/// Se ordena (tolerancia a reordenamiento de la captura) y se calculan los
/// deltas consecutivos; con menos de 3 paquetes (2 intervalos) no hay
/// estadística útil y se devuelve `None`.
fn interval_stats_of(times_fwd: &[u64]) -> Option<IntervalStats> {
    if times_fwd.len() < 3 {
        return None;
    }
    let mut ts = times_fwd.to_vec();
    ts.sort_unstable();
    let deltas: Vec<u64> = ts.windows(2).map(|w| w[1] - w[0]).collect();
    IntervalStats::from_deltas(&deltas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_core::RawPacket;
    use socshark_dissectors::DissectorPipeline;
    use socshark_testgen as tg;

    /// Diseca una trama y devuelve (tamaño_capturado, paquete_diseccionado).
    /// La trama se traslada al heap con duración 'static para simplificar.
    fn dissected(pkt: Vec<u8>) -> (usize, DissectedPacket<'static>) {
        let len = pkt.len();
        let raw: &'static RawPacket = Box::leak(Box::new(RawPacket {
            ts_micros: 0,
            orig_len: len as u32,
            data: pkt,
        }));
        let dp = DissectorPipeline::new()
            .dissect(raw, socshark_core::LinkType::Ethernet)
            .expect("trama del testgen diseccionable");
        (len, dp)
    }

    #[test]
    fn bidireccional_comparte_flujo() {
        let mut agg = FlowAggregator::new(1000, 120, false);
        let (len1, dp1) = dissected(tg::frame_tcp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::WEB,
            52000,
            443,
            1,
            0,
            tg::flags::SYN,
            &[],
        ));
        let (len2, dp2) = dissected(tg::frame_tcp(
            tg::MAC_ROUTER,
            tg::MAC_HOST_A,
            tg::WEB,
            tg::HOST_A,
            443,
            52000,
            2,
            2,
            tg::flags::SYN_ACK,
            &[],
        ));
        agg.on_packet(1_000, len1, &dp1);
        agg.on_packet(2_000, len2, &dp2);

        let flows = agg.finish();
        assert_eq!(flows.len(), 1, "A→B y B→A deben ser el mismo flujo");
        let f = &flows[0];
        assert_eq!(f.packets, 1);
        assert_eq!(f.packets_rev, 1);
        assert_eq!(f.tcp_flags.syn, 2); // SYN + SYN-ACK
        assert_eq!(f.state, FlowState::Idle); // sin FIN/RST
    }

    // ---------------------------------------------- Fase 2: IPv6

    #[test]
    fn flujo_ipv6_se_agrega_como_ipv4() {
        let mut agg = FlowAggregator::new(1000, 120, false);
        let (len1, d1) = dissected(tg::frame_ipv6_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A6,
            tg::DNS6,
            53010,
            53,
            &tg::dns_query(0x0606, "v6.example.com", 28),
        ));
        let (len2, d2) = dissected(tg::frame_ipv6_udp(
            tg::MAC_ROUTER,
            tg::MAC_HOST_A,
            tg::DNS6,
            tg::HOST_A6,
            53,
            53010,
            &tg::dns_response_aaaa(0x0606, "v6.example.com", tg::WEB6),
        ));
        agg.on_packet(1_000, len1, &d1);
        agg.on_packet(2_000, len2, &d2);

        let flows = agg.finish();
        assert_eq!(flows.len(), 1);
        let f = &flows[0];
        assert_eq!(f.ip_version, 6);
        assert_eq!(f.src_ip, IpAddr::V6(tg::HOST_A6));
        assert_eq!(f.dst_ip, IpAddr::V6(tg::DNS6));
        assert_eq!(f.packets_rev, 1);
        let dns = f.dns.as_ref().expect("resumen DNS v6");
        assert_eq!(dns.answers[0].address, Some(IpAddr::V6(tg::WEB6)));
        // flow_id con literal IPv6 entre corchetes visualmente legible.
        assert!(f.flow_id.0.contains("fd00::10") || f.flow_id.0.contains("fd00:"));
    }

    // ---------------------------------------- Fase 2: reensamblado TCP

    /// Pcap sintético: cliente manda 2 segmentos y servidor responde con
    /// un segmento fuera de orden + retransmisión solapada.
    #[allow(clippy::vec_init_then_push)]
    fn pcap_streams() -> Vec<(u64, Vec<u8>)> {
        let (sp, s_seq, r_seq) = (50000u16, 1000u32, 5000u32);
        let mut pkts: Vec<(u64, Vec<u8>)> = Vec::new();
        // Cliente → servidor: "HOLA " (seq 1000) y "MUNDO" (seq 1005).
        pkts.push((
            1_000,
            tg::frame_tcp(
                tg::MAC_HOST_A,
                tg::MAC_ROUTER,
                tg::HOST_A,
                tg::WEB,
                sp,
                8080,
                s_seq,
                r_seq,
                tg::flags::PSH_ACK,
                b"HOLA ",
            ),
        ));
        pkts.push((
            2_000,
            tg::frame_tcp(
                tg::MAC_HOST_A,
                tg::MAC_ROUTER,
                tg::HOST_A,
                tg::WEB,
                sp,
                8080,
                s_seq + 5,
                r_seq,
                tg::flags::PSH_ACK,
                b"MUNDO",
            ),
        ));
        // Servidor → cliente: llega primero el segmento LECLeJO (seq 5005)
        // y después el inicial (seq 5000): fuera de orden en la captura.
        pkts.push((
            3_000,
            tg::frame_tcp(
                tg::MAC_ROUTER,
                tg::MAC_HOST_A,
                tg::WEB,
                tg::HOST_A,
                8080,
                sp,
                r_seq + 5,
                s_seq + 10,
                tg::flags::PSH_ACK,
                b"ECLEJO",
            ),
        ));
        // Retransmisión solapada de "ADIOS" + 2 bytes ya vistos.
        pkts.push((
            4_000,
            tg::frame_tcp(
                tg::MAC_ROUTER,
                tg::MAC_HOST_A,
                tg::WEB,
                tg::HOST_A,
                8080,
                sp,
                r_seq,
                s_seq + 10,
                tg::flags::PSH_ACK,
                b"ADIOSECLEJO",
            ),
        ));
        pkts
    }

    #[test]
    fn reensamblado_orden_retransmisiones_y_huecos() {
        let mut agg = FlowAggregator::new(1000, 120, true);
        let pipe = DissectorPipeline::new();
        for (ts, frame) in pcap_streams() {
            let len = frame.len();
            let raw = RawPacket {
                ts_micros: ts,
                orig_len: len as u32,
                data: frame,
            };
            if let Some(dp) = pipe.dissect(&raw, socshark_core::LinkType::Ethernet) {
                agg.on_packet(ts, len, &dp);
            }
        }
        let (flows, streams) = agg.finish_with_streams();
        assert_eq!(flows.len(), 1);
        let s = streams.get(&flows[0].flow_id.0).expect("stream presente");

        // Cliente: dos segmentos consecutivos → sin huecos.
        assert_eq!(s.client, b"HOLA MUNDO");
        assert!(!s.client_lossy);

        // Servidor: "ECLEJO" llegó antes (seq+5), "ADIOSECLEJO" retransmite
        // "ADIOS" + solapa 6 bytes; el reensamblado debe dar "ADIOS"+"ECLEJO".
        assert_eq!(s.server, b"ADIOSECLEJO");
        assert!(!s.server_lossy);
    }

    #[test]
    fn hueco_de_secuencia_se_marca() {
        let mut agg = FlowAggregator::new(1000, 120, true);
        // Solo dos segmentos con un hueco de 100 bytes entre ellos.
        let (len1, d1) = dissected(tg::frame_tcp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::WEB,
            50001,
            8080,
            1000,
            0,
            tg::flags::PSH_ACK,
            b"INICIO",
        ));
        agg.on_packet(1_000, len1, &d1);
        let (len2, d2) = dissected(tg::frame_tcp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::WEB,
            50001,
            8080,
            1106,
            0,
            tg::flags::PSH_ACK,
            b"FINAL",
        ));
        agg.on_packet(2_000, len2, &d2);

        let (_, streams) = agg.finish_with_streams();
        let s = streams.values().next().unwrap();
        assert_eq!(s.client, b"INICIO\n[100 bytes perdidos]\nFINAL");
        assert!(s.client_lossy);
    }

    #[test]
    fn tope_de_stream_marca_lossy() {
        // 20 segmentos de 60 KiB (el máximo realista de IPv4 son ~65 KiB por
        // datagrama): 1,2 MiB en total supera el tope de 1 MiB por dirección.
        let seg = vec![b'x'; 60_000];
        let mut agg = FlowAggregator::new(1000, 120, true);
        for i in 0..20u32 {
            let seq = 1000 + i * 60_000;
            let (len, d) = dissected(tg::frame_tcp(
                tg::MAC_HOST_A,
                tg::MAC_ROUTER,
                tg::HOST_A,
                tg::WEB,
                50002,
                8080,
                seq,
                0,
                tg::flags::PSH_ACK,
                &seg,
            ));
            agg.on_packet((i as u64 + 1) * 1_000, len, &d);
        }
        let (_, streams) = agg.finish_with_streams();
        let s = streams.values().next().unwrap();
        assert!(
            s.client_lossy,
            "los segmentos que exceden el tope se descartan"
        );
        // 17 × 60.000 = 1.020.000 bytes entran; el 18.º ya excede 1 MiB.
        assert_eq!(s.client.len(), 1_020_000);
    }

    #[test]
    fn sin_collect_streams_no_hay_mapa() {
        let mut agg = FlowAggregator::new(1000, 120, false);
        let (len, d) = dissected(tg::frame_tcp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::WEB,
            50003,
            8080,
            1,
            0,
            tg::flags::PSH_ACK,
            b"payload",
        ));
        agg.on_packet(1_000, len, &d);
        let (_, streams) = agg.finish_with_streams();
        assert!(streams.is_empty());
    }

    #[test]
    fn fin_marcado_como_cerrado() {
        let mut agg = FlowAggregator::new(1000, 120, false);
        let (len1, d1) = dissected(tg::frame_tcp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::WEB,
            52000,
            443,
            1,
            0,
            tg::flags::FIN,
            &[],
        ));
        agg.on_packet(1_000, len1, &d1);
        let f = agg.finish().remove(0);
        assert_eq!(f.state, FlowState::Closed);
    }

    #[test]
    fn dns_query_y_respuesta_se_fusionan() {
        let mut agg = FlowAggregator::new(1000, 120, false);
        let (len1, d1) = dissected(tg::frame_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::DNS_EXT,
            53001,
            53,
            &tg::dns_query(0x1234, "example.com", 1),
        ));
        let (len2, d2) = dissected(tg::frame_udp(
            tg::MAC_ROUTER,
            tg::MAC_HOST_A,
            tg::DNS_EXT,
            tg::HOST_A,
            53,
            53001,
            &tg::dns_response(0x1234, "example.com", 1, tg::WEB),
        ));
        agg.on_packet(1_000, len1, &d1);
        agg.on_packet(2_000, len2, &d2);

        let f = agg.finish().remove(0);
        let dns = f.dns.expect("resumen DNS presente");
        assert!(dns.is_response);
        assert_eq!(dns.queries[0].name, "example.com");
        assert_eq!(dns.answers[0].address, Some(std::net::IpAddr::V4(tg::WEB)));
    }

    #[test]
    fn drain_expired_expulsa_solo_inactivos() {
        let mut agg = FlowAggregator::new(1000, 120, false); // 120 s
        let (len1, d1) = dissected(tg::frame_udp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::DNS_EXT,
            53001,
            53,
            &tg::dns_query(1, "a.example", 1),
        ));
        agg.on_packet(1_000_000, len1, &d1); // t = 1 s

        assert!(agg.drain_expired(30_000_000).is_empty()); // t = 30 s: aún activo
        let expired = agg.drain_expired(200_000_000); // t = 200 s: expira
        assert_eq!(expired.len(), 1);
        assert!(agg.finish().is_empty());
    }

    #[test]
    fn snapshot_no_consume_y_marca_activos() {
        let mut agg = FlowAggregator::new(1000, 120, false);
        for (ts, sport) in [(1_000_000, 53001), (2_000_000, 53002), (3_000_000, 53001)] {
            let (len, d) = dissected(tg::frame_udp(
                tg::MAC_HOST_A,
                tg::MAC_ROUTER,
                tg::HOST_A,
                tg::DNS_EXT,
                sport,
                53,
                &tg::dns_query(1, "a.example", 1),
            ));
            agg.on_packet(ts, len, &d);
        }
        let snap = agg.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].packets, 2, "ordenado por primer avistamiento");
        assert!(snap.iter().all(|f| f.state == FlowState::Active));
        // La foto no cambia nada: los flujos siguen en el agregador.
        let again: Vec<u64> = agg.snapshot().iter().map(|f| f.packets).collect();
        assert_eq!(again, [2, 1]);
        assert_eq!(agg.stats().total_packets, 3);
        let fin = agg.finish();
        assert_eq!(fin.len(), 2);
        assert_eq!(fin[0].state, FlowState::Idle);
    }

    #[test]
    fn max_flows_fuerza_expulsion_de_los_mas_antiguos() {
        let mut agg = FlowAggregator::new(4, 120, false);
        // 6 flujos distintos (puertos origen distintos), límite 4 → quedan ~3-4.
        for i in 0..6u16 {
            let (len, d) = dissected(tg::frame_udp(
                tg::MAC_HOST_A,
                tg::MAC_ROUTER,
                tg::HOST_A,
                tg::DNS_EXT,
                50000 + i,
                53,
                &tg::dns_query(i, &format!("f{i}.example"), 1),
            ));
            agg.on_packet((i as u64 + 1) * 1_000_000, len, &d);
        }
        assert!(
            agg.live_flows() <= 4,
            "la tabla no debe superar max_flows tras la expulsión (obtenido {})",
            agg.live_flows()
        );
        // Los expulsados no se pierden: salen en finish.
        assert_eq!(agg.finish().len(), 6);
    }

    /// Segmento TCP cliente→servidor del flujo de pruebas 50010→443.
    fn seg_cli(seq: u32, flags: u8, payload: &[u8]) -> (usize, DissectedPacket<'static>) {
        dissected(tg::frame_tcp(
            tg::MAC_HOST_A,
            tg::MAC_ROUTER,
            tg::HOST_A,
            tg::WEB,
            50010,
            443,
            seq,
            0,
            flags,
            payload,
        ))
    }

    #[test]
    fn retransmision_con_contenido_distinto_marca_lossy() {
        let mut agg = FlowAggregator::new(1000, 120, true);
        for (i, (seq, data)) in [(1000u32, &b"HOLA MUNDO"[..]), (1005, &b"XXXXX"[..])]
            .into_iter()
            .enumerate()
        {
            let (len, d) = seg_cli(seq, tg::flags::PSH_ACK, data);
            agg.on_packet(i as u64 * 1000, len, &d);
        }
        let (_, streams) = agg.finish_with_streams();
        let s = streams.values().next().unwrap();
        assert_eq!(s.client, b"HOLA MUNDO", "gana lo primero que llegó");
        assert!(s.client_lossy, "el solape difiere: inyección o corrupción");

        // Retransmisión idéntica: no es pérdida.
        let mut agg = FlowAggregator::new(1000, 120, true);
        for (i, (seq, data)) in [(1000u32, &b"HOLA MUNDO"[..]), (1005, &b"MUNDO!"[..])]
            .into_iter()
            .enumerate()
        {
            let (len, d) = seg_cli(seq, tg::flags::PSH_ACK, data);
            agg.on_packet(i as u64 * 1000, len, &d);
        }
        let (_, streams) = agg.finish_with_streams();
        let s = streams.values().next().unwrap();
        assert_eq!(s.client, b"HOLA MUNDO!");
        assert!(!s.client_lossy);
    }

    #[test]
    fn presupuesto_global_y_tope_de_segmentos() {
        // Presupuesto global de 10 KiB repartido entre dos flujos.
        let mut agg = FlowAggregator::new(1000, 120, true).with_stream_budget(10 * 1024);
        let chunk = vec![b'z'; 1000];
        for i in 0..20u32 {
            let (len, d) = seg_cli(1000 + i * 1000, tg::flags::PSH_ACK, &chunk);
            agg.on_packet(i as u64, len, &d);
            assert!(agg.stream_bytes_used() <= 10 * 1024);
        }
        let (_, streams) = agg.finish_with_streams();
        assert!(streams.values().next().unwrap().client_lossy);

        // Segmentos de 1 byte: se corta por número de segmentos.
        let mut agg = FlowAggregator::new(1000, 120, true);
        for i in 0..(MAX_SEGMENTS_PER_DIR as u32 + 10) {
            let (len, d) = seg_cli(1000 + i, tg::flags::PSH_ACK, b"a");
            agg.on_packet(i as u64, len, &d);
        }
        assert!(agg.stream_bytes_used() <= MAX_SEGMENTS_PER_DIR as u64 * (1 + SEGMENT_OVERHEAD));
        let (_, streams) = agg.finish_with_streams();
        let s = streams.values().next().unwrap();
        assert_eq!(s.client.len(), MAX_SEGMENTS_PER_DIR);
        assert!(s.client_lossy);
    }

    #[test]
    fn expulsados_por_max_flows_se_exportan() {
        let mut agg = FlowAggregator::new(4, 120, false);
        for i in 0..6u16 {
            let (len, d) = dissected(tg::frame_udp(
                tg::MAC_HOST_A,
                tg::MAC_ROUTER,
                tg::HOST_A,
                tg::DNS_EXT,
                50000 + i,
                53,
                &tg::dns_query(i, &format!("f{i}.example"), 1),
            ));
            agg.on_packet((i as u64 + 1) * 1_000_000, len, &d);
        }
        assert!(agg.evicted_pending() > 0);
        // Ninguno ha caducado por tiempo, pero los expulsados salen ya.
        let drained = agg.drain_expired(7_000_000);
        assert!(!drained.is_empty());
        assert_eq!(agg.evicted_pending(), 0);
        let rest = agg.finish();
        assert_eq!(drained.len() + rest.len(), 6, "ningún flujo se pierde");

        // Sin drenar, finish los incluye.
        let mut agg = FlowAggregator::new(4, 120, false);
        for i in 0..6u16 {
            let (len, d) = dissected(tg::frame_udp(
                tg::MAC_HOST_A,
                tg::MAC_ROUTER,
                tg::HOST_A,
                tg::DNS_EXT,
                50000 + i,
                53,
                &tg::dns_query(i, &format!("f{i}.example"), 1),
            ));
            agg.on_packet((i as u64 + 1) * 1_000_000, len, &d);
        }
        assert_eq!(agg.finish().len(), 6);
    }

    #[test]
    fn dns_acumula_todos_los_nombres_del_flujo() {
        let mut agg = FlowAggregator::new(1000, 120, false);
        let names = ["a.example", "b.example", "a.example", "c.example"];
        for (i, n) in names.iter().enumerate() {
            let (len, d) = dissected(tg::frame_udp(
                tg::MAC_HOST_A,
                tg::MAC_ROUTER,
                tg::HOST_A,
                tg::DNS_EXT,
                53001,
                53,
                &tg::dns_query(i as u16, n, 1),
            ));
            agg.on_packet(i as u64 * 1000, len, &d);
        }
        let f = agg.finish().remove(0);
        let got: Vec<String> = f.dns.unwrap().queries.into_iter().map(|q| q.name).collect();
        assert_eq!(got, ["a.example", "b.example", "c.example"]);

        // Con cota.
        let mut agg = FlowAggregator::new(1000, 120, false);
        for i in 0..(MAX_DNS_QUERIES as u16 + 20) {
            let (len, d) = dissected(tg::frame_udp(
                tg::MAC_HOST_A,
                tg::MAC_ROUTER,
                tg::HOST_A,
                tg::DNS_EXT,
                53001,
                53,
                &tg::dns_query(i, &format!("n{i}.example"), 1),
            ));
            agg.on_packet(i as u64 * 1000, len, &d);
        }
        let f = agg.finish().remove(0);
        assert_eq!(f.dns.unwrap().queries.len(), MAX_DNS_QUERIES);
    }

    #[test]
    fn client_hello_desordenado_y_retransmitido_da_ja4() {
        let ch = tg::client_hello("tienda.example", b"h2");
        let cut = ch.len() / 2;
        let isn = 7000u32;
        let mut agg = FlowAggregator::new(1000, 120, false);
        let pkts = [
            seg_cli(isn, tg::flags::SYN, &[]),
            // Llega primero la segunda mitad...
            seg_cli(isn + 1 + cut as u32, tg::flags::PSH_ACK, &ch[cut..]),
            // ...luego la primera, y una retransmisión de la primera.
            seg_cli(isn + 1, tg::flags::PSH_ACK, &ch[..cut]),
            seg_cli(isn + 1, tg::flags::PSH_ACK, &ch[..cut]),
        ];
        for (i, (len, d)) in pkts.iter().enumerate() {
            agg.on_packet(i as u64 * 1000, *len, d);
        }
        let f = agg.finish().remove(0);
        assert_eq!(f.tls_sni.as_deref(), Some("tienda.example"));
        assert!(f.ja4_fingerprint.is_some());

        // Una retransmisión intercalada (en orden) tampoco corrompe el CH.
        let mut agg = FlowAggregator::new(1000, 120, false);
        let pkts = [
            seg_cli(isn + 1, tg::flags::PSH_ACK, &ch[..cut]),
            seg_cli(isn + 1, tg::flags::PSH_ACK, &ch[..cut]),
            seg_cli(isn + 1 + cut as u32, tg::flags::PSH_ACK, &ch[cut..]),
        ];
        for (i, (len, d)) in pkts.iter().enumerate() {
            agg.on_packet(i as u64 * 1000, *len, d);
        }
        let f = agg.finish().remove(0);
        assert_eq!(f.tls_sni.as_deref(), Some("tienda.example"));
    }
}
