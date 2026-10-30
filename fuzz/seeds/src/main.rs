//! Genera el corpus inicial de cada objetivo de `fuzz/fuzz_targets/` a
//! partir de los escenarios de `socshark-testgen` (demo, red doméstica y
//! escenarios hostiles del fuzzer determinista).
//!
//! Uso: `cargo run --manifest-path fuzz/seeds/Cargo.toml -- fuzz/corpus`
//! (escribe `fuzz/corpus/<objetivo>/seed-NNNN`). Es idempotente: los
//! nombres son deterministas y se sobrescriben.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use socshark_core::{LinkType, RawPacket};
use socshark_dissectors::DissectorPipeline;
use socshark_dissectors::{parse_ethernet, parse_ipv4, parse_ipv6, parse_tcp, parse_udp};
use socshark_flow::FlowAggregator;
use socshark_testgen as tg;

/// Expresiones DSL de partida (ver docs/filter-dsl.md).
const FILTERS: &[&str] = &[
    "flow.risk >= 50",
    "dns.qname contains \"evil\" || flow.risk >= 50",
    "flow.noise == true || flow.risk >= 50 && ip.dst == 93.184.216.34",
    "!(ip.addr == 10.0.0.1) and tcp.port == 443",
    "tls.sni == \"example.com\" && tls.ja4 != \"\"",
    "dns.qtype == \"TXT\" or dns.rcode == \"NXDOMAIN\"",
    "net.l7 == \"HTTP\" && file.count > 0 && file.name contains \".jpg\"",
    "flow.interval_cv < 0.15 && flow.interval_mean_secs >= 30",
    "tcp.flags.syn == true && tcp.flags.ack == false # escaneo",
    "process.name == 'curl' || process.pid == 4242",
    "ip.version == 6 && udp.port == 53",
    "flow.state == \"cerrado\" and flow.alerts >= 1 and domain contains 'example'",
];

#[derive(Default)]
struct Corpus(BTreeMap<&'static str, Vec<Vec<u8>>>);

impl Corpus {
    fn add(&mut self, target: &'static str, data: &[u8]) {
        let seeds = self.0.entry(target).or_default();
        if !data.is_empty() && !seeds.iter().any(|s| s == data) {
            seeds.push(data.to_vec());
        }
    }

    fn write(&self, root: &Path) -> std::io::Result<()> {
        for (target, seeds) in &self.0 {
            let dir = root.join(target);
            std::fs::create_dir_all(&dir)?;
            for (i, seed) in seeds.iter().enumerate() {
                std::fs::write(dir.join(format!("seed-{i:04}")), seed)?;
            }
            println!("{target}: {} semillas", seeds.len());
        }
        Ok(())
    }
}

fn main() -> std::io::Result<()> {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("fuzz/corpus"));

    let demo = tg::sample_pcap_packets();
    let home = tg::home_pcap_packets();
    let hostile: Vec<Vec<u8>> = tg::fuzz::hostile_scenarios()
        .into_iter()
        .flatten()
        .collect();

    let mut c = Corpus::default();
    let frames = demo
        .iter()
        .chain(home.iter())
        .map(|(_, f)| f.clone())
        .chain(hostile.iter().cloned());
    for frame in frames {
        split_layers(&mut c, &frame);
    }

    // TLS: ClientHello de testgen con y sin ALPN, además de los vistos en
    // los escenarios (ya añadidos por split_layers). El objetivo usa el
    // primer byte como tamaño de trozo: se antepone uno.
    for hello in [
        tg::client_hello("example.com", b"h2"),
        tg::client_hello("cdn.example.org", b""),
    ] {
        c.add("tls", &hello);
        let mut chunked = vec![7u8];
        chunked.extend_from_slice(&hello);
        c.add("tls", &chunked);
    }

    // Capturas completas: pcap clásico y pcapng en sus variantes.
    for packets in [&demo, &home] {
        c.add("pcap", &pcap_bytes(packets));
        for (little_endian, nanos, extra_blocks) in [
            (true, true, false),
            (false, false, true),
            (true, false, true),
        ] {
            let opt = tg::PcapNgOptions {
                little_endian,
                nanos,
                extra_blocks,
            };
            c.add("pcap", &tg::pcapng_bytes(1, packets, opt));
        }
    }

    // Carving: streams reensamblados del escenario demo (incluye la
    // descarga HTTP del ejecutable disfrazado de imagen).
    for (client, server) in http_streams(&demo) {
        let n = client.len().min(usize::from(u16::MAX));
        let mut seed = (n as u16).to_le_bytes().to_vec();
        seed.extend_from_slice(&client[..n]);
        seed.extend_from_slice(&server);
        c.add("carve", &seed);
    }

    for f in FILTERS {
        c.add("filter", f.as_bytes());
    }

    c.write(&root)
}

/// Reparte una trama Ethernet entre los objetivos por capa.
fn split_layers(c: &mut Corpus, frame: &[u8]) {
    c.add("dissect", frame);
    let Some((eth, l3)) = parse_ethernet(frame) else {
        return;
    };
    let l4 = match eth.ethertype {
        0x0800 => {
            c.add("ipv4", l3);
            parse_ipv4(l3).map(|(i, l4)| (i.protocol, l4))
        }
        0x86dd => {
            c.add("ipv6", l3);
            parse_ipv6(l3).map(|(i, l4)| (i.next_header, l4))
        }
        _ => None,
    };
    match l4 {
        Some((6, l4)) => {
            c.add("tcp", l4);
            if let Some((_, payload)) = parse_tcp(l4) {
                if payload.first() == Some(&0x16) {
                    c.add("tls", payload);
                }
            }
        }
        Some((17, l4)) => {
            c.add("udp", l4);
            if let Some((udp, payload)) = parse_udp(l4) {
                if [53, 5353, 5355].contains(&udp.src_port)
                    || [53, 5353, 5355].contains(&udp.dst_port)
                {
                    c.add("dns", payload);
                }
            }
        }
        _ => {}
    }
}

/// Pasa las tramas por el agregador con reensamblado y devuelve los streams
/// TCP que parecen HTTP.
fn http_streams(packets: &[(u64, Vec<u8>)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let pipeline = DissectorPipeline::new();
    let mut agg = FlowAggregator::new(10_000, 3_600, true);
    for (ts, frame) in packets {
        let raw = RawPacket {
            ts_micros: *ts,
            orig_len: frame.len() as u32,
            data: frame.clone(),
        };
        if let Some(dp) = pipeline.dissect(&raw, LinkType::Ethernet) {
            agg.on_packet(raw.ts_micros, raw.data.len(), &dp);
        }
    }
    let (_, streams) = agg.finish_with_streams();
    let mut out: Vec<_> = streams
        .into_values()
        .filter(|s| s.server.starts_with(b"HTTP/") || s.client.starts_with(b"GET "))
        .map(|s| (s.client, s.server))
        .collect();
    out.sort();
    out
}

/// pcap clásico en memoria (mismo formato que `tg::write_pcap`).
fn pcap_bytes(packets: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&65535u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    for (ts, data) in packets {
        buf.extend_from_slice(&((ts / 1_000_000) as u32).to_le_bytes());
        buf.extend_from_slice(&((ts % 1_000_000) as u32).to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
    }
    buf
}
