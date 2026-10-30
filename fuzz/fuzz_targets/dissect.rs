//! Pipeline de dissectors completo (`DissectorPipeline::dissect`) sobre una
//! trama arbitraria: Ethernet/VLAN → IPv4/IPv6 → TCP/UDP → DNS/L7. La misma
//! entrada se prueba también como IP crudo, Linux SLL/SLL2 y loopback BSD.
#![no_main]

use libfuzzer_sys::fuzz_target;
use socshark_core::{LinkType, RawPacket};
use socshark_dissectors::DissectorPipeline;

const LINKS: [LinkType; 5] = [
    LinkType::Ethernet,
    LinkType::RawIp,
    LinkType::Unknown(113),
    LinkType::Unknown(276),
    LinkType::Unknown(0),
];

fuzz_target!(|data: &[u8]| {
    let raw = RawPacket {
        ts_micros: 1_700_000_000_000_000,
        orig_len: data.len() as u32,
        data: data.to_vec(),
    };
    let pipeline = DissectorPipeline::new();
    for link in LINKS {
        if let Some(dp) = pipeline.dissect(&raw, link) {
            let _ = dp.src_ip();
            let _ = dp.dst_ip();
            let _ = dp.into_owned();
        }
    }
});
