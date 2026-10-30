//! Cabecera UDP (`parse_udp`) y, si parsea, el payload como DNS.
#![no_main]

use libfuzzer_sys::fuzz_target;
use socshark_dissectors::{parse_dns, parse_udp};

fuzz_target!(|data: &[u8]| {
    if let Some((_info, payload)) = parse_udp(data) {
        let _ = parse_dns(payload);
    }
});
