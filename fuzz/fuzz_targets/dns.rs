//! Parser DNS (`parse_dns`) con payloads UDP arbitrarios: compresión de
//! nombres con punteros en bucle, recuentos mentirosos, RDATA truncada...
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = socshark_dissectors::parse_dns(data);
});
