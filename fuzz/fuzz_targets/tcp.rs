//! Cabecera TCP (`parse_tcp`): data offset y opciones hostiles.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = socshark_dissectors::parse_tcp(data);
});
