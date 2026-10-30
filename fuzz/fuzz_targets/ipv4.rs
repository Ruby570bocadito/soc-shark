//! Cabecera IPv4 (`parse_ipv4`): IHL, longitud total y fragmentación
//! hostiles. Si parsea, el resto se pasa también a TCP y UDP.
#![no_main]

use libfuzzer_sys::fuzz_target;
use socshark_dissectors::{parse_ipv4, parse_tcp, parse_udp};

fuzz_target!(|data: &[u8]| {
    if let Some((info, l4)) = parse_ipv4(data) {
        let _ = info.is_non_initial_fragment();
        let _ = parse_tcp(l4);
        let _ = parse_udp(l4);
    }
});
