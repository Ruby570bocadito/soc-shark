//! Cabecera IPv6 (`parse_ipv6`) con cadenas de cabeceras de extensión
//! arbitrarias. Si parsea, el resto se pasa también a TCP y UDP.
#![no_main]

use libfuzzer_sys::fuzz_target;
use socshark_dissectors::{parse_ipv6, parse_tcp, parse_udp};

fuzz_target!(|data: &[u8]| {
    if let Some((_info, l4)) = parse_ipv6(data) {
        let _ = parse_tcp(l4);
        let _ = parse_udp(l4);
    }
});
