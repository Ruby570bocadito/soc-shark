//! ClientHello TLS: parser directo (`parse_client_hello` + JA4) y el
//! acumulador por segmentos (`ClientHelloCapture`), con la entrada partida
//! en trozos cuyo tamaño decide el primer byte (registros TLS partidos en
//! varios segmentos TCP).
#![no_main]

use libfuzzer_sys::fuzz_target;
use socshark_dissectors::{parse_client_hello, ClientHelloCapture};

fuzz_target!(|data: &[u8]| {
    if let Some(ch) = parse_client_hello(data) {
        let _ = ch.ja4();
        let _ = ch.has_sni_extension();
    }

    let Some((&chunk, rest)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(chunk).max(1);
    let mut cap = ClientHelloCapture::default();
    for segment in rest.chunks(chunk) {
        cap.feed(segment);
        if cap.is_done() {
            break;
        }
    }
    let _ = cap.ja4();
    let _ = cap.hello();
});
