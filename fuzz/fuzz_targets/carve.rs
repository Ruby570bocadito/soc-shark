//! *File carving* HTTP (`carve_http`) sobre un stream TCP reensamblado
//! sintético. Formato de la entrada: 2 bytes little-endian con la longitud
//! del lado cliente, el lado cliente y, el resto, el lado servidor.
//! Cubre la búsqueda de cabeceras, `Content-Length`, *chunked* y la
//! detección de *magic bytes*.
#![no_main]

use libfuzzer_sys::fuzz_target;
use socshark_soc::carve::{carve_http, detect_magic, masquerading_suspect};

fuzz_target!(|data: &[u8]| {
    let Some((len, rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let split = usize::from(u16::from_le_bytes(*len)).min(rest.len());
    let (client, server) = rest.split_at(split);

    for file in carve_http(client, server) {
        let _ = masquerading_suspect(&file.name, file.magic.as_deref());
    }
    let magic = detect_magic(server);
    if let Ok(name) = std::str::from_utf8(client) {
        let _ = masquerading_suspect(name, magic);
    }
});
