//! Lector de capturas pcap/pcapng (`PcapFileReader::new` sobre un
//! `Cursor`): cabeceras, bloques y longitudes corruptas. Cada paquete leído
//! se disecciona con el tipo de enlace que declara el archivo.
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use socshark_capture::{CaptureSource, PcapFileReader};
use socshark_dissectors::DissectorPipeline;

/// Tope de paquetes por entrada: el lector siempre avanza, pero así una
/// entrada lenta no se confunde con un cuelgue.
const MAX_PACKETS: usize = 10_000;

fuzz_target!(|data: &[u8]| {
    let Ok(mut reader) = PcapFileReader::new(Cursor::new(data)) else {
        return;
    };
    let _ = reader.is_pcapng();
    let _ = reader.nanosecond_resolution();
    let pipeline = DissectorPipeline::new();
    for _ in 0..MAX_PACKETS {
        match reader.next_packet() {
            Ok(Some(raw)) => {
                let _ = pipeline.dissect(&raw, reader.link_type());
            }
            Ok(None) | Err(_) => break,
        }
    }
});
