//! Linux cooked capture (SLL, DLT_LINUX_SLL = 113).

/// Cabecera SLL de 16 bytes: solo extraemos el protocolo.
pub struct SllFrame<'a> {
    /// Ethertype efectivo (campo `protocol` de la cabecera SLL).
    pub protocol: u16,
    pub payload: &'a [u8],
}

pub fn parse_sll(data: &[u8]) -> Option<SllFrame<'_>> {
    if data.len() < 16 {
        return None;
    }
    let protocol = u16::from_be_bytes([data[14], data[15]]);
    Some(SllFrame {
        protocol,
        payload: &data[16..],
    })
}
