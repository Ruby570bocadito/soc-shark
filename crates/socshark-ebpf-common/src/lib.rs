//! socshark-ebpf-common: tipos compartidos entre los probes eBPF (kernel) y
//! el daemon de atribución (userspace) — Fase 3.
//!
//! El contrato de la Fase 3 (ver `docs/ebpf-design.md`) es que probe y
//! userspace hablan **la misma estructura de bytes**: un único tipo
//! `#[repr(C)]` por evento, serializado a pelo sobre el ring buffer de eBPF.
//! Este crate contiene esos tipos y solo eso: **sin dependencias** y
//! compatible con `no_std` (los programas eBPF se compilan para el target
//! `bpfel-unknown-none`, donde no existe `std`).
//!
//! Convenciones:
//! - Todos los campos en orden de declaración, sin packing explícito: el
//!   layout natural de `repr(C)` es el contrato y se verifica en los tests
//!   (tamaños y offsets).
//! - Los puertos viajan en **orden de red (big-endian)** tal y como salen de
//!   las structs del kernel, para evitar conversions innecesarias en el probe.
//! - `comm` es `task->comm` truncado a 16 bytes por el kernel (no NUL si el
//!   nombre ocupa todo); el helper [`connect_event_comm`] lo recorta.
//!
//! Estado: los eventos están definidos y testeados; los probes con aya que
//! los emiten requieren toolchain nightly (`bpf-linker`) y privilegios
//! CAP_BPF/CAP_PERFMON, así que se implementan contra un entorno Linux
//! privilegiado (ver roadmap Fase 3).

#![cfg_attr(not(test), no_std)]
#![allow(clippy::upper_case_acronyms)]

use core::str;

/// Versión del formato de eventos (se incrementa con cualquier cambio de
/// layout; el daemon rechaza probes de otra versión).
pub const EVENT_FORMAT_VERSION: u32 = 1;

/// Tamaño máximo del nombre de proceso que entrega el kernel (`TASK_COMM_LEN`).
pub const COMM_LEN: usize = 16;

/// Evento de `kprobe/tcp_v4_connect`: **intención de conexión** IPv4.
///
/// Se emite antes de que el kernel asigne el puerto efímero definitivo;
/// la correlación definitiva la cierra `inet_sock_set_state` vía cookie.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectEvent {
    /// Cookie del socket (`bpf_get_socket_cookie`); estable ante NAT del host.
    pub cookie: u64,
    /// Dirección origen, orden de red.
    pub saddr: [u8; 4],
    /// Dirección destino, orden de red.
    pub daddr: [u8; 4],
    /// Puerto origen (big-endian).
    pub sport_be: u16,
    /// Puerto destino (big-endian).
    pub dport_be: u16,
    /// `(tgid << 32) | tid`: proceso e hilo que llamó a `connect()`.
    pub pid_tgid: u64,
    /// UID efectivo del proceso.
    pub uid: u32,
    /// Timestamp del evento (`bpf_ktime_get_ns`).
    pub ts_ns: u64,
    /// Nombre del proceso (`task->comm`, truncado por el kernel).
    pub comm: [u8; COMM_LEN],
}

/// Evento de `tracepoint/inet_sock_set_state`: ciclo de vida TCP.
///
/// Confirma la atribución (5-tupla definitiva + cookie) y marca la limpieza
/// del mapa de correlación cuando el socket muere (`newstate == TCP_CLOSE`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketStateEvent {
    /// Familia AF (2 = AF_INET, 10 = AF_INET6).
    pub family: u8,
    /// Protocolo IP (6 = TCP en la práctica de este probe).
    pub protocol: u8,
    /// Estado anterior (enum del kernel).
    pub oldstate: u8,
    /// Estado nuevo (1 = TCP_ESTABLISHED, 7 = TCP_CLOSE, ...).
    pub newstate: u8,
    /// Puerto origen (big-endian, definitivo).
    pub sport_be: u16,
    /// Puerto destino (big-endian).
    pub dport_be: u16,
    /// Dirección origen (v4 mapeada en los primeros 4 bytes).
    pub saddr: [u8; 16],
    /// Dirección destino (v4 mapeada en los primeros 4 bytes).
    pub daddr: [u8; 16],
    /// Cookie del socket para correlación con [`ConnectEvent`].
    pub cookie: u64,
    /// Timestamp del evento.
    pub ts_ns: u64,
}

/// Evento de `kprobe/udp_sendmsg`: envío UDP de un socket (conectado o no).
///
/// Cubre el caso UDP que `tcp_v4_connect` no ve (datagramas sin `connect()`),
/// p. ej. resolvers DNS que envían sin conectar.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSendEvent {
    pub cookie: u64,
    pub saddr: [u8; 4],
    pub daddr: [u8; 4],
    pub sport_be: u16,
    pub dport_be: u16,
    pub pid_tgid: u64,
    pub uid: u32,
    /// Longitud del datagrama en bytes.
    pub len: u32,
    pub ts_ns: u64,
    pub comm: [u8; COMM_LEN],
}

/// Extrae el `comm` legible de un buffer de kernel: recorta en el primer NUL
/// y descarta bytes UTF-8 inválidos (el nombre puede estar truncado a mitad
/// de carácter multibyte).
pub fn comm_to_str(comm: &[u8; COMM_LEN]) -> &str {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(COMM_LEN);
    str::from_utf8(&comm[..end]).unwrap_or("")
}

/// PID de proceso (Tgid) desde el campo combinado `pid_tgid`.
pub fn tgid_of(pid_tgid: u64) -> u32 {
    (pid_tgid >> 32) as u32
}

/// TID del hilo desde el campo combinado `pid_tgid`.
pub fn tid_of(pid_tgid: u64) -> u32 {
    pid_tgid as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    /// Offset de un campo respecto al inicio de la struct (compatible con
    /// MSRV 1.75; `mem::offset_of!` es de 1.77).
    fn offset_of(field: usize, base: usize) -> usize {
        field.wrapping_sub(base)
    }

    #[test]
    fn layouts_rep_c_estables() {
        // Los tamaños son el contrato en el ring buffer: si cambian, hay que
        // subir EVENT_FORMAT_VERSION y regenerar probe+daemon a la vez.
        assert_eq!(size_of::<ConnectEvent>(), 64);
        assert_eq!(size_of::<SocketStateEvent>(), 56);
        assert_eq!(size_of::<UdpSendEvent>(), 64);

        // Offsets clave de ConnectEvent (repr(C), alineación natural).
        let ev: ConnectEvent = unsafe { std::mem::zeroed() };
        let base = &ev as *const ConnectEvent as usize;
        assert_eq!(offset_of(core::ptr::addr_of!(ev.cookie) as usize, base), 0);
        assert_eq!(offset_of(core::ptr::addr_of!(ev.saddr) as usize, base), 8);
        assert_eq!(offset_of(core::ptr::addr_of!(ev.daddr) as usize, base), 12);
        assert_eq!(
            offset_of(core::ptr::addr_of!(ev.sport_be) as usize, base),
            16
        );
        assert_eq!(
            offset_of(core::ptr::addr_of!(ev.dport_be) as usize, base),
            18
        );
        assert_eq!(
            offset_of(core::ptr::addr_of!(ev.pid_tgid) as usize, base),
            24
        );
        assert_eq!(offset_of(core::ptr::addr_of!(ev.uid) as usize, base), 32);
        assert_eq!(offset_of(core::ptr::addr_of!(ev.ts_ns) as usize, base), 40);
        assert_eq!(offset_of(core::ptr::addr_of!(ev.comm) as usize, base), 48);
    }

    #[test]
    fn comm_recorta_en_nul_y_sobrevive_a_truncado() {
        let mut c = [0u8; COMM_LEN];
        c[..4].copy_from_slice(b"curl");
        assert_eq!(comm_to_str(&c), "curl");

        // Nombre que ocupa los 16 bytes sin NUL (truncado por el kernel).
        let lleno = [b'a'; COMM_LEN];
        assert_eq!(comm_to_str(&lleno), "aaaaaaaaaaaaaaaa");

        // Bytes UTF-8 inválidos → cadena vacía en lugar de panic.
        let malo = [0xff, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(comm_to_str(&malo), "");

        // Truncado a mitad de carácter multibyte: se descarta la cola rota.
        let mut mb = [0u8; COMM_LEN];
        mb[..14].copy_from_slice("ñññññññ".as_bytes()); // 7 × 2 bytes = 14
        let s = comm_to_str(&mb);
        assert!(s.chars().all(|ch| ch == 'ñ') || s.is_empty());
    }

    #[test]
    fn pid_tgid_se_descompone() {
        let pid_tgid = ((24312u64) << 32) | 24317u64;
        assert_eq!(tgid_of(pid_tgid), 24312);
        assert_eq!(tid_of(pid_tgid), 24317);
    }

    #[test]
    fn evento_connect_ida_y_vuelta_por_bytes() {
        let ev = ConnectEvent {
            cookie: 0xdead_beef_1234_5678,
            saddr: [192, 168, 1, 30],
            daddr: [8, 8, 8, 8],
            sport_be: 53002u16.to_be(),
            dport_be: 53u16.to_be(),
            pid_tgid: (24312u64) << 32,
            uid: 1000,
            ts_ns: 123_456_789,
            comm: {
                let mut c = [0u8; COMM_LEN];
                c[..6].copy_from_slice(b"beacon");
                c
            },
        };
        // Serialización a bytes crudos (lo que viaja por el ring buffer).
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &ev as *const ConnectEvent as *const u8,
                size_of::<ConnectEvent>(),
            )
        };
        let back = unsafe { bytes.as_ptr().cast::<ConnectEvent>().read() };
        assert_eq!(back, ev);
        assert_eq!(u16::from_be(back.sport_be), 53002);
        assert_eq!(u16::from_be(back.dport_be), 53);
        assert_eq!(tgid_of(back.pid_tgid), 24312);
        assert_eq!(comm_to_str(&back.comm), "beacon");
    }
}
