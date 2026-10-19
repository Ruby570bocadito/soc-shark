//! Qué programa de este ordenador tiene abierta cada conexión.
//!
//! Wireshark no lo sabe: solo ve paquetes. Pero en vivo, para el tráfico de
//! la propia máquina, el sistema operativo sí sabe qué proceso es dueño de
//! cada puerto local. [`SocketTable::snapshot`] hace una foto de esa tabla:
//!
//! - **Linux**: `/proc/net/{tcp,tcp6,udp,udp6}` da puerto → inodo, y los
//!   enlaces `/proc/<pid>/fd/*` (`socket:[inodo]`) dan inodo → proceso. Sin
//!   privilegios solo se ven los procesos propios.
//! - **Windows**: `GetExtendedTcpTable`/`GetExtendedUdpTable` (iphlpapi)
//!   con PID, y `QueryFullProcessImageNameW` para el nombre.
//! - Resto: no disponible (error claro, nunca pánico).
//!
//! Una conexión muy corta puede abrirse y cerrarse entre dos fotos: entonces
//! simplemente no se sabe su programa.

use std::collections::HashMap;

use socshark_core::Transport;

use crate::CaptureError;

/// Proceso dueño de un socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketOwner {
    pub pid: u32,
    /// Nombre del ejecutable (`chrome.exe`, `firefox`).
    pub name: String,
}

/// Foto de los sockets TCP/UDP del sistema con su programa.
#[derive(Debug, Default, Clone)]
pub struct SocketTable {
    by_port: HashMap<(bool, u16), SocketOwner>,
}

impl SocketTable {
    /// Programa que tiene abierto el puerto local `port` (TCP o UDP).
    pub fn lookup(&self, transport: Transport, port: u16) -> Option<&SocketOwner> {
        let tcp = match transport {
            Transport::Tcp => true,
            Transport::Udp => false,
            _ => return None,
        };
        self.by_port.get(&(tcp, port))
    }

    pub fn len(&self) -> usize {
        self.by_port.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_port.is_empty()
    }

    /// Foto actual de la tabla de sockets.
    pub fn snapshot() -> Result<Self, CaptureError> {
        imp::snapshot()
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::fs;

    /// Puertos locales e inodos de una tabla de `/proc/net`.
    fn parse_proc_net(text: &str) -> Vec<(u16, u64)> {
        text.lines()
            .skip(1)
            .filter_map(|line| {
                let cols: Vec<&str> = line.split_whitespace().collect();
                let port_hex = cols.get(1)?.rsplit(':').next()?;
                let port = u16::from_str_radix(port_hex, 16).ok()?;
                let inode: u64 = cols.get(9)?.parse().ok()?;
                (inode != 0).then_some((port, inode))
            })
            .collect()
    }

    /// Nombre del proceso: el del ejecutable si se puede leer, si no `comm`.
    fn process_name(pid: u32) -> Option<String> {
        if let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe")) {
            if let Some(name) = exe.file_name().and_then(|n| n.to_str()) {
                return Some(name.trim_end_matches(" (deleted)").to_string());
            }
        }
        let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        Some(comm.trim().to_string()).filter(|c| !c.is_empty())
    }

    pub(super) fn snapshot() -> Result<SocketTable, CaptureError> {
        let mut by_inode: HashMap<u64, (bool, u16)> = HashMap::new();
        for (file, tcp) in [
            ("tcp", true),
            ("tcp6", true),
            ("udp", false),
            ("udp6", false),
        ] {
            if let Ok(text) = fs::read_to_string(format!("/proc/net/{file}")) {
                for (port, inode) in parse_proc_net(&text) {
                    by_inode.insert(inode, (tcp, port));
                }
            }
        }
        let mut table = SocketTable::default();
        if by_inode.is_empty() {
            return Ok(table);
        }
        let procs = fs::read_dir("/proc").map_err(CaptureError::Io)?;
        for entry in procs.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            // Sin permiso sobre los fd de otro usuario: se salta.
            let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
                continue;
            };
            let mut name: Option<Option<String>> = None;
            for fd in fds.flatten() {
                let Ok(target) = fs::read_link(fd.path()) else {
                    continue;
                };
                let Some(inode) = target
                    .to_str()
                    .and_then(|t| t.strip_prefix("socket:["))
                    .and_then(|t| t.strip_suffix(']'))
                    .and_then(|t| t.parse::<u64>().ok())
                else {
                    continue;
                };
                if let Some(&key) = by_inode.get(&inode) {
                    let name = name.get_or_insert_with(|| process_name(pid));
                    if let Some(n) = name {
                        table.by_port.entry(key).or_insert(SocketOwner {
                            pid,
                            name: n.clone(),
                        });
                    }
                }
            }
        }
        Ok(table)
    }

    #[cfg(test)]
    #[test]
    fn tabla_de_proc_net() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n   1: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1\n";
        assert_eq!(parse_proc_net(text), vec![(8080, 12345)]);
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::c_void;

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    const UDP_TABLE_OWNER_PID: u32 = 1;
    const NO_ERROR: u32 = 0;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedTcpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            af: u32,
            class: u32,
            reserved: u32,
        ) -> u32;
        fn GetExtendedUdpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            af: u32,
            class: u32,
            reserved: u32,
        ) -> u32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn QueryFullProcessImageNameW(
            process: *mut c_void,
            flags: u32,
            name: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    type TableFn = unsafe extern "system" fn(*mut c_void, *mut u32, i32, u32, u32, u32) -> u32;

    /// Llama a la API con el patrón de dos pasos (tamaño, luego datos).
    fn fetch(f: TableFn, af: u32, class: u32) -> Option<Vec<u8>> {
        let mut size: u32 = 0;
        for _ in 0..4 {
            let mut buf = vec![0u8; size as usize + 4096];
            size = buf.len() as u32;
            // SAFETY: el búfer mide `size` bytes; la API escribe como mucho
            // eso y, si no cabe, devuelve el tamaño necesario.
            let rc = unsafe { f(buf.as_mut_ptr().cast(), &mut size, 0, af, class, 0) };
            match rc {
                NO_ERROR => {
                    buf.truncate(size as usize);
                    return Some(buf);
                }
                ERROR_INSUFFICIENT_BUFFER => continue,
                _ => return None,
            }
        }
        None
    }

    fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
        Some(u32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?))
    }

    /// El puerto va en orden de red en los 16 bits bajos.
    fn port_of(raw: u32) -> u16 {
        u16::from_be_bytes([(raw & 0xff) as u8, ((raw >> 8) & 0xff) as u8])
    }

    /// Filas `(puerto, pid)` de una tabla: `row` bytes por fila, el puerto
    /// y el PID en los desplazamientos dados.
    fn rows(buf: &[u8], row: usize, port_off: usize, pid_off: usize) -> Vec<(u16, u32)> {
        let n = u32_at(buf, 0).unwrap_or(0) as usize;
        (0..n.min(buf.len() / row))
            .filter_map(|i| {
                let base = 4 + i * row;
                Some((
                    port_of(u32_at(buf, base + port_off)?),
                    u32_at(buf, base + pid_off)?,
                ))
            })
            .collect()
    }

    fn process_name(pid: u32) -> Option<String> {
        match pid {
            // PID 0: conexiones cerrándose (TIME_WAIT), sin dueño real.
            0 => return None,
            4 => return Some("System".into()),
            _ => {}
        }
        // SAFETY: handle propio, se cierra siempre; el búfer mide `size`.
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut buf = vec![0u16; 1024];
            let mut size = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
            CloseHandle(h);
            if ok == 0 {
                return None;
            }
            let path = String::from_utf16_lossy(&buf[..size as usize]);
            path.rsplit('\\').next().map(str::to_string)
        }
    }

    pub(super) fn snapshot() -> Result<SocketTable, CaptureError> {
        let mut pairs: Vec<(bool, u16, u32)> = Vec::new();
        // MIB_TCPROW_OWNER_PID: estado, ip local, puerto local, ip remota,
        // puerto remoto, pid (24 bytes). MIB_TCP6ROW_OWNER_PID: 56 bytes.
        if let Some(b) = fetch(GetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_ALL) {
            pairs.extend(
                rows(&b, 24, 8, 20)
                    .into_iter()
                    .map(|(p, pid)| (true, p, pid)),
            );
        }
        if let Some(b) = fetch(GetExtendedTcpTable, AF_INET6, TCP_TABLE_OWNER_PID_ALL) {
            pairs.extend(
                rows(&b, 56, 20, 52)
                    .into_iter()
                    .map(|(p, pid)| (true, p, pid)),
            );
        }
        // MIB_UDPROW_OWNER_PID: ip, puerto, pid (12). UDP6: 28.
        if let Some(b) = fetch(GetExtendedUdpTable, AF_INET, UDP_TABLE_OWNER_PID) {
            pairs.extend(
                rows(&b, 12, 4, 8)
                    .into_iter()
                    .map(|(p, pid)| (false, p, pid)),
            );
        }
        if let Some(b) = fetch(GetExtendedUdpTable, AF_INET6, UDP_TABLE_OWNER_PID) {
            pairs.extend(
                rows(&b, 28, 20, 24)
                    .into_iter()
                    .map(|(p, pid)| (false, p, pid)),
            );
        }
        let mut names: HashMap<u32, Option<String>> = HashMap::new();
        let mut table = SocketTable::default();
        for (tcp, port, pid) in pairs {
            let name = names.entry(pid).or_insert_with(|| process_name(pid));
            if let Some(n) = name {
                table.by_port.entry((tcp, port)).or_insert(SocketOwner {
                    pid,
                    name: n.clone(),
                });
            }
        }
        Ok(table)
    }

    #[cfg(test)]
    #[test]
    fn puerto_en_orden_de_red() {
        // 8080 = 0x1F90 → en memoria 0x90 0x1F en los 16 bits bajos.
        assert_eq!(port_of(0x0000_901F), 8080);
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod imp {
    use super::*;

    pub(super) fn snapshot() -> Result<SocketTable, CaptureError> {
        Err(CaptureError::LiveUnavailable(
            "saber qué programa usa cada conexión solo está disponible en Linux y Windows".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un socket propio abierto aquí mismo aparece con este programa.
    #[test]
    fn el_socket_propio_tiene_dueno() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let table = match SocketTable::snapshot() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("no disponible aquí: {e}");
                return;
            }
        };
        let Some(owner) = table.lookup(Transport::Tcp, port) else {
            // Wine (con el que se prueba el .exe) no informa del proceso
            // dueño; en Linux y en Windows real tiene que aparecer.
            #[cfg(not(windows))]
            panic!("puerto {port} sin dueño en {} sockets", table.len());
            #[cfg(windows)]
            {
                eprintln!("sin proceso dueño (¿Wine?): se omite");
                return;
            }
        };
        assert_eq!(owner.pid, std::process::id());
        assert!(!owner.name.is_empty());
        assert!(table.lookup(Transport::Icmp, port).is_none());
    }
}
