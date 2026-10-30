//! Captura en vivo sobre libpcap — backend de la Fase 2.
//!
//! Diseño (ADR-009): **FFI propio + `dlopen` en tiempo de ejecución**. No se
//! declara ninguna dependencia de Rust nueva (ADR-003 sigue congelado en
//! cinco crates) ni hace falta `libpcap-dev` para compilar: la biblioteca se
//! busca al abrir la interfaz y, si falta, se devuelve un error limpio con
//! instrucciones de instalación. El binario por defecto se construye y
//! funciona en cualquier máquina; la captura en vivo es una capacidad que se
//! resuelve al ejecutar, no al compilar.
//!
//! Contrato con libpcap (solo funciones estables de la API pública):
//! 1. `pcap_create` → handle inactivo.
//! 2. Configuración *pre-activación*: snaplen, promiscuo, timeout de lectura
//!    e *immediate mode* en unix (los paquetes se entregan sin agrupar:
//!    latencia mínima en las alertas). En Windows no se usa: Npcap entrega
//!    al vencer el timeout, que ya acota la latencia, y así también vale con
//!    versiones e implementaciones que no lo tienen.
//! 3. *Pushdown* BPF (ADR-004): el filtro DSL↔BPF se compila con
//!    `pcap_compile` y baja al kernel con `pcap_setfilter`, de modo que el
//!    tráfico irrelevante nunca llega al userspace.
//! 4. `pcap_activate` → captura; `pcap_next_ex` en bucle.
//!
//! Modelo de hilos: el handle de libpcap no es thread-safe, así que
//! `LiveCapture` se declara `Send` (se puede mover a otro hilo) pero no
//! `Sync` (no se comparte). El daemon lo usa desde un único hilo de lectura.
//!
//! Plataformas: Linux y macOS de 64 bits (libpcap con `dlopen`) y Windows
//! x64 (Npcap: `wpcap.dll` con `LoadLibraryExW`, misma API que libpcap). En
//! el resto se compila un stub que devuelve [`CaptureError::LiveUnavailable`].
//! En Windows no hay `poll`: el timeout de lectura de Npcap sí devuelve el
//! control sin tráfico, así que el *tick* lo da `pcap_next_ex`.

use std::net::IpAddr;

use crate::{CaptureError, CaptureSource};
use socshark_core::{LinkType, RawPacket};

/// Listado de interfaces capturables (`pcap_findalldevs`).
#[derive(Debug, Clone, Default)]
pub struct LiveIface {
    pub name: String,
    pub description: Option<String>,
    /// Direcciones IP asignadas: lo que permite a una persona reconocer
    /// "su" Wi-Fi o su cable (`192.168.1.23`).
    pub addresses: Vec<IpAddr>,
    /// Red interna del propio equipo.
    pub loopback: bool,
    /// Encendida y funcionando (`PCAP_IF_UP` y `PCAP_IF_RUNNING`).
    pub up: bool,
    /// Inalámbrica (libpcap ≥ 1.9 / Npcap).
    pub wireless: bool,
    /// `Some(true)` conectada, `Some(false)` desconectada; `None` si el
    /// sistema no lo sabe o no aplica.
    pub connected: Option<bool>,
}

/// Parámetros de apertura de una interfaz en vivo. Independiente de
/// plataforma: el stub de plataformas sin soporte la usa igualmente.
#[derive(Debug, Clone)]
pub struct LiveCaptureConfig {
    /// Nombre de la interfaz (`eth0`, `ens3`, `en0`, `lo`, ...).
    pub iface: String,
    /// Bytes máximos capturados por paquete (65535 = sin recorte).
    pub snaplen: i32,
    /// Modo promiscuo (necesario para ver tráfico ajeno a la máquina).
    pub promisc: bool,
    /// Timeout de lectura en ms: cadencia máxima de "tick" sin tráfico
    /// para que el daemon pueda expirar flujos y vaciar búferes.
    pub timeout_ms: i32,
    /// Filtro BPF con *pushdown* al kernel (sintaxis pcap, p. ej.
    /// `tcp port 443`). `None` captura todo.
    pub bpf: Option<String>,
}

impl LiveCaptureConfig {
    pub fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
            snaplen: 65_535,
            promisc: true,
            timeout_ms: 1_000,
            bpf: None,
        }
    }

    pub fn with_snaplen(mut self, snaplen: i32) -> Self {
        self.snaplen = snaplen;
        self
    }

    pub fn with_promisc(mut self, promisc: bool) -> Self {
        self.promisc = promisc;
        self
    }

    pub fn with_bpf(mut self, bpf: Option<String>) -> Self {
        self.bpf = bpf;
        self
    }
}

/// Convierte un `timeval` de libpcap a microsegundos Unix sin desbordar:
/// los valores negativos (posibles con `tv_sec` de 32 bits en Windows o un
/// reloj corrupto) se fijan a 0 y el producto se satura.
#[cfg_attr(
    not(any(
        all(unix, target_pointer_width = "64"),
        all(windows, target_pointer_width = "64")
    )),
    allow(dead_code)
)]
fn timeval_to_micros(tv_sec: impl Into<i64>, tv_usec: impl Into<i64>) -> u64 {
    // `Into<i64>` acepta los campos de 32 y 64 bits sin casts por plataforma.
    let sec = u64::try_from(tv_sec.into()).unwrap_or(0);
    let usec = u64::try_from(tv_usec.into()).unwrap_or(0);
    sec.saturating_mul(1_000_000).saturating_add(usec)
}

#[cfg(not(any(
    all(unix, target_pointer_width = "64"),
    all(windows, target_pointer_width = "64")
)))]
mod backend {
    use super::*;

    pub struct LiveCapture;

    /// Sin captura no hay nada que interrumpir.
    #[derive(Debug, Clone)]
    pub struct LiveBreaker;

    impl LiveBreaker {
        pub fn interrupt(&self) {}
    }

    impl LiveCapture {
        pub fn breaker(&self) -> LiveBreaker {
            LiveBreaker
        }

        pub fn open(_cfg: LiveCaptureConfig) -> Result<Self, CaptureError> {
            Err(CaptureError::LiveUnavailable(
                "la captura en vivo necesita un sistema de 64 bits (Linux, macOS o Windows)".into(),
            ))
        }

        pub fn kernel_stats(&self) -> Option<(u32, u32)> {
            None
        }
    }

    impl CaptureSource for LiveCapture {
        fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
            Err(CaptureError::LiveUnavailable(
                "plataforma sin soporte de captura en vivo".into(),
            ))
        }
        fn link_type(&self) -> LinkType {
            LinkType::Ethernet
        }
    }

    pub fn list_ifaces() -> Result<Vec<LiveIface>, CaptureError> {
        Err(CaptureError::LiveUnavailable(
            "plataforma sin soporte de captura en vivo".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Backend real: unix LP64 (libpcap) y Windows x64 (Npcap)
// ---------------------------------------------------------------------------

#[cfg(any(
    all(unix, target_pointer_width = "64"),
    all(windows, target_pointer_width = "64")
))]
mod backend {
    use std::ffi::{c_char, c_int, c_void, CStr, CString};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;

    // ---------------------------------------------------- carga dinámica

    /// `dlopen`/`dlsym` sobre libpcap.
    #[cfg(unix)]
    mod dl {
        use std::ffi::{c_char, c_int, c_void, CString};

        const RTLD_NOW: c_int = 0x2;
        const RTLD_LOCAL: c_int = 0x0;

        extern "C" {
            fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
            fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
            fn dlclose(handle: *mut c_void) -> c_int;
        }

        pub const LIB_NAME: &str = "libpcap";
        pub const INSTALL_HINT: &str = "instala la biblioteca de captura (Debian/Ubuntu: `apt install libpcap0.8`; Fedora: `dnf install libpcap`; macOS ya la trae el sistema)";
        #[cfg(target_os = "linux")]
        pub const PERM_HINT: &str = "da el permiso una sola vez con `sudo setcap cap_net_raw,cap_net_admin=eip \"$(command -v socshark)\"` (install.sh ya lo hace) o ejecuta con sudo";
        #[cfg(not(target_os = "linux"))]
        pub const PERM_HINT: &str =
            "ejecuta con sudo (o instala ChmodBPF, el ayudante de Wireshark, para capturar sin sudo)";

        /// Linux: solo *sonames* sin `/` (Debian/Ubuntu `so.0.8`,
        /// Fedora/Arch `so.1`, genérico con `-dev`), que `dlopen` resuelve
        /// con la caché del enlazador y las rutas del sistema, nunca contra
        /// el directorio actual.
        #[cfg(not(target_os = "macos"))]
        pub fn candidates() -> Vec<String> {
            ["libpcap.so.1", "libpcap.so.0.8", "libpcap.so"]
                .map(String::from)
                .to_vec()
        }

        /// macOS: rutas absolutas. Un nombre suelto (`libpcap`) no lleva
        /// `.dylib`, así que nunca resolvía, y `dlopen` lo buscaría también
        /// en el directorio actual (biblioteca plantada). Primero la del
        /// sistema (en la caché compartida de dyld) y después Homebrew
        /// (Apple Silicon e Intel).
        #[cfg(target_os = "macos")]
        pub fn candidates() -> Vec<String> {
            [
                "/usr/lib/libpcap.A.dylib",
                "/usr/lib/libpcap.dylib",
                "/opt/homebrew/opt/libpcap/lib/libpcap.dylib",
                "/usr/local/opt/libpcap/lib/libpcap.dylib",
            ]
            .map(String::from)
            .to_vec()
        }

        pub unsafe fn open(name: &str) -> *mut c_void {
            let c = CString::new(name).expect("nombre de biblioteca sin NUL");
            dlopen(c.as_ptr(), RTLD_NOW | RTLD_LOCAL)
        }

        pub unsafe fn sym(h: *mut c_void, name: *const c_char) -> *mut c_void {
            dlsym(h, name)
        }

        pub unsafe fn close(h: *mut c_void) {
            dlclose(h);
        }
    }

    /// `LoadLibraryExW`/`GetProcAddress` sobre `wpcap.dll` de Npcap.
    #[cfg(windows)]
    mod dl {
        use std::ffi::{c_char, c_void, OsStr};
        use std::os::windows::ffi::OsStrExt;

        /// Dependencias (`Packet.dll`) solo desde la carpeta de la propia DLL.
        const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
        /// Búsqueda restringida a System32: nunca la carpeta de la
        /// aplicación, el directorio actual ni el `PATH` (DLL planting).
        const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

        #[link(name = "kernel32")]
        extern "system" {
            fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
            fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
            fn FreeLibrary(module: *mut c_void) -> i32;
            fn GetSystemDirectoryW(buf: *mut u16, size: u32) -> u32;
        }

        pub const LIB_NAME: &str = "Npcap (wpcap.dll)";
        pub const INSTALL_HINT: &str =
            "instala Npcap desde https://npcap.com y deja marcado «WinPcap API-compatible Mode»";
        pub const PERM_HINT: &str =
            "abre la consola como administrador (Npcap se instaló solo para administradores)";

        /// Carpeta System32 según el propio sistema (`GetSystemDirectoryW`),
        /// no según `%SystemRoot%`, que cualquiera puede cambiar en el
        /// entorno del proceso.
        fn system_dir() -> Option<String> {
            let mut buf = [0u16; 512];
            // SAFETY: búfer propio con su tamaño real; la función escribe
            // como mucho `size` u16 y devuelve la longitud sin el NUL.
            let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
            if n == 0 || n >= buf.len() {
                return None;
            }
            Some(String::from_utf16_lossy(&buf[..n]))
        }

        /// Instalación propia de Npcap (`System32\Npcap`) y, si no, el
        /// `wpcap.dll` de System32 (modo compatible con WinPcap). Ambas
        /// cargas se restringen a carpetas del sistema (ver [`open`]).
        pub fn candidates() -> Vec<String> {
            let mut out = Vec::new();
            if let Some(sys) = system_dir() {
                out.push(format!(r"{sys}\Npcap\wpcap.dll"));
            }
            out.push("wpcap.dll".into());
            out
        }

        /// Con ruta absoluta, las dependencias (`Packet.dll`) se buscan solo
        /// en la carpeta de la DLL y en System32; con nombre suelto, solo
        /// en System32. Nunca la carpeta de la aplicación ni el directorio
        /// actual.
        pub unsafe fn open(name: &str) -> *mut c_void {
            let wide: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();
            let flags = if name.contains('\\') {
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32
            } else {
                LOAD_LIBRARY_SEARCH_SYSTEM32
            };
            LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), flags)
        }

        pub unsafe fn sym(h: *mut c_void, name: *const c_char) -> *mut c_void {
            GetProcAddress(h, name)
        }

        pub unsafe fn close(h: *mut c_void) {
            FreeLibrary(h);
        }
    }

    #[cfg(unix)]
    extern "C" {
        fn poll(fds: *mut PollFd, nfds: NfdsT, timeout: c_int) -> c_int;
    }

    /// `struct pollfd` (idéntica en Linux y macOS).
    #[cfg(unix)]
    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }
    #[cfg(unix)]
    const POLLIN: i16 = 0x1;
    /// Tramo máximo de cada `poll`: cota de lo que tarda en verse una parada.
    #[cfg(unix)]
    const POLL_SLICE_MS: c_int = 100;
    /// `nfds_t`: `unsigned long` en Linux, `unsigned int` en macOS.
    #[cfg(target_os = "macos")]
    type NfdsT = std::ffi::c_uint;
    #[cfg(all(unix, not(target_os = "macos")))]
    type NfdsT = std::ffi::c_ulong;

    /// Biblioteca cargada; al soltarla se hace `dlclose`.
    struct LibPcap {
        handle: *mut c_void,
    }

    // El handle de dlopen es global al proceso y puede consultarse desde
    // cualquier hilo (solo lo usamos para dlsym durante la carga).
    unsafe impl Send for LibPcap {}
    unsafe impl Sync for LibPcap {}

    impl LibPcap {
        /// Carga libpcap y resuelve todos los símbolos usados por el
        /// backend. Si falta alguno, se considera la instalación rota.
        fn load() -> Result<LibPcap, CaptureError> {
            for name in dl::candidates() {
                let h = unsafe { dl::open(&name) };
                if !h.is_null() {
                    return Ok(LibPcap { handle: h });
                }
            }
            Err(CaptureError::LiveUnavailable(format!(
                "{} no encontrada ({})",
                dl::LIB_NAME,
                dl::INSTALL_HINT
            )))
        }

        fn sym(&self, name: &str) -> Result<*mut c_void, CaptureError> {
            let cname = CString::new(name).expect("nombre de símbolo sin NUL");
            let p = unsafe { dl::sym(self.handle, cname.as_ptr()) };
            if p.is_null() {
                return Err(CaptureError::LiveUnavailable(format!(
                    "{} incompleta: falta el símbolo {name}",
                    dl::LIB_NAME
                )));
            }
            Ok(p)
        }
    }

    impl Drop for LibPcap {
        fn drop(&mut self) {
            unsafe { dl::close(self.handle) };
        }
    }

    // ------------------------------------------------ tipos y constantes

    type PcapT = c_void;

    #[repr(C)]
    struct BpfInsn {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct BpfProgram {
        bf_len: u32,
        bf_insns: *mut BpfInsn,
    }

    /// `timeval` según la plataforma: en Linux LP64 ambos campos son i64;
    /// en macOS `tv_usec` es de 32 bits; en Windows (LLP64) `long` es de 32
    /// bits y ambos lo son. Equivocarse aquí desplaza `caplen`/`len`.
    #[cfg(target_os = "macos")]
    #[repr(C)]
    struct PcapTimeval {
        tv_sec: i64,
        tv_usec: i32,
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    #[repr(C)]
    struct PcapTimeval {
        tv_sec: i64,
        tv_usec: i64,
    }
    #[cfg(windows)]
    #[repr(C)]
    struct PcapTimeval {
        tv_sec: i32,
        tv_usec: i32,
    }

    #[repr(C)]
    struct PcapPkthdr {
        ts: PcapTimeval,
        caplen: u32,
        len: u32,
    }

    /// En Windows `pcap_stat` lleva tres contadores más (`ps_capt`,
    /// `ps_sent`, `ps_netdrop`): la estructura debe tener su tamaño real
    /// aunque no se lean, o `pcap_stats` escribiría fuera de ella.
    #[repr(C)]
    #[derive(Default)]
    struct PcapStat {
        ps_recv: u32,
        ps_drop: u32,
        ps_ifdrop: u32,
        #[cfg(windows)]
        _win_extra: [u32; 3],
    }

    #[repr(C)]
    struct PcapIf {
        next: *mut PcapIf,
        name: *mut c_char,
        description: *mut c_char,
        addresses: *mut c_void,
        flags: u32,
    }

    /// `struct pcap_addr`.
    #[repr(C)]
    struct PcapAddr {
        next: *mut PcapAddr,
        addr: *mut c_void,
        netmask: *mut c_void,
        broadaddr: *mut c_void,
        dstaddr: *mut c_void,
    }

    const PCAP_IF_LOOPBACK: u32 = 0x1;
    const PCAP_IF_UP: u32 = 0x2;
    const PCAP_IF_RUNNING: u32 = 0x4;
    const PCAP_IF_WIRELESS: u32 = 0x8;
    const PCAP_IF_CONNECTION_STATUS: u32 = 0x30;
    const PCAP_IF_CONNECTION_STATUS_CONNECTED: u32 = 0x10;
    const PCAP_IF_CONNECTION_STATUS_DISCONNECTED: u32 = 0x20;

    /// `AF_INET6` cambia de número según el sistema.
    const AF_INET: u16 = 2;
    #[cfg(target_os = "linux")]
    const AF_INET6: Option<u16> = Some(10);
    #[cfg(target_os = "macos")]
    const AF_INET6: Option<u16> = Some(30);
    #[cfg(target_os = "freebsd")]
    const AF_INET6: Option<u16> = Some(28);
    #[cfg(windows)]
    const AF_INET6: Option<u16> = Some(23);
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        windows
    )))]
    const AF_INET6: Option<u16> = None;

    /// IP de un `struct sockaddr` (solo IPv4/IPv6; el resto, `None`).
    ///
    /// # Safety
    /// `sa` es nulo o apunta a un sockaddr válido de la familia que declara.
    unsafe fn sockaddr_ip(sa: *const u8) -> Option<IpAddr> {
        if sa.is_null() {
            return None;
        }
        // BSD/macOS: `sa_len: u8, sa_family: u8`; el resto: `sa_family: u16`.
        let family = if cfg!(any(target_os = "macos", target_os = "freebsd")) {
            u16::from(*sa.add(1))
        } else {
            u16::from_ne_bytes([*sa, *sa.add(1)])
        };
        // sockaddr_in: familia(2) puerto(2) dirección(4) → desplazamiento 4.
        // sockaddr_in6: familia(2) puerto(2) flowinfo(4) dirección(16) → 8.
        if family == AF_INET {
            let b: [u8; 4] = std::ptr::read_unaligned(sa.add(4) as *const [u8; 4]);
            Some(IpAddr::from(b))
        } else if Some(family) == AF_INET6 {
            let b: [u8; 16] = std::ptr::read_unaligned(sa.add(8) as *const [u8; 16]);
            Some(IpAddr::from(b))
        } else {
            None
        }
    }

    /// `PCAP_NETMASK_UNKNOWN`: vale para filtros que no usan direcciones.
    const PCAP_NETMASK_UNKNOWN: u32 = 0xFFFF_FFFF;

    const PCAP_ERROR: c_int = -1;
    const PCAP_ERROR_BREAK: c_int = -2;
    const PCAP_ERROR_NOT_ACTIVATED: c_int = -4;
    const PCAP_ERROR_NO_SUCH_DEVICE: c_int = -7;
    const PCAP_ERROR_PERM_DENIED: c_int = -8;

    const ERRBUF_LEN: usize = 256;

    /// Punteros tipados a las funciones de libpcap. Las firmas replican la
    /// ABI pública de la API estable (`pcap/pcap.h`) en unix LP64.
    struct Syms {
        create: unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut PcapT,
        set_snaplen: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
        set_promisc: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
        set_timeout: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
        #[cfg(unix)]
        set_immediate_mode: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
        activate: unsafe extern "C" fn(*mut PcapT) -> c_int,
        compile:
            unsafe extern "C" fn(*mut PcapT, *mut BpfProgram, *const c_char, c_int, u32) -> c_int,
        setfilter: unsafe extern "C" fn(*mut PcapT, *const BpfProgram) -> c_int,
        freecode: unsafe extern "C" fn(*mut BpfProgram),
        datalink: unsafe extern "C" fn(*mut PcapT) -> c_int,
        next_ex: unsafe extern "C" fn(*mut PcapT, *mut *const PcapPkthdr, *mut *const u8) -> c_int,
        geterr: unsafe extern "C" fn(*mut PcapT) -> *const c_char,
        close: unsafe extern "C" fn(*mut PcapT),
        breakloop: unsafe extern "C" fn(*mut PcapT),
        stats: unsafe extern "C" fn(*mut PcapT, *mut PcapStat) -> c_int,
        findalldevs: unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int,
        freealldevs: unsafe extern "C" fn(*mut PcapIf),
        // Solo unix: Npcap no exporta pcap_get_selectable_fd.
        #[cfg(unix)]
        setnonblock: unsafe extern "C" fn(*mut PcapT, c_int, *mut c_char) -> c_int,
        #[cfg(unix)]
        get_selectable_fd: unsafe extern "C" fn(*mut PcapT) -> c_int,
    }

    impl Syms {
        fn load(lib: &LibPcap) -> Result<Syms, CaptureError> {
            // Convierte la dirección de dlsym en el puntero de función
            // esperado. SAFETY (llamador): `T` debe coincidir con la firma
            // real del símbolo según la ABI pública de libpcap; las firmas
            // de `Syms` son la única fuente de verdad y están auditadas
            // contra `pcap/pcap.h` (API estable, sin variantes de tamaño
            // dependientes de la versión). `transmute_copy(&p)` reinterpreta
            // el *valor* de la dirección como `T`; leer *a través* de `p`
            // (`ptr::read(p)`) copiaría los primeros bytes del código
            // máquina de la función y el primer call saltaría a basura.
            unsafe fn sym_as<T>(p: *mut c_void) -> T {
                debug_assert!(!p.is_null());
                assert_eq!(
                    std::mem::size_of::<T>(),
                    std::mem::size_of::<*mut c_void>(),
                    "sym_as: T debe ser un puntero a función"
                );
                std::mem::transmute_copy(&p)
            }
            let s = |name: &str| -> Result<*mut c_void, CaptureError> { lib.sym(name) };
            Ok(Syms {
                create: unsafe { sym_as(s("pcap_create")?) },
                set_snaplen: unsafe { sym_as(s("pcap_set_snaplen")?) },
                set_promisc: unsafe { sym_as(s("pcap_set_promisc")?) },
                set_timeout: unsafe { sym_as(s("pcap_set_timeout")?) },
                #[cfg(unix)]
                set_immediate_mode: unsafe { sym_as(s("pcap_set_immediate_mode")?) },
                activate: unsafe { sym_as(s("pcap_activate")?) },
                compile: unsafe { sym_as(s("pcap_compile")?) },
                setfilter: unsafe { sym_as(s("pcap_setfilter")?) },
                freecode: unsafe { sym_as(s("pcap_freecode")?) },
                datalink: unsafe { sym_as(s("pcap_datalink")?) },
                next_ex: unsafe { sym_as(s("pcap_next_ex")?) },
                geterr: unsafe { sym_as(s("pcap_geterr")?) },
                close: unsafe { sym_as(s("pcap_close")?) },
                breakloop: unsafe { sym_as(s("pcap_breakloop")?) },
                stats: unsafe { sym_as(s("pcap_stats")?) },
                findalldevs: unsafe { sym_as(s("pcap_findalldevs")?) },
                freealldevs: unsafe { sym_as(s("pcap_freealldevs")?) },
                #[cfg(unix)]
                setnonblock: unsafe { sym_as(s("pcap_setnonblock")?) },
                #[cfg(unix)]
                get_selectable_fd: unsafe { sym_as(s("pcap_get_selectable_fd")?) },
            })
        }
    }

    // ------------------------------------------------------ LiveCapture

    /// Captura en vivo sobre una interfaz, vía libpcap cargada con dlopen.
    pub struct LiveCapture {
        syms: Syms,
        handle: *mut PcapT,
        link: LinkType,
        /// Programa BPF compilado; se libera en Drop tras cerrar el handle.
        prog: Option<BpfProgram>,
        /// Descriptor para `poll` en modo no bloqueante; -1 si la
        /// plataforma no lo ofrece (se delega la espera en libpcap).
        #[cfg(unix)]
        fd: c_int,
        /// Espera máxima por paquete antes de devolver un tick.
        #[cfg(unix)]
        timeout_ms: c_int,
        /// Estado compartido con los [`LiveBreaker`] de otros hilos.
        brk: Arc<BreakState>,
        /// Biblioteca subyacente; DEBE ser el último campo: al soltar la
        /// struct se hace `dlclose`, que debe ocurrir después de
        /// `pcap_close` (el orden de drop de campos es el de declaración).
        lib: LibPcap,
    }

    unsafe impl Send for LiveCapture {}

    /// Interrumpe desde otro hilo una lectura en curso (`pcap_breakloop`),
    /// para que "Detener" nunca espere al siguiente paquete. Comparte con la
    /// captura un cerrojo que impide llamarlo cuando el handle ya se cerró.
    #[derive(Clone)]
    pub struct LiveBreaker {
        inner: Arc<BreakState>,
    }

    impl std::fmt::Debug for LiveBreaker {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("LiveBreaker").finish_non_exhaustive()
        }
    }

    struct BreakState {
        /// Dirección del handle abierto; `None` en cuanto se cierra.
        handle: Mutex<Option<usize>>,
        breakloop: unsafe extern "C" fn(*mut PcapT),
        /// Petición de parada pendiente. `pcap_breakloop` no despierta el
        /// `poll` propio de unix, así que la espera se hace en tramos cortos
        /// que consultan esta bandera (se consume al devolver el tick).
        stop: AtomicBool,
    }

    impl LiveBreaker {
        pub fn interrupt(&self) {
            self.inner.stop.store(true, Ordering::SeqCst);
            if let Ok(h) = self.inner.handle.lock() {
                if let Some(addr) = *h {
                    // SAFETY: el handle sigue abierto mientras se tenga el
                    // cerrojo (Drop lo marca cerrado y cierra con él tomado),
                    // y pcap_breakloop está pensada para otro hilo.
                    unsafe { (self.inner.breakloop)(addr as *mut PcapT) };
                }
            }
        }
    }

    impl std::fmt::Debug for LiveCapture {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("LiveCapture").finish_non_exhaustive()
        }
    }

    impl LiveCapture {
        /// Abre y activa la interfaz según la configuración.
        ///
        /// Errores típicos ya traducidos: interfaz inexistente, privilegios
        /// de captura ausentes y libpcap no instalada.
        pub fn open(cfg: LiveCaptureConfig) -> Result<Self, CaptureError> {
            let lib = LibPcap::load()?;
            let syms = Syms::load(&lib)?;

            let mut errbuf = [0 as c_char; ERRBUF_LEN];
            let dev = CString::new(cfg.iface.as_str()).map_err(|_| {
                CaptureError::Live(format!("nombre de interfaz inválido: {:?}", cfg.iface))
            })?;

            let handle = unsafe { (syms.create)(dev.as_ptr(), errbuf.as_mut_ptr()) };
            if handle.is_null() {
                let msg = err_str(&errbuf);
                return Err(CaptureError::Live(format!(
                    "no se pudo abrir {}: {msg}",
                    cfg.iface
                )));
            }

            // Configuración pre-activación: cada paso devuelve 0 en éxito.
            let steps = [
                ("snaplen", unsafe {
                    (syms.set_snaplen)(handle, cfg.snaplen)
                }),
                ("promiscuo", unsafe {
                    (syms.set_promisc)(handle, cfg.promisc as c_int)
                }),
                ("timeout", unsafe {
                    (syms.set_timeout)(handle, cfg.timeout_ms)
                }),
                #[cfg(unix)]
                ("modo inmediato", unsafe {
                    (syms.set_immediate_mode)(handle, 1)
                }),
            ];
            for (name, rc) in steps {
                if rc != 0 {
                    unsafe { (syms.close)(handle) };
                    return Err(CaptureError::Live(format!(
                        "no se pudo configurar {name} en {}: {rc}",
                        cfg.iface
                    )));
                }
            }

            // rc > 0 son avisos (PCAP_WARNING*, p. ej. promiscuo no
            // soportado): la captura queda activa y se continúa.
            let rc = unsafe { (syms.activate)(handle) };
            if rc < 0 {
                let detail: String = if rc == PCAP_ERROR_PERM_DENIED {
                    format!("sin privilegios de captura: {}", dl::PERM_HINT)
                } else if rc == PCAP_ERROR_NO_SUCH_DEVICE {
                    "la interfaz no existe (¿nombre correcto? prueba `socshark daemon --list`)"
                        .to_string()
                } else if rc == PCAP_ERROR_NOT_ACTIVATED {
                    "la interfaz no pudo activarse".to_string()
                } else {
                    // Tras pcap_create el error vive en el handle, no en errbuf.
                    unsafe { CStr::from_ptr((syms.geterr)(handle)) }
                        .to_string_lossy()
                        .into_owned()
                };
                unsafe { (syms.close)(handle) };
                return Err(CaptureError::Live(format!(
                    "activación de {} falló: {detail}",
                    cfg.iface
                )));
            }

            // Pushdown BPF: compilar + filtrar en kernel. El programa se
            // guarda para liberarlo en Drop (libpcap copia su contenido en
            // setfilter, pero la memoria del programa sigue siendo nuestra).
            let prog = if let Some(expr) = cfg.bpf.as_deref() {
                let expr_c = CString::new(expr)
                    .map_err(|_| CaptureError::Live("filtro BPF inválido (contiene NUL)".into()))?;
                let mut prog = BpfProgram {
                    bf_len: 0,
                    bf_insns: std::ptr::null_mut(),
                };
                let rc = unsafe {
                    (syms.compile)(handle, &mut prog, expr_c.as_ptr(), 1, PCAP_NETMASK_UNKNOWN)
                };
                if rc != 0 {
                    let msg = unsafe { CStr::from_ptr((syms.geterr)(handle)) }
                        .to_string_lossy()
                        .into_owned();
                    unsafe { (syms.close)(handle) };
                    return Err(CaptureError::Live(format!(
                        "filtro BPF inválido `{expr}`: {msg}"
                    )));
                }
                let rc = unsafe { (syms.setfilter)(handle, &prog) };
                if rc != 0 {
                    let msg = unsafe { CStr::from_ptr((syms.geterr)(handle)) }
                        .to_string_lossy()
                        .into_owned();
                    unsafe { (syms.freecode)(&mut prog) };
                    unsafe { (syms.close)(handle) };
                    return Err(CaptureError::Live(format!(
                        "no se pudo instalar el filtro BPF: {msg}"
                    )));
                }
                Some(prog)
            } else {
                None
            };

            // Modo no bloqueante + `poll` propio: en Linux el timeout de
            // lectura de libpcap no garantiza que `pcap_next_ex` vuelva sin
            // tráfico (repite el poll por dentro), y el daemon necesita ese
            // tick para expirar flujos y atender `--duration` y Ctrl-C.
            #[cfg(unix)]
            let fd = {
                let fd = unsafe { (syms.get_selectable_fd)(handle) };
                if fd >= 0 && unsafe { (syms.setnonblock)(handle, 1, errbuf.as_mut_ptr()) } != 0 {
                    -1
                } else {
                    fd
                }
            };

            let dlt = unsafe { (syms.datalink)(handle) };
            let link = LinkType::from_pcap_code(dlt as u32);

            let brk = Arc::new(BreakState {
                handle: Mutex::new(Some(handle as usize)),
                breakloop: syms.breakloop,
                stop: AtomicBool::new(false),
            });
            Ok(Self {
                syms,
                handle,
                link,
                prog,
                brk,
                #[cfg(unix)]
                fd,
                #[cfg(unix)]
                timeout_ms: cfg.timeout_ms,
                lib,
            })
        }

        /// Interruptor para despertar la lectura desde otro hilo.
        pub fn breaker(&self) -> LiveBreaker {
            LiveBreaker {
                inner: Arc::clone(&self.brk),
            }
        }

        /// Contadores del kernel desde la última consulta: `(recibidos,
        /// descartados por el búfer)`. `None` si el backend no los da.
        pub fn kernel_stats(&self) -> Option<(u32, u32)> {
            let mut st = PcapStat::default();
            let rc = unsafe { (self.syms.stats)(self.handle, &mut st) };
            if rc == 0 {
                Some((st.ps_recv, st.ps_drop))
            } else {
                None
            }
        }

        fn last_err(&self) -> String {
            unsafe { CStr::from_ptr((self.syms.geterr)(self.handle)) }
                .to_string_lossy()
                .into_owned()
        }
    }

    impl CaptureSource for LiveCapture {
        /// Contrato en vivo: `Ok(None)` es un *tick* (venció el timeout de
        /// lectura sin tráfico o llegó una señal), no un fin de captura;
        /// `Err` sí es fatal.
        fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
            let mut hdr: *const PcapPkthdr = std::ptr::null();
            let mut data: *const u8 = std::ptr::null();
            #[allow(unused_mut)] // solo unix reintenta tras el poll
            let mut rc = unsafe { (self.syms.next_ex)(self.handle, &mut hdr, &mut data) };
            #[cfg(unix)]
            if rc == 0 && self.fd >= 0 {
                // Nada disponible: esperar al descriptor como mucho un
                // timeout, en tramos de POLL_SLICE_MS para atender pronto
                // una parada (`LiveBreaker::interrupt`). Vencido, parado o
                // interrumpido por una señal (EINTR, p. ej. Ctrl-C), es un
                // tick sin datos.
                // Timeout negativo = espera sin límite (como `poll`).
                let infinite = self.timeout_ms < 0;
                let mut remaining = self.timeout_ms.max(0);
                loop {
                    if self.brk.stop.swap(false, Ordering::SeqCst) {
                        return Ok(None);
                    }
                    let slice = if infinite {
                        POLL_SLICE_MS
                    } else {
                        remaining.min(POLL_SLICE_MS)
                    };
                    let mut pfd = PollFd {
                        fd: self.fd,
                        events: POLLIN,
                        revents: 0,
                    };
                    let n = unsafe { poll(&mut pfd, 1, slice) };
                    if n > 0 {
                        break;
                    }
                    remaining -= slice;
                    if n < 0 || (!infinite && remaining <= 0) {
                        return Ok(None);
                    }
                }
                rc = unsafe { (self.syms.next_ex)(self.handle, &mut hdr, &mut data) };
            }
            match rc {
                // Paquete disponible.
                1 => {
                    // SAFETY: next_ex garantiza punteros válidos cuando
                    // devuelve 1; copiamos inmediatamente a memoria propia
                    // (el búfer interno de libpcap se reutiliza).
                    let h = unsafe { &*hdr };
                    let bytes =
                        unsafe { std::slice::from_raw_parts(data, h.caplen as usize) }.to_vec();
                    let ts_micros = super::timeval_to_micros(h.ts.tv_sec, h.ts.tv_usec);
                    Ok(Some(RawPacket {
                        ts_micros,
                        orig_len: h.len,
                        data: bytes,
                    }))
                }
                // Timeout de lectura: tick sin datos.
                0 => Ok(None),
                // EOF (solo fuentes de archivo) o petición de parada.
                PCAP_ERROR_BREAK => Ok(None),
                PCAP_ERROR => Err(CaptureError::Live(self.last_err())),
                other => Err(CaptureError::Live(format!(
                    "error de lectura en vivo ({other}): {}",
                    self.last_err()
                ))),
            }
        }

        fn link_type(&self) -> LinkType {
            self.link
        }
    }

    impl Drop for LiveCapture {
        fn drop(&mut self) {
            // Se cierra con el cerrojo del interruptor tomado: nadie puede
            // llamar a pcap_breakloop sobre un handle ya liberado.
            let mut open = self.brk.handle.lock().unwrap_or_else(|e| e.into_inner());
            *open = None;
            if let Some(mut prog) = self.prog.take() {
                unsafe { (self.syms.freecode)(&mut prog) };
            }
            if !self.handle.is_null() {
                // Referencia explícita a `lib`: documenta que la biblioteca
                // sigue mapeada durante pcap_close (el dlclose llega después,
                // al soltar el último campo).
                let _lib = &self.lib;
                unsafe { (self.syms.close)(self.handle) };
            }
            drop(open);
        }
    }

    /// Enumera las interfaces capturables que ve libpcap.
    pub fn list_ifaces() -> Result<Vec<LiveIface>, CaptureError> {
        let lib = LibPcap::load()?;
        let syms = Syms::load(&lib)?;
        let mut errbuf = [0 as c_char; ERRBUF_LEN];
        let mut devs: *mut PcapIf = std::ptr::null_mut();
        let rc = unsafe { (syms.findalldevs)(&mut devs, errbuf.as_mut_ptr()) };
        if rc != 0 {
            return Err(CaptureError::Live(format!(
                "no se pudieron enumerar interfaces: {}",
                err_str(&errbuf)
            )));
        }

        let mut out = Vec::new();
        let mut cur = devs;
        while !cur.is_null() {
            // SAFETY: la lista enlazada devuelta por findalldevs es válida
            // hasta freealldevs.
            let d = unsafe { &*cur };
            let name = if d.name.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(d.name) }
                    .to_string_lossy()
                    .into_owned()
            };
            let description = if d.description.is_null() {
                None
            } else {
                Some(
                    unsafe { CStr::from_ptr(d.description) }
                        .to_string_lossy()
                        .into_owned(),
                )
            };
            let mut addresses = Vec::new();
            let mut a = d.addresses as *const PcapAddr;
            while !a.is_null() {
                // SAFETY: lista enlazada de pcap_addr, válida hasta
                // freealldevs; `addr` apunta a un sockaddr de su familia.
                let pa = unsafe { &*a };
                if let Some(ip) = unsafe { sockaddr_ip(pa.addr as *const u8) } {
                    addresses.push(ip);
                }
                a = pa.next;
            }
            // IPv4 primero: es la que la gente reconoce.
            addresses.sort_by_key(|ip| ip.is_ipv6());
            let f = d.flags;
            out.push(LiveIface {
                name,
                description,
                addresses,
                loopback: f & PCAP_IF_LOOPBACK != 0,
                up: f & PCAP_IF_UP != 0 && f & PCAP_IF_RUNNING != 0,
                wireless: f & PCAP_IF_WIRELESS != 0,
                connected: match f & PCAP_IF_CONNECTION_STATUS {
                    PCAP_IF_CONNECTION_STATUS_CONNECTED => Some(true),
                    PCAP_IF_CONNECTION_STATUS_DISCONNECTED => Some(false),
                    _ => None,
                },
            });
            cur = d.next;
        }
        unsafe { (syms.freealldevs)(devs) };
        Ok(out)
    }

    fn err_str(errbuf: &[c_char; ERRBUF_LEN]) -> String {
        unsafe { CStr::from_ptr(errbuf.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    }
}

// Cada plataforma compila exactamente un `backend` (real o stub).
pub use backend::{list_ifaces, LiveBreaker, LiveCapture};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeval_negativo_o_enorme_no_desborda() {
        // Regresión: `tv_sec as u64 * 1_000_000` hacía panic en debug con
        // tv_sec negativo (i32 en Windows).
        assert_eq!(timeval_to_micros(-1i32, 5i32), 5);
        assert_eq!(timeval_to_micros(1i64, -3i64), 1_000_000);
        assert_eq!(timeval_to_micros(i64::MAX, i64::MAX), u64::MAX);
        assert_eq!(
            timeval_to_micros(1_700_000_000i64, 42i64),
            1_700_000_000_000_042
        );
    }

    /// En una máquina sin libpcap la apertura debe fallar limpio y en
    /// español; con libpcap instalada, fallar por la interfaz o por
    /// privilegios — nunca con un panic.
    #[test]
    fn abrir_interfaz_inexistente_devuelve_error_limpio() {
        let cfg = LiveCaptureConfig::new("socshark-no-existe-99");
        match LiveCapture::open(cfg) {
            Err(e) => {
                let msg = e.to_string();
                assert!(!msg.is_empty());
                eprintln!("open() → {msg}");
            }
            Ok(_) => {
                // Entorno con libpcap e interfaz fantasma: pcap_create
                // debería haber fallado; si no, no rompemos el test pero
                // cerramos soltando el objeto.
            }
        }
    }

    /// Sin tráfico, `next_packet` debe devolver un tick (`Ok(None)`) en
    /// torno al timeout de lectura: el daemon depende de él para expirar
    /// flujos y atender `--duration` y Ctrl-C. Solo corre donde se puede
    /// capturar en `lo` (root/CAP_NET_RAW); en CI sin privilegios se omite.
    #[test]
    fn next_packet_vuelve_dentro_del_timeout_sin_trafico() {
        let iface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        // Filtro válido pero sin tráfico en loopback (9/udp = discard). Uno
        // imposible no sirve: libpcap lo detecta y ni siquiera espera.
        let cfg = LiveCaptureConfig {
            timeout_ms: 200,
            ..LiveCaptureConfig::new(iface).with_bpf(Some("udp port 9".into()))
        };
        let mut cap = match LiveCapture::open(cfg) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("sin captura en vivo en este entorno ({e}): se omite");
                return;
            }
        };
        for _ in 0..3 {
            let t = std::time::Instant::now();
            match cap.next_packet() {
                Ok(None) => {}
                Ok(Some(_)) => panic!("tráfico inesperado en 9/udp de loopback"),
                Err(e) => panic!("error de lectura: {e}"),
            }
            assert!(
                t.elapsed() < std::time::Duration::from_secs(2),
                "next_packet tardó {:?} sin tráfico",
                t.elapsed()
            );
        }
    }

    /// El interruptor es seguro antes y después de cerrar la captura.
    #[test]
    fn interrumpir_es_seguro_con_handle_abierto_o_cerrado() {
        let iface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let Ok(mut cap) =
            LiveCapture::open(LiveCaptureConfig::new(iface).with_bpf(Some("udp port 9".into())))
        else {
            eprintln!("sin captura en vivo en este entorno: se omite");
            return;
        };
        let brk = cap.breaker();
        brk.interrupt();
        // Tras interrumpir, la siguiente lectura es un tick, no un error.
        assert!(matches!(cap.next_packet(), Ok(None)));
        drop(cap);
        brk.interrupt(); // handle cerrado: no hace nada
    }

    #[test]
    fn listar_interfaces_no_panics() {
        // Con o sin libpcap: o lista, o error legible. Nunca crash.
        match list_ifaces() {
            Ok(ifaces) => {
                assert!(
                    !ifaces.is_empty(),
                    "una máquina con libpcap tiene al menos `lo`"
                );
                for i in &ifaces {
                    assert!(!i.name.is_empty());
                }
                // La de loopback se reconoce por sus banderas y su 127.0.0.1:
                // comprueba también el layout de pcap_addr/sockaddr.
                #[cfg(unix)]
                if let Some(lo) = ifaces.iter().find(|i| i.name == "lo" || i.name == "lo0") {
                    assert!(lo.loopback, "{lo:?}");
                    assert!(
                        lo.addresses.contains(&IpAddr::from([127, 0, 0, 1])),
                        "{lo:?}"
                    );
                    assert!(!lo.wireless);
                }
            }
            Err(e) => eprintln!("list_ifaces() → {e}"),
        }
    }
}
