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
//!    e *immediate mode* (los paquetes se entregan sin agrupar; imprescindible
//!    para un SOC que quiere latencia mínima en las alertas).
//! 3. *Pushdown* BPF (ADR-004): el filtro DSL↔BPF se compila con
//!    `pcap_compile` y baja al kernel con `pcap_setfilter`, de modo que el
//!    tráfico irrelevante nunca llega al userspace.
//! 4. `pcap_activate` → captura; `pcap_next_ex` en bucle.
//!
//! Modelo de hilos: el handle de libpcap no es thread-safe, así que
//! `LiveCapture` se declara `Send` (se puede mover a otro hilo) pero no
//! `Sync` (no se comparte). El daemon lo usa desde un único hilo de lectura.
//!
//! Restricción de plataforma: el bloque FFI asume LP64 unix (Linux/macOS de
//! 64 bits). En otras plataformas se compila un stub que devuelve
//! [`CaptureError::LiveUnavailable`].

use crate::{CaptureError, CaptureSource};
use socshark_core::{LinkType, RawPacket};

/// Listado de interfaces capturables (`pcap_findalldevs`).
#[derive(Debug, Clone)]
pub struct LiveIface {
    pub name: String,
    pub description: Option<String>,
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

#[cfg(not(all(unix, target_pointer_width = "64")))]
mod backend {
    use super::*;

    pub struct LiveCapture;

    impl LiveCapture {
        pub fn open(_cfg: LiveCaptureConfig) -> Result<Self, CaptureError> {
            Err(CaptureError::LiveUnavailable(
                "la captura en vivo solo está soportada en unix de 64 bits".into(),
            ))
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

#[cfg(not(all(unix, target_pointer_width = "64")))]
pub use backend::{list_ifaces, LiveCapture};

// ---------------------------------------------------------------------------
// Backend real: unix LP64
// ---------------------------------------------------------------------------

#[cfg(all(unix, target_pointer_width = "64"))]
mod backend {
    use std::ffi::{c_char, c_int, c_void, CStr, CString};

    use super::*;

    // ---------------------------------------------------- dlopen / dlsym

    const RTLD_NOW: c_int = 0x2;
    const RTLD_LOCAL: c_int = 0x0;

    extern "C" {
        fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn dlclose(handle: *mut c_void) -> c_int;
    }

    /// Nombres de soname probados en orden: Debian/Ubuntu (`so.0.8`),
    /// Fedora/Arch (`so.1`), genérico con `-dev` instalado y macOS
    /// (`dlopen("libpcap")` resuelve `libpcap.dylib` en las rutas del
    /// sistema).
    const LIBPCAP_CANDIDATES: [&str; 4] =
        ["libpcap.so.0.8", "libpcap.so.1", "libpcap.so", "libpcap"];

    const INSTALL_HINT: &str = "instala la biblioteca de captura (Debian/Ubuntu: `apt install libpcap0.8`; Fedora: `dnf install libpcap`; macOS ya la trae el sistema)";

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
            for name in LIBPCAP_CANDIDATES {
                let cname = CString::new(name).expect("soname sin NUL");
                let h = unsafe { dlopen(cname.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
                if !h.is_null() {
                    return Ok(LibPcap { handle: h });
                }
            }
            Err(CaptureError::LiveUnavailable(format!(
                "libpcap no encontrada ({INSTALL_HINT})"
            )))
        }

        fn sym(&self, name: &str) -> Result<*mut c_void, CaptureError> {
            let cname = CString::new(name).expect("nombre de símbolo sin NUL");
            let p = unsafe { dlsym(self.handle, cname.as_ptr()) };
            if p.is_null() {
                return Err(CaptureError::LiveUnavailable(format!(
                    "libpcap incompleta: falta el símbolo {name}"
                )));
            }
            Ok(p)
        }
    }

    impl Drop for LibPcap {
        fn drop(&mut self) {
            unsafe { dlclose(self.handle) };
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
    /// en macOS `tv_usec` es de 32 bits (el layout cambia, y equivocarse
    /// aquí desplaza `caplen`/`len`).
    #[cfg(target_os = "macos")]
    #[repr(C)]
    struct PcapTimeval {
        tv_sec: i64,
        tv_usec: i32,
    }
    #[cfg(not(target_os = "macos"))]
    #[repr(C)]
    struct PcapTimeval {
        tv_sec: i64,
        tv_usec: i64,
    }

    #[repr(C)]
    struct PcapPkthdr {
        ts: PcapTimeval,
        caplen: u32,
        len: u32,
    }

    #[repr(C)]
    struct PcapStat {
        ps_recv: u32,
        ps_drop: u32,
        ps_ifdrop: u32,
    }

    #[repr(C)]
    struct PcapIf {
        next: *mut PcapIf,
        name: *mut c_char,
        description: *mut c_char,
        addresses: *mut c_void,
        flags: u32,
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
        stats: unsafe extern "C" fn(*mut PcapT, *mut PcapStat) -> c_int,
        findalldevs: unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int,
        freealldevs: unsafe extern "C" fn(*mut PcapIf),
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
                set_immediate_mode: unsafe { sym_as(s("pcap_set_immediate_mode")?) },
                activate: unsafe { sym_as(s("pcap_activate")?) },
                compile: unsafe { sym_as(s("pcap_compile")?) },
                setfilter: unsafe { sym_as(s("pcap_setfilter")?) },
                freecode: unsafe { sym_as(s("pcap_freecode")?) },
                datalink: unsafe { sym_as(s("pcap_datalink")?) },
                next_ex: unsafe { sym_as(s("pcap_next_ex")?) },
                geterr: unsafe { sym_as(s("pcap_geterr")?) },
                close: unsafe { sym_as(s("pcap_close")?) },
                stats: unsafe { sym_as(s("pcap_stats")?) },
                findalldevs: unsafe { sym_as(s("pcap_findalldevs")?) },
                freealldevs: unsafe { sym_as(s("pcap_freealldevs")?) },
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
        /// Biblioteca subyacente; DEBE ser el último campo: al soltar la
        /// struct se hace `dlclose`, que debe ocurrir después de
        /// `pcap_close` (el orden de drop de campos es el de declaración).
        lib: LibPcap,
    }

    unsafe impl Send for LiveCapture {}

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
            let steps: [(&str, c_int); 4] = [
                ("snaplen", unsafe {
                    (syms.set_snaplen)(handle, cfg.snaplen)
                }),
                ("promiscuo", unsafe {
                    (syms.set_promisc)(handle, cfg.promisc as c_int)
                }),
                ("timeout", unsafe {
                    (syms.set_timeout)(handle, cfg.timeout_ms)
                }),
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
                    "sin privilegios de captura: ejecuta como root o concede CAP_NET_RAW (setcap cap_net_raw+ep)".to_string()
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

            let dlt = unsafe { (syms.datalink)(handle) };
            let link = LinkType::from_pcap_code(dlt as u32);

            Ok(Self {
                syms,
                handle,
                link,
                prog,
                lib,
            })
        }

        /// Contadores del kernel desde la última consulta: `(recibidos,
        /// descartados por el búfer)`. `None` si el backend no los da.
        pub fn kernel_stats(&self) -> Option<(u32, u32)> {
            let mut st = PcapStat {
                ps_recv: 0,
                ps_drop: 0,
                ps_ifdrop: 0,
            };
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
        /// lectura sin tráfico), no un fin de captura; `Err` sí es fatal.
        fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
            let mut hdr: *const PcapPkthdr = std::ptr::null();
            let mut data: *const u8 = std::ptr::null();
            let rc = unsafe { (self.syms.next_ex)(self.handle, &mut hdr, &mut data) };
            match rc {
                // Paquete disponible.
                1 => {
                    // SAFETY: next_ex garantiza punteros válidos cuando
                    // devuelve 1; copiamos inmediatamente a memoria propia
                    // (el búfer interno de libpcap se reutiliza).
                    let h = unsafe { &*hdr };
                    let bytes =
                        unsafe { std::slice::from_raw_parts(data, h.caplen as usize) }.to_vec();
                    let ts_micros = h.ts.tv_sec as u64 * 1_000_000 + h.ts.tv_usec as u64;
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
            out.push(LiveIface { name, description });
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

#[cfg(all(unix, target_pointer_width = "64"))]
pub use backend::{list_ifaces, LiveCapture};

#[cfg(not(all(unix, target_pointer_width = "64")))]
pub use backend::{list_ifaces, LiveCapture};

#[cfg(test)]
mod tests {
    use super::*;

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
            }
            Err(e) => eprintln!("list_ifaces() → {e}"),
        }
    }
}
