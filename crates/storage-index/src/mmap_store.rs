//! Store mmap (fase 2): diseño y placeholder documentado.
//!
//! El objetivo del diseño (ver `docs/02-arquitectura.md` § Almacenamiento):
//!
//! 1. `PcapFileSource` actualmente recibe un `&[u8]` que el daemon llena con
//!    `std::fs::read`. En fase 2 ese `&[u8]` pasará a ser una vista
//!    `unsafe { slice::from_raw_parts(map_ptr, len) }` sobre un `mmap` del
//!    archivo — **sin cambiar ninguna API**: los lectores ya son zero-copy.
//! 2. `CaptureIndex.entries[i].file_offset` ya almacena offsets absolutos,
//!    así que la UI podrá pedir `packet(i)` y leer 1 página del SO en lugar
//!    del archivo entero → capturas de 20 GB con RAM constante.
//! 3. Los metadatos de sesión (índice invertido flujo→paquetes) se volcarán
//!    a SQLite/DuckDB con esquema columnar para filtrado instantáneo.
//!
//! Se introducirá con `memmap2` (crate auditado, maduro) cuando se justifique
//! el coste de dependencia según ADR-0001.

/// Explica el plan del store mmap (usable por el comando `soc-shark info`).
pub fn plan() -> &'static str {
    "Fase 2: mmap_store sustituye el read() completo por un mapa de memoria \
     del archivo de captura; los offsets de CaptureIndex ya están listos para \
     acceso aleatorio paginado."
}
