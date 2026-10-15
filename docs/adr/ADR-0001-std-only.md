# ADR-0001: Rust std-only en los crates del motor

- Estado: **aceptado** (fase 1)
- Contexto: una herramienta de seguridad procesa bytes hostiles; cada
  dependencia es superficie de ataque y de auditoría (cadena de suministro).
  Además, la base debe compilar en entornos restringidos (CI mínima,
  contenedores sin red, equipos de laboratorio air-gapped).
- Decisión: **cero dependencias externas** en `common`, `capture-core`,
  `dissectors`, `flow-aggregator`, `soc-engine`, `filter-dsl`,
  `storage-index` y `daemon` (fase 1). Implementaciones propias de SHA-256,
  Base64, JSON (escritura), entropía, IP/CIDR, tiempo y colores ANSI, todas
  con vectores de prueba conocidos.
- Consecuencias:
  - (+) Superficie de auditoría = este repo; builds reproducibles offline.
  - (+) Sin `libc`: binarios estáticos fáciles; SIGPIPE se gestiona con un
    hook de pánico (documentado en CHANGELOG).
  - (−) Más código propio que mantener (mitigado: piezas pequeñas y testeadas).
  - (−) La fase 2-3 introducirá dependencias puntuales (`memmap2`, `aya`,
    `ratatui`, `tokio`) **cada una con su ADR** y con criterio de
    mantenimiento activo y auditabilidad.
