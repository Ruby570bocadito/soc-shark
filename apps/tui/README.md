# apps/tui — Interfaz de terminal (fase 2)

Estado: **no implementada todavía** (el motor de fase 1 está completo y su
salida textual en `daemon/src/output.rs` ya define el render de referencia).

## Plan

- **Ratatui** (dependencia se introduce en fase 2, con ADR).
- Componentes:
  - Tabla virtualizada de `EnrichedFlow` (una fila por conversación).
  - Barra de filtro con el DSL de `socshark-filter-dsl` (autocompletado del
    catálogo `registry::FIELDS`).
  - Acordeón `▶/▼` de paquetes vía `CaptureIndex` + mmap.
  - Panel Radar SOC (alertas + artefactos) y visor hex.
- Navegación Vim: `j/k` · `/` filtro · `Enter` expandir · `E` exportar ECS ·
  `S` regla Suricata · `n` alternar ruido · `q` salir.

## Criterios de aceptación (ver docs/11-hoja-de-ruta.md)

- Triaje del demo sin tocar la shell: radar visible al abrir.
- 1 M de flujos con scroll fluido (virtual scrolling sobre índice mmap).
- Filtro DSL aplicado en el motor, no en la TUI.
