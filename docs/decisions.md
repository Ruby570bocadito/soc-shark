# Decisiones de arquitectura (ADRs)

Registro de decisiones con formato ADR (*Architecture Decision Record*).
Cada decisión ocupa un bloque numerado, inmutable una vez aceptada: si el
contexto cambia, se escribe un ADR nuevo que **supersede** al anterior y se
actualiza su estado. Las decisiones citadas por el código y la documentación
(`ADR-001`, `ADR-003`, `ADR-007`, ...) apuntan siempre a este archivo.

- **Estado** — propuesta / aceptada / reemplazada por ADR-XXX.
- **Contexto** — el problema real que fuerza a decidir, con sus restricciones.
- **Decisión** — qué se eligió, de forma concreta y verificable.
- **Consecuencias** — qué gana y qué cuesta el proyecto con esta elección.

---

## ADR-001 — Rust como lenguaje del motor

**Estado:** aceptada.

**Contexto.** El motor procesa bytes controlables por un atacante a línea
caliente: necesita rendimiento comparable a C/C++, garantías de memoria sin
GC y una historia de herramientas (cargo, clippy, rustfmt, cargo-fuzz) que
escalen con el proyecto. Go descarta GC pauses deterministas y no permite
eBPF idiomático sin CGo; C/C++ no ofrece seguridad de memoria; Python no
cubre el objetivo de rendimiento.

**Decisión.** Rust (edition 2021, MSRV 1.75) para todos los crates del
workspace. Sin `unsafe` en Fase 1; si algún módulo futuro lo requiere
(ARENA de mmap, FFI de captura), irá aislado en un crate propio con
`#![deny(unsafe_code)]` en el resto y auditoría explícita en el ADR
correspondiente.

**Consecuencias.** Curva de aprendizaje inicial y tiempos de compilación
mayores, a cambio de parsers que no necesitan fuzzing para no ser exploits
(aunque se fuzzing igualmente: ver [security.md](security.md)) y de un MSRV
bajo que facilita la instalación en distribuciones estables.

---

## ADR-002 — Paradigma Flow-First: `EnrichedFlow` como unidad central

**Estado:** aceptada.

**Contexto.** La pregunta del analista SOC es *«¿qué está pasando y qué me
debería preocupar?»*, no *«¿qué hay en el paquete 4281?»*. Toda la interfaz,
el filtrado, la puntuación de riesgo y la exportación necesitan una unidad
con contexto de sesión, no tramas sueltas.

**Decisión.** El tipo central del proyecto es `EnrichedFlow`
([data-model.md](data-model.md)): una conversación bidireccional con
contadores, protocolo L7, dominio resuelto, alertas, riesgo y campos
reservados para la atribución de proceso de la Fase 3. Los paquetes crudos
(`RawPacket`) existen, pero son entrada del pipeline, nunca producto de
salida por defecto.

**Consecuencias.** Las cuatro etapas del pipeline comparten un contrato
estable y serializable (JSONL), lo que desacopla CLI/TUI/GUI del núcleo. El
coste: el análisis *por paquete* (examen hex, reensamblado) requiere
expandir un flujo, y esa vista llega en la Fase 2/4.

---

## ADR-003 — Lector pcap propio y dependencias externas mínimas

**Estado:** aceptada.

**Contexto.** La cadena de suministro es una superficie de ataque real para
una herramienta de seguridad (ver [security.md](security.md)). Los bindings
de libpcap arrastran una librería C y `build.rs` con ejecución de código
arbitrario en cada `cargo build`; el formato pcap clásico es trivial
(cabecera global de 24 bytes + registros de 16) y se puede parsear con
Rust seguro y acotado.

**Decisión.** Fase 1 implementa su propio lector pcap (4 magics, micro y
nanosegundos, ambos endianness, validación de longitudes) y sus checksums.
Las dependencias externas quedan congeladas en cinco crates auditables y de
mantenimiento impecable: `serde`, `serde_json`, `thiserror`, `clap`,
`anyhow`. pcapng se aplaza a Fase 2 (detrás del trait `CaptureSource`), y
cualquier dependencia nueva exige un ADR que la justifique.

**Consecuencias.** Menos superficie de auditoría y builds reproducibles sin
toolchains del sistema; a cambio, asumimos mantener el parser propio (con
sus tests) y perder temporalmente la lectura de pcapng y la captura en vivo,
que llegan por fases según [roadmap.md](roadmap.md).

---

## ADR-004 — Separación de privilegios: daemon captura, resto no

**Estado:** aceptada.

**Contexto.** Un bug en un disector escrito por terceros no debe convertirse
nunca en un root exploit. Si todo el programa corre con privilegios de
captura, cada parser es parte del TCB (*trusted computing base*).

**Decisión.** Arquitectura de dos procesos desacoplados por JSONL sobre un
socket: el *daemon* (único componente con `CAP_NET_RAW`, y más adelante
`CAP_BPF`) solo captura y serializa; dissectors, heurísticas, plugins y UI
corren sin privilegios y consumen flujos. La Fase 1 lo respeta en espíritu
(CLI sin privilegios leyendo archivos) y deja la frontera de proceso definida
en [security.md](security.md) para la Fase 2.

**Consecuencias.** Un poco más de complejidad operativa (dos binarios, IPC),
a cambio de que el 95 % del código —el que procesa datos hostiles de forma
más creativa— quede fuera del TCB.

---

## ADR-005 — DSL de filtrado propio, no el lenguaje de Wireshark

**Estado:** aceptada.

**Contexto.** El filtro es la herramienta diaria del analista. Reutilizar el
lenguaje de Wireshark (display filter) promete familiaridad, pero arrastra
semántica packet-céntrica incompatible con Flow-First (¿qué significa
`ip.src == X` en una conversación bidireccional?) y una especificación
grande que habría que imitar con fidelidad incierta.

**Decisión.** DSL propio ([filter-dsl.md](filter-dsl.md)) con lexer,
parser por precedencias (`or` < `and` < `not`) y evaluador sobre
`EnrichedFlow`: campos de flujo (`flow.risk`, `flow.bytes`), campos L7
(`dns.qname`, `tls.sni`), operadores de comparación y `contains`, atajos de
protocolo (`dns`, `tls`, `noise`). La sintaxis es deliberadamente parecida
a Wireshark para que la migración sea intuitiva, pero la semántica es de
flujo.

**Consecuencias.** Control total de la gramática y del mensaje de error con
posición; coste de aprendizaje para usuarios de Wireshark, mitigado por la
similitud de sintaxis y la documentación con ejemplos.

---

## ADR-006 — Zero-copy por slicing y cero panics con datos hostiles

**Estado:** aceptada.

**Contexto.** Los parsers procesan bytes que un atacante controla y que
llegan a máxima velocidad. Clonar cada trama multiplica el ancho de banda de
memoria; un `panic` en el camino de datos convierte un paquete malformado en
una denegación de servicio del propio analizador.

**Decisión.** Los dissectors trabajan con `&[u8]` prestados y acceden por
slicing acotado (`get`, comparaciones de longitud, `try_into`); solo se
copian metadatos pequeños y cadenas necesarias (nombres DNS). Cualquier caso
degenerado devuelve `Option::None`. La suite de tests incluye tramas
truncadas en todas las longitudes y punteros DNS con bucles diseñados para
colgar implementaciones ingenuas.

**Consecuencias.** El estilo de parseo es más verboso que el indexing
directo; a cambio, el motor nunca crashea por entrada malformada y la copia
de bytes queda confinada donde aporta valor.

---

## ADR-007 — Documentación en español, identificadores en inglés

**Estado:** aceptada.

**Contexto.** El proyecto define su audiencia primaria en analistas SOC de
habla hispana (documentación, mensajes de error, resúmenes humanos), mientras
que el ecosistema Rust, las APIs y el código fuente de terceros son en
inglés. Mezclar idiomas sin una regla explícita produce inconsistencia
inmediata.

**Decisión.** Toda la documentación (`docs/`, README, CHANGELOG,
CONTRIBUTING), los mensajes de la CLI y los doc-comments van en español; los
identificadores, nombres de tipos y términos técnicos (`dissector`, `flow`,
`uprobe`) van en inglés. Esta regla se aplica también en revisión de PRs.

**Consecuencias.** Documentación accesible para su audiencia y una base de
código que cualquier desarrollador Rust puede contribuir sin fricción
lingüística inesperada.

---

## ADR-008 — Reescritura v0.2: workspace limpio `socshark-*`

**Estado:** aceptada (reemplaza el alcance de la v0.1; ver tag
`v0.1.0-base` en el historial git).

**Contexto.** La primera iteración (v0.1.0-base) creció en paralelo a la
definición del producto y acumuló módulos que las fases aún no sostienen
(pcapng, ring buffer, carving, export SIEM, esbozos de TUI/GUI) junto a una
regla *std-only* que penalizaba la serialización y la CLI. El resultado era
difícil de mantener y de explicar.

**Decisión.** Se reescribe el workspace con ocho crates `socshark-*`
(core → capture → dissectors → flow → soc → filter, más testgen y cli),
se adoptan las cinco dependencias externas de ADR-003 y se redocumenta el
proyecto desde cero ([index.md](index.md)). El código de la v0.1 que aún no
tiene fase asignada (pcapng, carving, SIEM, TUI) vuelve por
[roadmap.md](roadmap.md) cuando su fase lo requiera; el historial git
conserva el trabajo original bajo el tag `v0.1.0-base`.

**Consecuencias.** Base de código homogénea, testeada (70 tests) y
alineada con la visión de producto; el coste, asumido, es rehacer por fases
funcionalidad que la v0.1 ya adelantó sin contrato de diseño estable.
