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

**Decisión.** Rust (edition 2021, MSRV 1.75 en origen; hoy 1.88, la que exigen las dependencias del Cargo.lock) para todos los crates del
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

**Decisión.** Se reescribe el workspace con crates `socshark-*` (ocho al reescribir;
nueve desde la Fase 3 con `socshark-ebpf-common`)
(core → capture → dissectors → flow → soc → filter, más testgen y cli),
se adoptan las cinco dependencias externas de ADR-003 y se redocumenta el
proyecto desde cero ([index.md](index.md)). El código de la v0.1 que aún no
tiene fase asignada (pcapng, carving, SIEM, TUI) vuelve por
[roadmap.md](roadmap.md) cuando su fase lo requiera; el historial git
conserva el trabajo original bajo el tag `v0.1.0-base`.

**Consecuencias.** Base de código homogénea, testeada (70 tests) y
alineada con la visión de producto; el coste, asumido, es rehacer por fases
funcionalidad que la v0.1 ya adelantó sin contrato de diseño estable.

---

## ADR-009 — Captura en vivo: FFI propio sobre libpcap con `dlopen`

**Estado:** aceptada (Fase 2).

**Contexto.** La captura en vivo exige hablar con el stack de captura del
sistema. Las opciones eran: (a) depender del crate `pcap` (rompería el
congelamiento de dependencias de ADR-003 y añadiría `-sys` con enlazado en
tiempo de compilación), (b) usar sockets crudos AF_PACKET vía `libc` (otro
crate, más código de bajo nivel y sin pushdown BPF portable), o (c) declarar
nuestro propio FFI contra libpcap. Además, el entorno de desarrollo no tiene
`libpcap-dev`, así que cualquier dependencia de enlazado rompería los builds
por defecto.

**Decisión.** `socshark-capture/src/live.rs` declara las firmas de la API
estable de libpcap (`pcap_create/activate/next_ex/compile/setfilter/stats/
findalldevs/...`) y carga la biblioteca con `dlopen` al abrir la interfaz,
probando los sonames habituales (`libpcap.so.0.8`, `libpcap.so.1`,
`libpcap.so`, `libpcap` en macOS). Consecuencias de diseño: cero
dependencias nuevas y ningún requisito de compilación; el binario por
defecto funciona en cualquier máquina y la captura en vivo se resuelve al
ejecutar (si falta la biblioteca, error limpio con instrucciones de
instalación). El backend cubre unix LP64 y Windows de 64 bits (Npcap:
`wpcap.dll` con `LoadLibraryExW`, primero por ruta absoluta del sistema;
`timeval` de 32 bits y `pcap_stat` ampliado; sin `poll` ni modo inmediato,
el tick lo da el timeout de Npcap); otras plataformas reciben un stub con
`LiveUnavailable`. `LiveBreaker` permite despertar una lectura bloqueada
desde otro hilo con `pcap_breakloop`, bajo un cerrojo que `Drop` toma antes
de `pcap_close`. Los punteros de función se resuelven con `dlsym` y
se tipan contra firmas auditadas; `LiveCapture` es `Send` (un solo hilo de
lectura) y libera `pcap_freecode`/`pcap_close`/`dlclose` en orden garantizado.

**Consecuencias.** La superficie FFI es nuestra responsabilidad: cualquier
error de firma es un fallo silencioso, mitigado con un conjunto mínimo de
funciones estables, tests de degradación limpia y el fuzzer del pipeline
(no del FFI). El coste de indirección de `dlsym` es una vez por apertura.
A cambio, distribuir soc-shark no exige binarios por distribución ni
paquetes `-dev`.

---

## ADR-010 — Paralelismo de disección por lotes con entrega ordenada

**Estado:** aceptada (Fase 2).

**Contexto.** La disección es la etapa CPU-intensiva y es una función pura
(`RawPacket → Option<DissectedPacket>`), ideal para paralelizar. Pero el
agregador es secuencial y *sensible al orden*: la dirección fwd/rev, los
timestamps de first/last seen y el reensamblado dependen del orden de
llegada. Un pool ingenuo que entregue en orden de finalización alteraría
los flujos (y las alertas) de forma no determinista entre ejecuciones.

**Decisión.** Paralelismo **por lotes**: el lector acumula lotes de 256
paquetes, los reparte round-robin entre N workers y vuelca los resultados
al agregador estrictamente en el orden de envío, almacenando en búfer los
lotes adelantados. El paralelismo se da *dentro* del lote; el orden global
queda intacto, de modo que `--workers 4` produce JSONL byte a byte idéntico
a `--workers 1` (test E2E de igualdad). Para cruzar hilos, `DissectedPacket`
lleva el payload como `Cow<[u8]>`: `Borrowed` en el camino secuencial
(zero-copy de ADR-006 intacto) y `Owned` solo cuando el pool copia. Los
workers son desechables y su muerte (p. ej., tras un error inesperado)
degrada a "lote no diseccionado" sin pánico.

**Consecuencias.** La latencia por lote acota el paralelismo efectivo a
tráficos con lotes llenos (en archivos, irrelevante; en vivo el daemon usa
disección secuencial porque la cadencia de alerta manda). A cambio:
determinismo verificable, sin locks en el agregador, y una sola línea de
configuración (`workers`) para escalar en máquinas grandes.

---

## ADR-011 — SHA-256 propio para JA4 (sin dependencias criptográficas)

**Estado:** aceptada (Fase 3).

**Contexto.** La huella JA4 exige SHA-256 de las listas de ciphers y
extensiones del ClientHello. Las opciones eran añadir una crate de hashing
(`sha2`, madura y auditada) o implementar el algoritmo en el workspace. El
contexto importa: no es una primitiva de seguridad (no protege secretos ni
firma nada), es un resumen público y determinista sobre una lista de
números de 16 bits.

**Decisión.** Implementación propia de ~80 líneas en
`socshark-dissectors::tls` (FIPS 180-4, revisable línea a línea), validada
en CI con los vectores oficiales de NIST (cadena vacía, "abc", fronteras de
bloque a 55 y 64 bytes) **y** con los vectores canónicos de la
especificación JA4 de FoxIO (`8daaf6152771` y `e5627efa2ab1`), que además
ejercitan todo el pipeline de normalización (orden hex, ceros, GREASE). Se
mantiene así la regla de dependencias congeladas (ADR-003) intacta.

**Consecuencias.** Si JA4 dejara de bastar y hubiera que cifrar/firmar con
SHA-256, se sustituye por una crate auditada en ese momento (el módulo está
aislado detrás de `sha256()` y `sha256_12()`). El coste de mantenimiento es
mínimo: el algoritmo lleva congelado desde 2001 y los tests de vectores
detectan cualquier regresión.

## ADR-012 — Export SIEM e ISO-8601 propio (sin dependencias nuevas)

**Fecha:** 2026-10-16 · **Estado:** aceptada

**Contexto.** La Fase 4 exige entregar los flujos enriquecidos a SIEMs
(Elastic ECS y Wazuh). ECS exige `@timestamp` ISO-8601 con precisión de
microsegundos; el workspace congela sus dependencias externas en cinco
crates (ADR-003) y ni `chrono` ni `time` aportan nada más al proyecto.

**Decisión.** El export vive en `socshark-soc::siem` como transformación
pura sobre `EnrichedFlow` (dos funciones: `to_ecs` y `to_wazuh`), añadiendo
solo `serde_json` al crate — que ya estaba en el conjunto congelado. La
conversión de microsegundos Unix a fecha civil ISO-8601 se implementa con
el algoritmo de Howard Hinnant (`civil_from_days`, ~20 líneas), testado
contra época, la fecha del escenario demo y un bisiesto con fracción de
segundo. El contrato campo a campo se documenta en `docs/siem-export.md`
y es la referencia obligada ante cualquier cambio.

En la misma línea, el SHA-256 de ADR-011 se centraliza en
`socshark-core::hash` para que el file carving (Fase 4) reutilice el motor
de JA4 sin duplicar código.

**Consecuencias.** Un formato de fecha menos estándar (sin zonas horarias
no-UTC) a cambio de cero dependencias; los timestamps de soc-shark son
siempre UTC. Si TheHive exigiera cliente HTTP (ADR-003 lo prohíbe hoy), se
revaluará en un ADR específico: por ahora el camino es SIEM → TheHive con
sus integraciones nativas.

## ADR-013 — GUI como página local servida por el binario (sin dependencias nuevas)

**Fecha:** 2026-10-19 · **Estado:** aceptada

**Contexto.** El objetivo del proyecto es que *cualquier persona* entienda
su red, no solo quien domina Wireshark: hace falta una interfaz gráfica, y
el roadmap preveía Tauri + WebGL. Tauri arrastra cientos de crates y, en
Windows, requisitos de compilación adicionales; la regla de dependencias
congeladas (ADR-003) sigue vigente y la mayoría de usuarios están en
Windows, donde una GUI que no compila es peor que ninguna.

**Decisión.** `socshark gui` sirve una página web local desde el propio
binario y la abre en una ventana de aplicación (Edge/Chrome con `--app`, o
el navegador por defecto):

- Servidor HTTP/1.1 mínimo propio (`socshark-cli::gui::http`, std), solo en
  `127.0.0.1`, con comprobación de `Host`, token de sesión en cada llamada a
  la API, CSP estricta y límites de tamaño y tiempo.
- Frontend sin frameworks ni CDN (`assets/gui/`: HTML, CSS y JS
  incrustados con `include_str!`); todo dato de la captura se pinta como
  texto, nunca con `innerHTML`.
- El lenguaje claro (semáforo, frases, «qué hacer», historias agrupadas)
  vive en el motor (`socshark-soc::explain`), no en la interfaz.
- Solo se añade `serde` (ya en el conjunto congelado) a `socshark-soc` y
  `socshark-cli`.

**Consecuencias.** GUI en Windows, macOS y Linux hoy, sin dependencias
nuevas y probada en un navegador real. La ventana es una página: no hay
icono propio en la barra de tareas ni instalador. El frontend está aislado
detrás de una API JSON pequeña, así que empaquetarlo en Tauri más adelante
no exige reescribirlo; esa decisión se tomará en su propio ADR cuando el
producto lo justifique.

*Ampliación (modo en vivo).* La captura en vivo de la GUI reutiliza el
backend del daemon en un hilo propio que publica una **foto** de la red
cada segundo (conversaciones terminadas + activas, enriquecidas con un
contexto SOC nuevo para que escaneo y DNS pasivo vean el conjunto) con un
número de generación; la ventana consulta `/api/session` cada segundo y
solo recarga cuando la generación cambia. Se eligió el sondeo frente a
WebSocket/SSE para no complicar el servidor HTTP mínimo: a 1 Hz y en
`127.0.0.1` su coste es despreciable.

## ADR-014 — Quién es quién: nombres anunciados, fabricante y programa

**Contexto.** Para que cualquiera entienda su red, «192.168.1.30» no sirve:
hay que decir «el iPhone de Ana», «la impresora HP» o «el router», y en el
propio ordenador, qué programa habló. Wireshark resuelve nombres por DNS,
pero no reconoce equipos ni procesos.

**Decisión.**
- **Lo que anuncian los equipos**, aprendido paquete a paquete
  (`socshark-soc::hosts::HostBook`): nombre de host por DHCP (opción 12),
  sistema por la opción 60, nombres y servicios mDNS (impresora,
  Chromecast, AirPlay…), LLMNR y registros NetBIOS; prioridad DHCP > mDNS
  > LLMNR > NetBIOS. Parsers nuevos y acotados en
  `socshark-dissectors::discovery`. Solo para direcciones de la red local.
- **Router**: la MAC por la que entra y sale el tráfico de Internet (y la
  opción 3 de DHCP). **Este ordenador**: las direcciones de sus interfaces
  (en vivo).
- **Fabricante**: subconjunto del registro público MA-L del IEEE con ~70
  marcas reconocibles en casa y oficina (11.762 prefijos), generado por
  `scripts/gen_oui.py` a `oui_data.rs` e incrustado (sin red al
  ejecutar). La marca se dice como marca («Apple», no la razón social) y
  con «a qué suele corresponder» solo cuando es fiable («router de
  operadora»). Las MAC administradas localmente se marcan como aleatorias.
- **Programa**: foto de la tabla de sockets del sistema cada 400 ms
  mientras haya conversaciones de esta máquina sin dueño
  (`socshark-capture::owners`: `/proc` en Linux; iphlpapi en Windows), sin
  dependencias nuevas. El programa se atribuye al lado que es esta
  máquina.
- **Apodos** de la persona usuaria, persistentes y por MAC.
- Todo es **informativo**: ninguna regla de alerta lo usa.

**Consecuencias.** Las frases, la GUI, el mapa y el informe hablan con
nombres. Coste: un análisis por paquete más (barato) y una tabla de ~94 KB
en el binario. Limitaciones conocidas: un equipo puede mentir sobre su
nombre; una conexión que se abre y cierra entre dos fotos de la tabla de
sockets queda sin programa (eBPF lo resolverá, Fase 3); macOS aún no
atribuye programas; Wine no informa del dueño de los sockets, así que en
Windows se ha probado la lectura de la tabla pero no la atribución real.
