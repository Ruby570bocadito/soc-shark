# Hoja de ruta

Cinco fases, cada una con criterios de aceptación verificables. La regla del
proyecto: **una fase no se da por cerrada si su criterio falla**, aunque el
código exista. El estado se mantiene en este documento y en el README.

## Fase 0 — Fundaciones ✅ (completada)

Estructura del workspace, modelo de datos `EnrichedFlow` completo (con
campos futuros reservados), CI con fmt/clippy/test, documentación base y el
generador de fixtures `socshark-testgen`.

- [x] Workspace multi-crate con grafo de dependencias limpio
- [x] `EnrichedFlow` y tipos asociados serializables con `serde(default)`
- [x] Pipeline de CI: `fmt --check`, `clippy -D warnings`, `test`, `build`

## Fase 1 — MVP funcional sobre pcap ✅ (completada)

Analizar capturas de archivo de extremo a extremo y producir valor SOC real.

- [x] Lector pcap clásico propio (4 magics, validación, límites)
- [x] Dissectors: Ethernet (+VLAN), IPv4 (checksum), TCP, UDP, DNS
      (compresión, DNS-over-TCP) + heurística L7 (TLS/HTTP/SSH/NTP/DHCP)
- [x] Agregador de flujos bidireccionales con expiración y presión de memoria
- [x] DSL de filtrado con parser por precedencia y 25+ campos
- [x] Capa SOC: DNS pasivo, ruido de fondo, mini-IDS (túnel DNS, escaneo,
      telnet, DB expuesta), riesgo 0-100, resúmenes humanos
- [x] CLI: `capture` (tabla/JSONL/filtro), `dev sample-pcap`, stub `daemon`
- [x] 70 tests (unitarios + integración) en verde, clippy limpio

## Fase 2 — Captura en vivo + TUI (implementación completa ✅)

Objetivo: dejar de ser un lector de archivos y convertirse en herramienta de
operación en tiempo real.

- [x] Backend de captura en vivo: **libpcap vía FFI propio + `dlopen`**
      (ADR-009) — sin `libpcap-dev` en tiempo de compilación ni crates
      nuevos; si la biblioteca falta, error limpio con instrucciones.
      Soporta snaplen, promiscuo, *immediate mode*, timeout de lectura y
      **pushdown BPF** al kernel; `socshark daemon` consume el flujo con
      expiración incremental y exportación JSONL/alertas por cadencia, más
      `--list` (interfaces), `--duration` y `--max-packets`. La
      verificación *en una interfaz real* queda pendiente de un entorno con
      privilegios de captura (el sandbox de desarrollo no tiene libpcap ni
      CAP_NET_RAW); la frontera FFI está testeada (errores limpios, sin
      panics) y el resto del pipeline es idéntico al modo archivo.
      AF_XDP sigue siendo el objetivo de alto rendimiento (Fase 3+).
- [x] Pipeline en streaming: agregador incremental con `drain_expired`
      testado; el daemon en vivo lo consume por cadencia (`--flush-secs`).
- [x] Pool de dissectors concurrente (ADR-010): lotes de 256 paquetes en
      N hilos (`--workers`), entrega ordenada garantizada — test E2E de
      igualdad JSONL byte a byte frente al camino secuencial.
- [x] TUI con Ratatui (modo offline): lista Flow-First con detalle
      expandible, panel de alertas, línea de filtro con el DSL completo y
      ruido atenuado (`socshark tui -r captura.pcap`, ver `docs/tui.md`);
      el modelo de estado se testea sin terminal y se enchufará al JSONL
      del daemon en vivo sin cambios
- [x] IPv6 completo: disector con cabeceras de extensión (Hop-by-Hop,
      Routing, Destinos, Fragment —solo primer fragmento— y AH), claves de
      flujo sobre `IpAddr`, campo `ip_version`, `ip.version` en el DSL y
      literales v6 nativos (`2001:db8::1`)
- [x] Reensamblado TCP por dirección: orden de secuencia con aritmética
      serial (RFC 9293 §3.3), deduplicación de retransmisiones, huecos
      marcados (`[N bytes perdidos]`), tope de 1 MiB con marcado `lossy`,
      más `socshark follow` en texto/hexdump
- [x] Fuzzing: **determinista en proceso** (`socshark dev fuzz`,
      splitmix64 propio, corpus mutado del escenario demo, recorre
      disección + agregador + expiración + SOC + DSL; CI ejecuta 50 000
      iteraciones por build y un fallo se reproduce con la semilla
      impresa). En su primera ejecución atrapó y corrigió un panic real
      (DNS con `QDCOUNT=0`). cargo-fuzz/libFuzzer con cobertura guiada
      queda como tarea de contribución (ver CONTRIBUTING.md).

Estado 0.4.0: 105 tests verdes. El único criterio de fase pendiente de
verificación sobre hardware real es el rendimiento en vivo (≥ 200 Mbps
sostenidos y TUI fluida con 10k flujos): el resto del criterio (Follow
Stream legible, salida determinista con paralelismo) ya está cubierto por
tests. Follow Stream ya es legible para un flujo HTTP real (test de
integración con segmentos fuera de orden).

## Fase 3 — eBPF: atribución de proceso

Objetivo: la característica diferencial. Diseño completo en
[ebpf-design.md](ebpf-design.md).

- [ ] Crate `socshark-ebpf-common` con tipos compartidos probe/userspace
- [ ] Probes `tcp_v4_connect`, `inet_sock_set_state`, `udp_sendmsg` con aya
- [ ] Daemon separado con CAP_NET_RAW/CAP_BPF publicando por gRPC/UDS
- [ ] Correlación cookie-de-socket → (pid, exe, uid) en el Enricher
- [ ] Columnas Proceso/Usuario en la TUI + campo en el JSONL
- [ ] Fingerprinting JA4 del handshake TLS (sobre el reensamblado de F2)
- [ ] Detección de beaconing por regularidad de intervalos (T1071)
- [ ] Descifrado TLS por uprobes con opt-in explícito (detrás de flag, con
      banner legal y auditoría)

Criterios: flujo iniciado por `curl` muestra `process_name=/usr/bin/curl`
antes de que el primer paquete llegue al dissector; beaconing simulado con
sleep fijo de 30 s se alerta en < 5 min con periodo estimado ±2%.

## Fase 4 — GUI, plugins y export

Objetivo: producto para el analista no-cli y ecosistema de comunidad.

- [ ] GUI con Tauri + WebGL: tabla virtualizada de flujos, RadarSidebar de
      IOCs, SequenceView de handshakes, StreamInspector con decodificador
      CyberChef-style (pipelines Base64→XOR→Zlib→JSON)
- [ ] Runtime de plugins WASM (wasmtime) con la API WIT de
      [wasm-plugins.md](wasm-plugins.md) + firma Ed25519 + plugins oficiales
- [ ] File carving HTTP con SHA-256 + detección T1036 (magic vs nombre)
- [ ] Threat intel offline (GeoIP/ASN, Feodo, Tor exits) → `dst_geo_asn`
- [ ] Export SIEM: mapeo ECS completo, salida Wazuh, push a TheHive
- [ ] Persistencia de sesiones (DuckDB) con consultas analíticas

Criterios: un plugin HTTP comunitario corre en sandbox con fuel limit y
enriquece flujos reales; un ejecutable renombrado a `.jpg` transferido por
HTTP genera alerta T1036; un SIEM Wazuh de laboratorio recibe flujos
enriquecidos con tags ATT&CK correctos.

## Fuera de alcance (declarado)

- Captura inalámbrica (802.11): requiere stack de radios distinto; quizá
  como proyecto hermano.
- Interceptar/bloquear tráfico: soc-shark es solo lectura por diseño.
- Sustituir el SIEM: soc-shark alimenta SIEMs, no los reemplaza.
