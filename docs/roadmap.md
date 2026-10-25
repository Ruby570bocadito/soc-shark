# Hoja de ruta

Cinco fases, cada una con criterios de aceptación verificables. La regla del
proyecto: **una fase no se da por cerrada si su criterio falla**, aunque el
código exista. El estado se mantiene en este documento y en el README.

> **Lo que viene después de la 0.7.0** (README, i18n, protocolos, detecciones,
> GUI, rendimiento, empaquetado y el camino a la 1.0) está en el
> [roadmap de expansión](../ROADMAP.md).

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
      `--list` (interfaces), `--duration` y `--max-packets`. Verificado en
      una interfaz real (loopback de Linux con libpcap 1.10): la primera
      prueba con libpcap instalada destapó un SIGSEGV en la carga de
      símbolos y que el timeout de lectura no devolvía el control sin
      tráfico; ahora el handle va en modo no bloqueante con `poll` propio
      (tick garantizado, testeado cuando hay privilegios de captura) y
      Ctrl-C/SIGTERM cierran exportando los flujos vivos.
      **Windows**: el mismo backend carga el `wpcap.dll` de Npcap
      (LoadLibrary, layout de Windows, Ctrl+C con `SetConsoleCtrlHandler`
      y parada inmediata con `pcap_breakloop`); verificado con el
      `wpcap.dll` de Wine, pendiente de prueba en Windows real.
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

Estado 0.7.0: 210 tests verdes (152 en 0.6.0; el resto, de los arreglos, la GUI, el modo en vivo, el quién es quién y pcapng, ver CHANGELOG). El único criterio de fase pendiente de
verificación sobre hardware real es el rendimiento en vivo (≥ 200 Mbps
sostenidos y TUI fluida con 10k flujos): el resto del criterio (Follow
Stream legible, salida determinista con paralelismo) ya está cubierto por
tests. Follow Stream ya es legible para un flujo HTTP real (test de
integración con segmentos fuera de orden).

## Fase 3 — eBPF: atribución de proceso

Objetivo: la característica diferencial. Diseño completo en
[ebpf-design.md](ebpf-design.md). Las piezas puras (verificables con el
toolchain estándar y sin privilegios) están ya implementadas; los probes con
aya exigen nightly + `bpf-linker` + CAP_BPF y se implementan contra un
entorno Linux privilegiado.

- [x] Crate `socshark-ebpf-common` con tipos compartidos probe/userspace:
      `ConnectEvent`, `SocketStateEvent` y `UdpSendEvent` como `#[repr(C)]`,
      sin dependencias y compilable `no_std` (target `bpfel-unknown-none`);
      layout y helpers testados
- [ ] Probes `tcp_v4_connect`, `inet_sock_set_state`, `udp_sendmsg` con aya
      (pendiente de entorno con CAP_BPF; los eventos que emiten ya están
      definidos y testeados)
- [ ] Daemon separado con CAP_NET_RAW/CAP_BPF publicando por gRPC/UDS
- [ ] Correlación cookie-de-socket → (pid, exe, uid) en el Enricher
- [ ] Columnas Proceso/Usuario en la TUI + campo en el JSONL
- [x] Fingerprinting JA4 del handshake TLS (spec FoxIO oficial): parser de
      ClientHello que reconstruye el mensaje aunque cruce segmentos/registros
      (acotado a 16 KiB), SHA-256 propio sin dependencias (ADR-011),
      validación contra los vectores canónicos del spec en CI; huella en
      `ja4_fingerprint`, SNI en `tls_sni` (y `resolved_domain` desde SNI),
      campos DSL `tls.ja4` / `tls.sni`. QUIC/DTLS queda para después
- [x] Detección de beaconing por regularidad de intervalos (T1071):
      `IntervalStats` por flujo (ventana de 32 intervalos, tolerante a
      reordenamiento), regla `R5` con umbrales configurables (≥ 6 intervalos,
      media 5 s-1 h, CV ≤ 0.15, excluye ruido); el beacon demo de 30 s alerta
      en 3 minutos con periodo estimado exacto (±0%) — dentro del criterio
      de < 5 min y ±2%
- [ ] Descifrado TLS por uprobes con opt-in explícito (detrás de flag, con
      banner legal y auditoría)

Criterios: flujo iniciado por `curl` muestra `process_name=/usr/bin/curl`
antes de que el primer paquete llegue al dissector (pendiente de entorno
privilegiado); beaconing simulado con sleep fijo de 30 s se alerta en
< 5 min con periodo estimado ±2% — **cubierto por el test E2E** del
escenario demo (alerta a los 3 min, periodo 30.0 s ±0%).

## Fase 4 — GUI, plugins y export (piezas puras implementadas ✅)

Objetivo: producto para el analista no-cli y ecosistema de comunidad. Las
piezas verificables sin entorno gráfico ni runtime pesado están ya
implementadas; Tauri, wasmtime y DuckDB se implementan contra sus
ecosistemas (son las únicas piezas que justificarían dependencias nuevas).

- [x] File carving HTTP con SHA-256 + detección T1036 (magic vs nombre y
      doble extensión ejecutable): Content-Length/chunked, keep-alive,
      magic bytes propio, regla R6 `FILE-MASQUERADING`; criterio de fase
      cubierto por test E2E (el ejecutable renombrado a `.jpg` del escenario
      demo genera la alerta)
- [x] Threat intel offline (Feodo C2 IP/CIDR v4-v6, Tor Bulk Exit List) →
      `threat_intel` + regla R7 (`THREAT-INTEL-FEODO` T1071.001,
      `TOR-USAGE` T1090.003); GeoIP/ASN hacia `dst_geo_asn` queda pendiente
      de un lector `.mmdb` propio (sin dependencias)
- [x] Export SIEM: mapeo ECS 8.x completo en lo esencial + salida Wazuh
      (reglas de ejemplo documentadas en `docs/siem-export.md`); push a
      TheHive pendiente (exigiría cliente HTTP propio)
- [x] GUI (`socshark gui`, ADR-013): página local servida por el binario,
      sin dependencias nuevas. Historias agrupadas con «qué hacer»,
      conversaciones en lenguaje claro (modo Simple) o técnico (Experto),
      vista de paquetes con capas explicadas y bytes resaltados, filtro DSL,
      glosario, abrir/arrastrar capturas. Ver [gui.md](gui.md)
- [x] GUI en tiempo real y funciones tipo Wireshark: captura en vivo desde
      la ventana (interfaces con IP y estado, foto cada segundo, parada
      inmediata), lista global de paquetes virtualizada, «Contenido»
      (seguir flujo), estadísticas (protocolos, servicios, equipos,
      actividad en el tiempo), «filtrar por…» con clic derecho, columnas
      ordenables, paneles ajustables y guardar `.pcap`
- [x] Quién es quién: nombres por DHCP/mDNS/LLMNR/NetBIOS, fabricante por
      MAC (registro IEEE), router y este ordenador, apodos persistentes y,
      en vivo, el programa de cada conexión (Linux/Windows) — ADR-014
- [x] Mapa de la red (tu red · router · Internet), avisos en vivo con
      notificación del sistema e informe HTML en lenguaje claro
      (`socshark report`)
- [x] Lectura de pcapng (secciones, interfaces, resoluciones de tiempo)
- [ ] GUI empaquetada (Tauri) con tabla de conversaciones virtualizada, SequenceView de
      handshakes y StreamInspector con decodificador CyberChef-style
      (pipelines Base64→XOR→Zlib→JSON)
- [ ] Runtime de plugins WASM (wasmtime) con la API WIT de
      [wasm-plugins.md](wasm-plugins.md) + firma Ed25519 + plugins oficiales
- [ ] Persistencia de sesiones (DuckDB) con consultas analíticas

Criterios restantes: un plugin HTTP comunitario corre en sandbox con fuel
limit y enriquece flujos reales (wasmtime); un SIEM Wazuh de laboratorio
recibe flujos enriquecidos con tags ATT&CK correctos — el contrato de
export ya está operativo (`docs/siem-export.md`), la verificación en un
manager real queda pendiente de entorno. El criterio T1036 está **cubierto
por test E2E**.

## Fuera de alcance (declarado)

- Captura inalámbrica (802.11): requiere stack de radios distinto; quizá
  como proyecto hermano.
- Interceptar/bloquear tráfico: soc-shark es solo lectura por diseño.
- Sustituir el SIEM: soc-shark alimenta SIEMs, no los reemplaza.
