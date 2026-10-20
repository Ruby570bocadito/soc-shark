# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y [SemVer](https://semver.org/lang/es/).

## [Sin publicar]

## [0.7.0] — 2026-10-19

### Añadido

- **Instalación en una línea en Linux** (`install.sh`, también macOS):
  `curl -fsSL … | bash`. Instala lo que falte (git, compilador de C,
  libpcap, `setcap`) con apt, dnf, yum, pacman, zypper o apk, Rust con
  rustup, compila, instala en `~/.local/bin` y da al binario el permiso de
  captura (`cap_net_raw,cap_net_admin`): **la red en vivo funciona sin
  sudo**. Desde una copia del repositorio usa esa copia; se puede volver a
  ejecutar para actualizar.
- **Ventana propia en Linux**: `socshark gui` se abre en modo aplicación con
  Chrome, Chromium, Edge o Brave si están instalados (como en Windows); si
  no, en el navegador por defecto.
- **README en inglés (por defecto) y en español** (`README.es.md`), con la
  instalación en una línea bien visible, un **vídeo de demostración**
  (`docs/media/demo.webp` y `demo.mp4`) y una captura real de la **TUI**.
- CI: revisa los instaladores (`shellcheck install.sh`, sintaxis de
  `install.ps1` y que siga en ASCII sin BOM).
- **GUI** (`socshark gui [-r captura.pcap]`, ADR-013, [docs/gui.md](docs/gui.md)):
  ventana estilo Wireshark pensada para que cualquier persona entienda su
  red. Historias (alertas agrupadas: un escaneo es una historia) con «qué
  hacer» y enlace a MITRE ATT&CK; conversaciones en lenguaje claro con
  semáforo 🟢🟠🔴 (modo Simple) o en columnas técnicas (modo Experto);
  vista de paquetes con una frase por paquete, capas explicadas campo a
  campo y bytes en hexadecimal resaltados por capa; filtro DSL con error
  señalado en su posición; glosario al pasar el ratón; abrir o arrastrar
  capturas; tema claro/oscuro. Página local servida por el propio binario
  (HTTP propio solo en `127.0.0.1`, token de sesión, comprobación de
  `Host`, CSP estricta): sin dependencias nuevas, funciona en Windows,
  macOS y Linux. En Windows se abre como ventana de aplicación con Edge o
  Chrome.
- **GUI en tiempo real**: botón «En vivo» (Ctrl+E) que muestra la red
  mientras pasa. Las interfaces se presentan como las reconoce una persona
  (Wi-Fi o cable con su IP y si está conectada; loopback aparte; las
  especiales, plegadas), filtro de captura BPF opcional, foto nueva cada
  segundo sin perder la selección ni el desplazamiento, paquetes perdidos
  por el sistema en la barra de estado y «Detener» inmediato aunque no haya
  tráfico (`pcap_breakloop` protegido contra uso tras cierre).
- **Captura en vivo en Windows** con [Npcap](https://npcap.com): mismo
  backend cargando `wpcap.dll` (layout de Windows: `timeval` de 32 bits,
  `pcap_stat` ampliado), Ctrl+C del daemon con `SetConsoleCtrlHandler`.
  `install.ps1` detecta Npcap y explica cómo instalarlo. Verificado con el
  `wpcap.dll` de Wine; falta probarlo en un Windows real.
- **Funciones tipo Wireshark en la GUI**: vistas Conversaciones / Paquetes /
  Estadísticas; lista completa de paquetes virtualizada y coloreada por
  gravedad; pestaña «Contenido» (seguir la conversación, texto o hex,
  copiar); estadísticas de protocolos, servicios, equipos que más hablan y
  actividad en el tiempo (con vista de tabla); clic derecho «ver solo /
  ocultar» equipo, puerto, protocolo o conversación (combinable con el
  filtro actual); columnas ordenables; paneles redimensionables; barra de
  estado; historial de filtros; guardar como `.pcap` (Ctrl+S).
- API de la GUI: `/api/stats`, `/api/timeline`, `/api/packets` (paginada),
  `/api/flows/{i}/stream`, `/api/save.pcap`, `/api/live/*`; el filtro, el
  tráfico de fondo y «solo lo importante» se aplican igual a paquetes,
  línea de tiempo y estadísticas.
- DSL: campo `ip.addr` (alias `host`), cualquiera de los dos extremos, como
  en Wireshark.
- `socshark daemon --list` muestra la IP y el estado de cada interfaz.
- **Quién es quién** (ADR-014): cada equipo por su nombre («El equipo
  «iPhone-de-Ana» (192.168.1.30)…», «la impresora «HP OfficeJet Pro 8020»»,
  «el router»), aprendido de DHCP, mDNS, LLMNR y NetBIOS; fabricante por la
  MAC con el registro público del IEEE; MAC aleatorias señaladas; apodos
  propios persistentes («Ponerle nombre»); en vivo, **qué programa** de
  este ordenador abrió cada conexión (Linux y Windows). DHCP, NetBIOS y
  SSDP se cuentan como lo que son. `socshark dev sample-pcap --escenario
  casa` genera una red doméstica para probarlo.
- **Abrir pcapng** (el formato por defecto de Wireshark) en la CLI y la
  GUI, verificado contra pcapng escrito por scapy.
- **Mapa de la red** (vista 4): tus equipos, el router e Internet con quién
  habla con quién; lo peligroso en rojo; clic para filtrar.
- **Avisos en vivo**: aviso en la ventana y notificación del sistema cuando
  aparece algo peligroso o raro; marca «Nuevo» en las historias.
- **Informe** en lenguaje claro (botón *Informe*, `Ctrl+I`, y `socshark
  report -r captura -o informe.html`): HTML de un archivo, sin scripts.
- API de la GUI: `/api/hosts`, `/api/hosts/nick`, `/api/map`,
  `/api/report.html`.
- `socshark-soc::explain`: traductor a lenguaje humano reutilizable
  (semáforo, frases, explicación y «qué hacer» por alerta, historias
  agrupadas, nombres de servicios por puerto/transporte y de resolutores
  DNS conocidos).

### Cambiado

- **`install.ps1`**: banner «SOC SHARK» en letras de bloque; se puede usar
  en una línea con `irm … | iex`; lee el token de `GH_TOKEN` y lo pasa en
  una cabecera, sin guardarlo nunca en `.git/config`; rama o etiqueta
  configurable (`SOCSHARK_REF`); compila solo el binario y con `--locked`.
  El archivo queda en ASCII puro y sin BOM (con BOM, `irm | iex` falla).
- Ayuda de la CLI más clara: ejemplos empezando por la ventana, la TUI y el
  informe; sin referencias internas a fases; `-r` acepta pcap y pcapng.
- Sin permiso de captura, el error dice el comando exacto para darlo
  (`sudo setcap …`) en Linux, y qué hacer en macOS.
- **Logo e interfaz nuevos**: logo de una aleta de tiburón cortando una ola
  (barra, bienvenida, icono de la pestaña e informe). Bienvenida con las dos
  formas de empezar y lo que hace el programa; pestañas de vista con
  icono; buscador con lupa; resumen con icono por gravedad (en gris si no
  hay ninguno); historias con «Qué hacer» destacado; barra adaptable que
  nunca desplaza la ventana en pantallas estrechas.
- Mapa: los nombres de los equipos de casa van a la izquierda de su icono,
  donde las líneas no los tachan.

### Corregido

- `install.ps1`: el banner no mostraba el nombre (se leía «ScSHat»).
- `docs/tui.md` decía que el daemon en vivo aún no existía.
- README: la insignia de CI salía rota porque apuntaba a otro repositorio
  (`soc-shark/soc-shark`); también el `repository` de `Cargo.toml`.
- Iconos de gravedad (✕ ! ✓) descentrados en la leyenda del mapa y, según
  la fuente, en el resto de la ventana: ahora son SVG centrados, también en
  el informe.
- Detalle de un paquete: valores como «443 (HTTPS)» se partían letra a
  letra.
- El DSL reportaba `posición 18446744073709551615` cuando la expresión
  terminaba antes de tiempo; ahora indica el final de la entrada.
- `socshark capture -f` valida el filtro **antes** de leer la captura (un
  error de sintaxis ya no espera a procesar un archivo de varios GB).

- **Mini-IDS: la regla de escaneo no detectaba escaneos de puertos reales.**
  Contaba SYNs por (origen, destino, *mismo* puerto) y descartaba cualquier
  flujo con ACK; un `nmap -sS` de 100 puertos daba 0 alertas (un SYN por
  puerto, y los cerrados responden RST/ACK) y lo que alertaba eran
  reintentos al mismo puerto. Ahora R2 trabaja sobre *sondas fallidas*
  (SYN sin datos ni FIN: sin respuesta, RST/ACK o half-open) y emite
  `PORT-SCAN` (≥ 10 puertos de un host, T1046), `NETWORK-SWEEP` (mismo
  puerto en ≥ 20 hosts, T1046) o, si no llega a escaneo,
  `REPEATED-ATTEMPTS` (≥ 4 intentos al mismo servicio, severidad baja).
  `PipelineConfig::scan_syn_threshold` se sustituye por
  `scan_port_threshold`, `scan_host_threshold` y
  `repeated_attempt_threshold`.
- `INSECURE-PORT` (telnet) y `EXPOSED-DB` ya no saltan con una sonda
  fallida: un SYN sin respuesta al 23 no transporta credenciales.
- Escenario demo: el escaneo pasa a ser de 12 puertos del gateway con
  puertos abiertos, cerrados y filtrados (45 paquetes, 20 flujos).
- **Daemon: sin tráfico no volvía nunca del bucle de lectura.** En Linux el
  timeout de libpcap no garantiza que `pcap_next_ex` regrese, así que
  `--duration`, la expiración de flujos y los informes de estado esperaban
  al siguiente paquete. El handle va ahora en modo no bloqueante con
  `poll` propio sobre `pcap_get_selectable_fd`.
- **Daemon: Ctrl-C/SIGTERM perdían los flujos vivos y el JSONL en búfer.**
  Ahora cierran de forma ordenada exportándolo todo; un segundo Ctrl-C
  fuerza la salida.

- **Captura en vivo: SIGSEGV en la primera llamada a libpcap.** `sym_as`
  convertía la dirección de `dlsym` con `ptr::read(p)`, que lee los primeros
  bytes del *código* de la función en lugar de usar la dirección; ahora usa
  `transmute_copy(&p)`. Afectaba a `daemon -i`, `daemon --list` y a los tests
  de `socshark-capture` en cualquier máquina con libpcap instalada (el CI de
  GitHub fallaba por esto desde la 0.4.0).
- `pcap_activate`: los avisos (`rc > 0`, p. ej. promiscuo no soportado) ya no
  abortan la captura, y los errores genéricos muestran el mensaje de
  `pcap_geterr` en lugar de una cadena vacía.
- `clippy -D warnings` vuelve a pasar en toolchains anteriores a
  `clippy::chunks_exact_to_as_chunks` (p. ej. 1.97): los `allow` incluyen
  `unknown_lints`.
- **Windows: el proyecto no compilaba.** `live.rs` reexportaba dos veces el
  backend stub (E0252) y al stub le faltaba `kernel_stats`. Verificado con
  `clippy` para `x86_64-pc-windows-msvc` y los 152 tests como `.exe`
  (`x86_64-pc-windows-gnu` bajo Wine).
- `install.ps1`: comprueba e instala (winget) las Build Tools de C++ de
  Visual Studio, sin las que `cargo build` falla con `link.exe not found`;
  deja de anunciar el daemon como disponible en Windows (allí solo hay
  stub) y corrige los ejemplos `dev fuzz --iterations` y `follow --flow`.

## [0.6.0] — 2026-10-16

### Añadido (Fase 4, piezas puras: file carving, threat intel, export SIEM)

- **File carving HTTP con detección de encubrimiento T1036**
  (`socshark capture --carve-files`; módulo `socshark-soc::carve`): extrae
  archivos de las respuestas HTTP de los streams TCP reensamblados — cuerpos
  por Content-Length exacto o Transfer-Encoding chunked (reensamblado propio
  de chunks), keep-alive con emparejamiento petición/respuesta en orden,
  tolerancia a cuerpos truncados y respuestas 1xx. Magic bytes propio
  (PE32, ELF, Mach-O, PDF, ZIP/Office, OLE2, GZIP, RAR, 7Z, PNG, JPEG, GIF,
  shebang), SHA-256 reutilizando el motor de JA4 (centralizado en
  `socshark-core::hash`, ADR-011) y **T1036 por dos vías**: magic ≠ extensión
  declarada (un `factura.jpg` que es PE32) y doble extensión ejecutable
  (`informe.pdf.exe`). Selección conservadora (nombre declarado, binario o
  firma conocida; las páginas HTML no tallan) y cota de 8 archivos por flujo.
  Regla `R6` del mini-IDS: `FILE-MASQUERADING` (alta, T1036, +40) y
  ejecutables sin encubrir suman +15 sin alerta. El criterio de fase — un
  ejecutable renombrado a `.jpg` transferido por HTTP genera alerta T1036 —
  queda cubierto por test E2E sobre el escenario demo, que ahora incluye una
  descarga encubierta (33 paquetes, 13 flujos).
- **Threat intel offline** (`--intel-feodo` / `--intel-tor`; módulo
  `socshark-soc::intel`): listas de texto plano cargadas de ficheros locales
  sin conexión saliente. Formato Feodo Tracker (IP o CIDR por línea, v4/v6,
  comentarios `#`) y Tor Bulk Exit List (se extrae la primera IP de cada
  línea). Parser tolerante: comentarios, líneas vacías y basura se saltan sin
  error. El destino de cada flujo se marca en `threat_intel`
  (`FEODO-C2`, `TOR-EXIT`) y la regla `R7` alerta `THREAT-INTEL-FEODO`
  (alta, T1071.001, +45) y `TOR-USAGE` (media, T1090.003 — proxy
  multi-salto, +20). GeoIP/ASN (lector `.mmdb` propio) queda pendiente y
  documentado en el roadmap.
- **Export a SIEM** (`socshark export -r captura.pcap -F ecs|wazuh`; módulo
  `socshark-soc::siem`, contrato completo en `docs/siem-export.md`): mapeo
  **ECS 8.x** (`source/destination/network/dns/tls/threat.technique.id` +
  espacio propio anidado `socshark.*`) y salida **Wazuh** plana
  (`srcip`/`dstip`/`data.*` + `rule.level` 0-15 con mapeo de severidad +
  `rule.mitre.id`), ambas con el pipeline completo detrás (carving e intel
  incluidos si se piden). ISO-8601 propio con el algoritmo civil de Hinnant
  (ADR-012): sin `chrono` para un solo formato.
- **DSL**: campos nuevos `file.count`, `file.name`, `file.magic`,
  `file.masquerading` e `intel.tag`.
- El SHA-256 propio se centraliza en `socshark-core::hash` (antes vivía
  dentro de `socshark-dissectors::tls`): misma implementación, misma
  validación FIPS 180-4, ahora compartida por JA4 y el carving.
- Docs: `soc-features.md` (carving, intel y SIEM implementados),
  `soc-mitre-mapping.md` (T1036, T1071.001 y T1090.003 implementados),
  `data-model.md` (`threat_intel`), `filter-dsl.md` (campos F4),
  `siem-export.md` (nuevo, contrato campo a campo), ADR-012.
- 152 tests (antes 121): SHA-256 en su módulo definitivo, parser de
  respuestas HTTP (chunked, keep-alive, truncados, 1xx, hostiles),
  masquerading por tabla de casos, listas Feodo/Tor (CIDR, tolerancia,
  errores limpios), mapeo ECS/Wazuh e ISO-8601 contra fechas conocidas,
  reglas R6/R7 y cuatro E2E de integración (carving demo, no-carving,
  Feodo sobre el C2 demo, export ECS/Wazuh con MITRE).

## [0.5.0] — 2026-10-16

### Añadido (Fase 3, piezas puras: JA4, beaconing, tipos eBPF)

- **Huella JA4 del ClientHello TLS** según la especificación oficial de
  FoxIO: nuevo módulo `socshark-dissectors::tls` con parser de ClientHello
  (tolera mensajes que cruzan segmentos TCP y registros TLS, acotado a
  16 KiB, sin panics ante entrada malformada) y cálculo completo de
  `t{ver}{sni}{ciphers}{exts}{alpn}_{hash ciphers}_{hash exts+sigalgs}`
  (GREASE ignorado en todo, SNI/ALPN excluidos del hash de extensiones,
  signature algorithms en orden de aparición, ALPN con fallback hexadecimal
  para valores no alfanuméricos). El SHA-256 necesario es implementación
  propia (~80 líneas, ADR-011): cero dependencias nuevas. Validado en CI
  contra los vectores canónicos del spec (`t13d1516h2_8daaf6152771_
  e5627efa2ab1`) y los vectores NIST del SHA-256.
- **SNI del ClientHello** en el campo `tls_sni` del flujo; el enriquecimiento
  lo usa como `resolved_domain` cuando no hubo DNS observable. Campos DSL
  nuevos: `tls.ja4` y `tls.sni` (`==`, `contains`).
- **Detección de beaconing (T1071)**: nueva estadística `IntervalStats` por
  flujo (ventana acotada de 32 intervalos entre paquetes del iniciador,
  tolerante a reordenamiento de captura) y regla `R5` del mini-IDS: alerta
  `BEACONING` con periodo estimado y jitter cuando ≥ 6 intervalos, media
  entre 5 s y 1 h y CV ≤ 0.15 (todo configurable en `PipelineConfig`); el
  ruido de fondo (NTP, mDNS) queda excluido por diseño. Criterio de fase
  cubierto: el beacon demo de 30 s alerta a los 3 min con periodo ±0%.
- **Crate `socshark-ebpf-common`** (Fase 3): tipos compartidos
  probe/userspace `ConnectEvent`, `SocketStateEvent` y `UdpSendEvent` como
  `#[repr(C)]`, sin dependencias y compilable `no_std` (target
  `bpfel-unknown-none`); tamaños, offsets y helpers (`comm_to_str`,
  `tgid_of`) testados. Los probes con aya requieren entorno privilegiado
  (CAP_BPF) y quedan pendientes de él.
- Escenario demo ampliado (29 paquetes, 12 flujos): ClientHello TLS completo
  y realista (produce huella JA4 estable `t13d0208h2_777cda164f4b_af51ac0c444f`
  y SNI) y beacon UDP cada 30 s hacia un C2 simulado (dispara `BEACONING`).
- Docs: `soc-features.md` (JA4 + beaconing), `soc-mitre-mapping.md`
  (T1071 implementado), `data-model.md`, `filter-dsl.md`,
  `ebpf-design.md` (estado real), ADR-011.
- 121 tests (antes 105): vectores JA4/SHA-256, captura del hello partida en
  segmentos, extractor acotado, beaconing positivo/negativo, DSL Fase 3 y
  E2E con huella + beaconing sobre el escenario demo.

## [0.4.0] — 2026-10-16

### Añadido (Fase 2 completa: captura en vivo, pool, fuzzing)

- **Captura en vivo sobre libpcap sin dependencia en tiempo de compilación**
  (ADR-009): FFI propio en `socshark-capture/src/live.rs` que carga libpcap
  con `dlopen` al abrir la interfaz (sonames `libpcap.so.0.8` / `so.1` /
  `so` / `libpcap` en macOS). Sin `libpcap-dev` para compilar y sin crates
  nuevos: si la biblioteca falta, error limpio con instrucciones de
  instalación. Soporta snaplen, modo promiscuo, *immediate mode*, timeout de
  lectura (ticks para el barrido de expiración), **pushdown BPF**
  (`pcap_compile` + `pcap_setfilter`), contadores del kernel (`pcap_stats`)
  y `socshark daemon --list` vía `pcap_findalldevs`.
- **`socshark daemon`**: bucle de captura en vivo real (antes, stub
  informativo). Disección secuencial → agregador con `drain_expired` cada
  `--flush-secs` → enriquecimiento SOC con contexto persistente → JSONL
  incremental (`--json -` para tuberías) y alertas por stderr según
  `--min-risk`/`--show-noise`. Límites `--duration`/`--max-packets` para
  sesiones acotadas y demostraciones.
- **Pool de dissectors concurrente** (ADR-010): `socshark capture
  --workers N` disecciona lotes de 256 paquetes en N hilos y vuelca los
  resultados al agregador en orden estricto. Test E2E garantiza JSONL
  **byte a byte idéntico** al modo secuencial. El payload pasa a
  `Cow<[u8]>`: cero copias en secuencial, una copia solo cuando hay
  paralelismo. Workers murieron → degradación controlada, sin pánico.
- **Fuzzing determinista en proceso**: `socshark dev fuzz --seed S
  --iterations N`. splitmix64 sin dependencias genera el corpus mutando el
  escenario demo (volteo de bits, truncados, basura, zeroizado,
  intercambios y empalmes entre tramas + mentiras de `orig_len`); cada
  iteración recorre *dissector → agregador (con reensamblado) → expiración
  → SOC → filtro DSL*. Un panic imprime semilla e iteración para
  reproducir. Integrado en CI (50 000 iteraciones por build).
- Primitivas de fuzzing en `socshark-testgen::fuzz` (`FuzzRng`,
  `mutate_frame`, `splice_frames`) reutilizables por tests.

### Corregido

- `socshark-soc` (`summarize.rs`): un mensaje DNS con `QDCOUNT=0`
  (malformado pero parseable) panicaba con index-out-of-bounds al
  construir el resumen humano. **El fuzzer lo atrapó en su primera
  ejecución**; corregido y el caso queda cubierto por el corpus.

### Cambiado

- `CaptureSource::next_packet` (documentación del contrato): en captura en
  vivo `Ok(None)` es un *tick* de timeout, no fin de fuente; `Err` es lo
  único fatal. Nuevo error `CaptureError::Live`.
- CI: paso de fuzzing tras el build release.
- `PipelineConfig` gana `workers` (1 = secuencial).

## [0.3.0] — 2026-10-15

### Añadido (Fase 2, parcial: 4/7 según `docs/roadmap.md`)

- **IPv6 completo**: disector con cabeceras de extensión (Hop-by-Hop,
  Routing, Destinos, Fragment —solo primer fragmento— y AH), agregación
  v4/v6 sobre `IpAddr`, campo `ip_version` en `EnrichedFlow`, campo
  `ip.version` en el DSL y **literales IPv6 nativos** sin comillas
  (`ip.dst == 2001:db8::1`).
- **Reensamblado TCP por dirección**: orden de secuencia con aritmética
  serial (RFC 9293 §3.3), base retrocedible para capturas iniciadas a mitad
  de conversación, deduplicación de retransmisiones solapadas, huecos
  marcados (`[N bytes perdidos]`) y tope de 1 MiB por dirección con marcado
  `lossy`. Nuevo comando **`socshark follow`** (texto o `--hex`) con
  contexto del flujo.
- **TUI interactiva** (Ratatui + crossterm, feature `tui` activada por
  defecto): lista Flow-First, panel de alertas SOC, detalle expandible,
  línea de filtro con el DSL completo y ruido atenuado. El modelo
  (`TuiApp`) se testea sin terminal (`socshark tui -r captura.pcap`).
- Pipeline streaming: `drain_expired` ya testado + `collect_streams`
  opt-in en `PipelineConfig` (frontera lista para el daemon en vivo).
- Demo ampliado: intercambio DNS-over-IPv6 con respuesta AAAA (21
  paquetes, 13 flujos, 11 sin ruido).
- testgen: builders IPv6 UDP/TCP con checksum de pseudo-cabecera v6,
  respuestas AAAA y acumulador u64 (soporta segmentos grandes).

### Cambiado

- `FlowAggregator::new(max_flows, idle_timeout_secs, collect_streams)` y
  `finish_with_streams() -> (flujos, streams)`.
- DSL: el lexer acepta `:` en palabras (literales v6); nuevo campo
  `ip.version`; ejemplos de `follow` con el id normalizado.

### Pendiente de Fase 2 (documentado en roadmap)

- Backend de captura en vivo libpcap/AF_XDP: el entorno de build carece de
  libpcap-dev y privilegios; la frontera (`CaptureSource`, stub `daemon`)
  está definida.
- Pool de dissectors concurrente y fuzzing con cargo-fuzz en CI.

## [0.2.0] — 2026-10-15

### Cambiado (reestructuración del workspace, ADR-008)

- Workspace reescrito con 8 crates `socshark-*` de contrato claro:
  `core` (modelo `EnrichedFlow`), `capture` (trait `CaptureSource` + lector
  pcap), `dissectors` (Ethernet/IPv4/TCP/UDP/DNS + heurística L7), `flow`
  (agregador bidireccional), `filter` (DSL), `soc` (ruido, DNS pasivo,
  riesgo/mini-IDS, resúmenes), `testgen` (fixtures) y `cli` (binario
  `socshark`).
- Dependencias externas congeladas en cinco crates auditables: `serde`,
  `serde_json`, `thiserror`, `clap`, `anyhow` (supersede la regla std-only
  de la v0.1; ver [docs/decisions.md](docs/decisions.md)).
- Documentación reescrita desde cero: 11 documentos en `docs/` + registro
  de ADRs (`docs/decisions.md`), con índice y guía de lectura por perfil.
- `EnrichedFlow` serializable con `serde` y JSONL estable como frontera de
  datos entre núcleo y futuras TUI/GUI/daemon.

### Añadido

- CLI `socshark`: `capture` (tabla SOC, `--json` JSONL a fichero o stdout,
  filtro DSL `-f`, `--show-noise`, límites de memoria), `daemon` (stub
  informativo de Fase 2) y `dev sample-pcap` (escenario demo reproducible
  con túnel DNS y escaneo de puertos).
- DSL de filtrado propio con parser por precedencias, ~25 campos de flujo
  y L7, `contains` y atajos de protocolo (`docs/filter-dsl.md`).
- Detecciones SOC: túnel DNS (entropía + longitud), escaneo SYN, telnet y
  bases de datos expuestas, DNS pasivo, Smart Noise Dimming y puntuación
  de riesgo 0-100 (`docs/soc-mitre-mapping.md`).
- 70 tests unitarios y de integración, incluido el barrido anti-panic
  (truncado de tramas) y los tests E2E de la CLI.

### Eliminado (disponible en el tag git `v0.1.0-base`)

- Crates de la v0.1 (`common`, `capture-core`, `dissectors`,
  `flow-aggregator`, `soc-engine`, `filter-dsl`, `storage-index`, `daemon`),
  `apps/`, `plugins-sdk/`, `tools/` y la documentación `00-11` + `adr/`.
- Lectura pcapng, carving de ficheros, export SIEM/ECS, threat intel y TUI:
  volverán por fases según [docs/roadmap.md](docs/roadmap.md).

## [0.1.0] — 2026-10-15 (archivada; código en el tag `v0.1.0-base`)

### Añadido (Fase 1: el motor)

- **Workspace Rust std-only** (ADR-0001) con 8 crates:
  `common`, `capture-core`, `dissectors`, `flow-aggregator`, `soc-engine`,
  `filter-dsl`, `storage-index` y `daemon`.
- Lectura zero-copy de capturas **pcap** (μs/ns, ambos endianness) y
  **pcapng** (SHB/IDB/EPB/SPB, `if_tsresol`) — `capture-core`.
- Ring buffer lock-free SPSC (`SpscRing`) listo para el pipeline paralelo
  de la fase 2.
- Dissectors L2-L7 con slicing comprobado (sin panics sobre entrada
  malformada): Ethernet+VLAN/QinQ, ARP, SLL, IPv4 (fragmentación), IPv6
  (extension headers), ICMP, TCP, UDP, **DNS** (descompresión segura),
  **HTTP/1.1** (sniffing en cualquier puerto), **TLS** (ClientHello +
  fingerprint JA4-like).
- **Flow-First**: `SessionTable` agrupa conversaciones bidireccionales y
  produce `EnrichedFlow` (dominio resuelto, proceso futuro, resumen humano,
  riesgo, alertas, artefactos, offsets mmap-ready).
- **Passive DNS**, **Smart Noise Dimming** (ARP/mDNS/SSDP/NTP/DHCP/NetBIOS)
  y **traducción semántica** de cabeceras a frases legibles.
- Motor SOC: **Live File Carving** (HTTP, SHA-256, magic bytes, Masquerading
  T1036), **C2 Beaconing** (CV de intervalos), **Port Mismatch** (T1071),
  **DNS Tunneling** (T1071.004), **conexión directa por IP** (T1095),
  **TLS sin SNI**, threat intel offline (IP/CIDR) y **exportación ECS** +
  regla Suricata.
- **Filter DSL** estilo Wireshark: lexer + Pratt parser + VM con campos
  booleanos a secas, IPs literales, `contains` y catálogo de campos
  (`soc-shark fields`).
- CLI `soc-shark`: `read` (tabla SOC/radar, `--json`, `--events`, `--filter`,
  `--export-ecs`, `--export-suricata`, `--iocs`, `--min-risk`),
  `fields`, `live` (guía), `info`.
- Escenario demo reproducible: `tools/gen_demo_pcap.py` + lista de IOCs de
  ejemplo (C2 beaconing + Masquerading + DNS tunneling + Tor IOC).
- 99 tests unitarios y de integración, incluido el barrido anti-panic
  (truncado masivo de tramas y entrada aleatoria).

### Notas conocidas

- La captura en vivo y el daemon de privilegios separados llegan en fase 2
  (`soc-shark live` guía la preparación).
- La captura se carga completa en RAM en fase 1; el store mmap está
  diseñado (`storage-index::mmap_store`) para la fase 2.
- `proc.*` y `geo.*` existen en el DSL pero devuelven vacío hasta eBPF/MMDB
  (fase 3).
- Sin `libc`: una tubería cerrada (`| head`) se gestiona vía hook de pánico.
