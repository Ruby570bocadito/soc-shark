# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y [SemVer](https://semver.org/lang/es/).

## [Sin publicar]

### Rendimiento

- **GUI fluida con 10 000 conversaciones**: `/api/flows` se serializa sin
  construir un árbol `Value` (~400 ms → ~30 ms para 16 MB) y la tabla se
  pinta por trozos cediendo el turno entre uno y otro, con el orden
  memorizado (las flechas ya no reordenan 10 000 filas en cada pulsación).
  Volver a ver las 10 000 tras un filtro: 726 → 409 ms hasta la última
  fila y el bloqueo más largo de la ventana de 190 a 77 ms.
- **TUI fluida con 10 000 conversaciones**: cada fotograma construía las
  10 000 líneas y el panel de alertas (dos veces). Ahora solo las filas
  que caben, con un desplazamiento que sigue a la selección, y las alertas
  se calculan al aplicar el filtro: 7,4 → 0,4 ms por fotograma, y de 50 a
  0,4 ms con 20 000 alertas (antes, mantener pulsada `j` daba tirones).

## [0.8.0] — 2026-11-01

### Añadido (interfaz bilingüe)

- **GUI en inglés y español** (ADR-015): selector ES/EN en la barra de
  herramientas que cambia toda la ventana sin volver a abrir la captura
  (barra, vistas, historias, explicaciones, paquetes y capas,
  estadísticas, mapa, ayuda, glosario e informe). Se recuerda el idioma
  elegido y, la primera vez, se usa el del navegador si es inglés.
- `socshark_soc::Lang`, la macro `tr!` y las variantes `*_in(…, lang)` de
  los textos del motor (`explain_in`, `stories_in`, `summarize_in`,
  `alert_name_in`, `alert_detail_in`…). La API de la GUI acepta la
  cabecera `X-Socshark-Lang` (o `?lang=`).

### Sin cambios (interfaz bilingüe)

- El JSONL, ECS, Wazuh, los `alert.id` y el `human_summary` exportado
  siguen en español (`schema_version` 1). La TUI, la CLI y `socshark
  report` también.

### Alcance de la 1.0

- La hoja de ruta se recorta: la 1.0 es lo que ya funciona, verificado y
  accesible. eBPF, privilegios separados, Tauri, WASM, DuckDB, protocolos
  nuevos y distribución por gestores de paquetes pasan a «Después de la
  1.0» (`docs/roadmap.md`).

### Añadido (hoja de ruta 0.8, segundo bloque)

- **Corpus de verificación** (`corpus/`): cada captura declara las reglas
  que deben saltar y las que no, y guarda el resultado esperado en un
  *golden file*. El test `corpus` corre en cada `cargo test`;
  `SOCSHARK_BLESS=1` regenera los golden y `scripts/fetch_corpus.py` baja
  las capturas reales comprobando su SHA-256. Sembrado con seis escenarios
  sintéticos.
- **Reglas Wazuh listas para copiar** (`docs/wazuh/local_rules.xml`): nivel
  por severidad, una regla por técnica MITRE con su bloque `<mitre>` y
  subida a 12 para destinos en threat intel. Test de contrato
  (`wazuh_contract`) que fija la forma del JSON y falla si una técnica o un
  nivel se queda sin regla.
- **`schema_version` en el JSONL** (`capture --json`, daemon): contrato
  versionado de la salida (`docs/data-model.md`).
- **`SECURITY.md`**: canal privado de reporte, plazos y alcance.

### Rendimiento

- *Carving* unas 4 veces más rápido: SHA-256 sin copiar el cuerpo entero,
  búsqueda de cabeceras HTTP por primer byte (~4,7×) y flujos tallados en
  paralelo (resultado idéntico al secuencial, con test). `dev bench`:
  ~350k → ~450-510k paquetes/s.
- **Presupuesto de reensamblado configurable** (`--stream-budget-mib` en
  `capture` y `export`, 256 por defecto) y **tallado temprano**: cuando el
  presupuesto pasa de la mitad, las conexiones ya cerradas (FIN en las dos
  direcciones o RST, y 5 s sin paquetes) se tallan y sueltan su memoria.
  El flujo sigue en la tabla, así que el resultado es el mismo que con un
  presupuesto infinito (test con 1 MiB, 1 y 4 hilos). Antes, con 1M
  paquetes se perdía la mitad de los archivos sin avisar.

### Hoja de ruta 0.8 (primer bloque)

- **Túnel DNS por volumen**: muchos subdominios únicos de un mismo dominio
  por cliente (dnscat2/iodine con codificaciones de baja entropía).
- **Beaconing con jitter aleatorio** (hasta ±50%, p. ej. Cobalt Strike):
  mediana + MAD sobre los intervalos reales, dentro de un flujo y entre
  conexiones (`IntervalStats` gana `median_micros`, `mad_micros` e
  `in_band_permille`, compatibles con JSONL anteriores).
- **Fuzzing guiado por cobertura** (`fuzz/`, job nocturno) y validación del
  export **ECS contra el esquema oficial** en CI.
- **`socshark dev bench`**: banco de rendimiento reproducible con job de CI.
- Corregido: el lector pcap/pcapng reservaba la longitud declarada antes de
  leer (40 bytes → 256 MiB); ECS emitía `flow.id` y `tls.ja4`, que no
  existen en el esquema (ahora `socshark.flow_id` y `socshark.tls_ja4`);
  `refuse_overwrite` detecta enlaces duros; los rechazos de la GUI llegan
  completos en vez de como *reset*; lotes del pool de 256 a 4096 paquetes.

Auditoría de robustez y seguridad: todos los fallos se reprodujeron con una
captura o petición fabricada y tienen test de regresión (209 → 281 tests).

### Seguridad

- **GUI**: el cuerpo de una petición se leía (hasta 512 MiB) antes de
  comprobar `Host` y token; cualquier proceso local podía tumbar la ventana
  agotando la memoria. Ahora se autoriza antes de leer, solo `POST /api/open`
  admite cuerpos grandes (el resto, 64 KiB), una subida a la vez y como
  mucho 64 conexiones.
- **GUI**: el archivo temporal de subida tenía nombre predecible (ataque por
  enlace simbólico en Linux): ahora es aleatorio y se crea con `create_new`
  (0600).
- **Filtro DSL**: un filtro con ~2 000 paréntesis desbordaba la pila y
  abortaba el proceso. Límite de 128 niveles y 4 096 tokens, y cadenas
  `&&`/`||` en árbol equilibrado.
- **Terminal**: nombres DNS, SNI y alertas se imprimían con caracteres de
  control (inyección de secuencias de escape); ahora se escapan, también los
  de dirección bidi.
- **Carga de libpcap**: sin búsqueda en la carpeta del programa en Windows
  (`LOAD_LIBRARY_SEARCH_SYSTEM32`) y rutas absolutas en macOS.
- **Instaladores**: `setcap` sin el bit heredable (`=ep`), solo descargas
  HTTPS, el token de git ya no aparece en la línea de órdenes y el PATH de
  Windows conserva sus `%VARIABLES%`. Actions fijadas por SHA y versiones de
  `cargo-zigbuild`/`ziglang` fijadas.

### Corregido

- **Pánico** en el *carving* con un chunk HTTP de tamaño `ffffffffffffffff`:
  tumbaba `gui -r`, `report` y `capture --carve-files`.
- **Falsos positivos DNS-TUNNELING** con nombres normales
  (`settings-win.data.microsoft.com`): la entropía se mide ahora sobre el
  subdominio a la izquierda del dominio registrable. MITRE corregido a
  **T1071.004**.
- Fragmentos IPv4 no iniciales y ethertypes que no son IPv4 ya no se
  interpretan como TCP/UDP; `total_len = 0` (TSO) usa la longitud capturada.
- DNS con bytes no UTF-8 ya no se descarta entero (evasión de túnel).
- TLS: JA4 con ClientHello sin extensiones, partido en varios registros o con
  segmentos fuera de orden/retransmitidos.
- `--workers N` no paralelizaba nada y se colgaba si un hilo caía.
- Flujos expulsados por memoria ahora se exportan; presupuesto global de
  reensamblado; retransmisiones solapadas distintas marcan `lossy`;
  `dns.qname` acumula todas las consultas (máx. 64).
- *Carving*: nombre de archivo desalineado tras un 304 (falso T1036),
  instaladores versionados marcados como doble extensión, búsqueda cuadrática.
- Ruido UDP por puerto de origen ocultaba C2; DNS pasivo aceptaba registros
  fuera de la cadena CNAME; estado del daemon sin límite.
- ECS: `network.direction` calculado, `event.kind: alert`, MAC en formato ECS.
- Threat intel: comprueba origen y destino, tolera bytes no UTF-8 y rechaza
  redes más amplias que /8 (v4) o /16 (v6).
- Códigos de salida: `export` con fallo de escritura, error fatal del daemon y
  `tui` sin la *feature* ya no salen con 0; `| head` ya no provoca pánico.
- TUI: el filtro `-f` inicial se puede quitar y la terminal se restaura si
  algo falla.
- Se niega a sobrescribir la captura de entrada con `-o`/`--json`.

### Añadido

- Beaconing **entre conexiones** (beacons más lentos que el timeout de
  inactividad).
- Disección de Linux *cooked* (SLL/SLL2) y loopback (NULL/LOOP), y QinQ.
- Fuzzer: escenarios hostiles (chunked, fragmentos, TLS partido) y el
  *carving* dentro del recorrido.
- CI en Windows y macOS, permisos mínimos y comprobación de MSRV.

### Cambiado

- **MSRV 1.88** (lo que exige el `Cargo.lock` real; antes decía 1.75).

## [0.7.0] — 2026-10-20

### Añadido

- **Binarios ya compilados en cada release** (`.github/workflows/release.yml`):
  un botón («Run workflow» en Actions → Release) pasa los tests, compila
  `socshark` para Windows x86_64, Linux x86_64 y ARM64 (glibc 2.17: cualquier
  distribución de los últimos diez años) y macOS universal, crea la etiqueta
  `vX.Y.Z` de la versión del `Cargo.toml` y publica el release con
  `SHA256SUMS` y las notas de este CHANGELOG. También se lanza al subir una
  etiqueta.
- **Instalación en una línea que no compila**: `install.ps1` e `install.sh`
  descargan el binario del último release, comprueban su SHA-256 y lo
  instalan en segundos, sin Rust ni Build Tools. Si no hay binario para el
  sistema, o no arranca, lo compilan desde el código como antes.
  `SOCSHARK_VERSION` elige versión y `SOCSHARK_FROM_SOURCE=1` fuerza
  compilar.
- **Instalador para Linux** (`install.sh`, también macOS): `curl -fsSL … |
  bash`. Instala en `~/.local/bin`, añade libpcap si falta (apt, dnf, yum,
  pacman, zypper o apk) y da al binario el permiso de captura
  (`cap_net_raw,cap_net_admin`): **la red en vivo funciona sin sudo**. Desde
  una copia del repositorio compila esa copia.
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

- **Instaladores en inglés y sin ruido**: solo muestran lo necesario (unas
  diez líneas al descargar el binario); ni la salida del compilador ni la
  tabla del análisis de prueba, que queda en una línea («Self-test
  passed»), y tres comandos para empezar en vez de diez.
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
  *(Nota posterior: entrada histórica. El subcomando `read` y esos flags ya
  no existen con ese nombre: hoy el análisis de una captura es
  `socshark capture -r <pcap>` (con `--json`, `--filter`, `--intel-*`) y la
  exportación SIEM es `socshark export` (ECS o Wazuh). Ver
  `socshark --help`.)*
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
