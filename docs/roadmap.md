# Hoja de ruta

La regla del proyecto: **una fase no se da por cerrada si su criterio falla**,
aunque el código exista. Cada hito tiene criterios de aceptación verificables
y el estado se mantiene en este documento, en el README y en el CHANGELOG.

## Dónde estamos (0.7.x)

| Área | Estado |
|---|---|
| Lectura pcap/pcapng, disectores (Ethernet/VLAN/QinQ, SLL, IPv4/IPv6, TCP, UDP, DNS, TLS) | ✅ estable |
| Flujos, reensamblado TCP, *Follow stream* | ✅ estable |
| Motor SOC: túnel DNS, escaneos, beaconing, T1036, threat intel offline | ✅ estable |
| CLI, informe HTML, export ECS/Wazuh | ✅ estable |
| GUI local y TUI | ✅ estable |
| Captura en vivo (libpcap/Npcap) | 🟡 funciona; falta medir rendimiento en hardware real |
| Atribución de proceso por eBPF | 🔴 solo los tipos compartidos |
| Tauri, plugins WASM, DuckDB | 🔴 sin empezar |

La **auditoría de octubre de 2026** (ver CHANGELOG, «Sin publicar») cerró
todos los fallos reproducidos:

- caídas por capturas o peticiones manipuladas (*carving* chunked, GUI sin
  autenticar, filtros anidados);
- falsos positivos de túnel DNS;
- fragmentos IPv4 tomados por TCP/UDP;
- el pool de disección, que no paralelizaba;
- endurecimiento de instaladores y CI.

Los tests pasaron de 209 a 281.

---

## Historial de fases (resumen)

- **Fase 0 — Fundaciones** ✅ Workspace multi-crate, `EnrichedFlow`
  serializable, CI con fmt/clippy/test, generador `socshark-testgen`.
- **Fase 1 — MVP sobre pcap** ✅ Lector pcap propio, disectores, agregador
  de flujos, DSL de filtrado, capa SOC con riesgo 0-100, CLI `capture`.
- **Fase 2 — En vivo + TUI** ✅ Captura en vivo por FFI + `dlopen`
  (ADR-009), daemon en streaming, pool de disectores (ADR-010), TUI Ratatui,
  IPv6 completo, reensamblado TCP, fuzzing determinista en CI. *Pendiente:
  el criterio de rendimiento (ver 0.9).*
- **Fase 3 — eBPF y detección avanzada** 🟡 JA4 (spec FoxIO, vectores
  canónicos en CI) y beaconing (R5, también entre conexiones) hechos;
  `socshark-ebpf-common` listo. *Pendiente: probes, daemon separado y
  atribución de proceso (ver 0.10).*
- **Fase 4 — GUI, plugins y export** 🟡 *Carving* HTTP + T1036, threat
  intel offline, ECS/Wazuh, GUI completa (en vivo, quién es quién, mapa,
  informe), pcapng. *Pendiente: Tauri, WASM y DuckDB (ver 0.11).*

---

## 0.7.1 — Parche de seguridad (rama `fix/auditoria-0.7`)

Objetivo: publicar ya la auditoría, porque varios fallos tumban la app con
una captura ajena.

- [x] Todos los fallos reproducidos, corregidos y con test de regresión
- [x] Fuzzer con escenarios hostiles (chunked, fragmentos, TLS partido) y
      *carving* dentro del recorrido
- [x] CI en Windows y macOS, MSRV real (1.88), actions fijadas por SHA
- [ ] Probar los instaladores en limpio: Windows 11 con PowerShell 5.1,
      Ubuntu, Fedora y macOS (actualizar con la GUI abierta debe fallar con
      mensaje claro)
- [ ] Pasar `shellcheck install.sh` (en local no estaba disponible)
- [ ] Release 0.7.1 desde el flujo de Actions

**Criterio:** CI verde en los tres sistemas. Las reproducciones de la
auditoría (`chunked_overflow.pcap`, 100 conexiones hostiles, filtro con
7 000 paréntesis) no tumban ni `report` ni `gui`.

## 0.8 — Confianza en los datos

Objetivo: que lo que dice la herramienta sea correcto y verificable frente a
la realidad.

- [ ] **Fuzzing guiado por cobertura**: `cargo-fuzz` con objetivos por
      parser (DNS, IPv4/6, TCP, TLS, pcapng, *carving*, DSL, HTTP de la GUI)
      y un job nocturno en CI con el corpus persistido
- [ ] **Corpus de capturas reales** (sin datos personales: capturas públicas
      de Wireshark, Malware-Traffic-Analysis, CICIDS) con resultados
      esperados en *golden files*. Cada regla del mini-IDS se mide en
      verdaderos y falsos positivos
- [ ] **Túnel DNS por volumen**: muchos subdominios únicos por dominio base
      (contador entre flujos, acotado). Hoy solo se mira la entropía por
      consulta
- [ ] **Beaconing con jitter aleatorizado** (CV alto): detección por
      periodograma o histograma de intervalos
- [ ] **Wazuh verificado**: `local_rules.xml` probado contra un manager de
      laboratorio en Docker y test de contrato del JSON de salida
- [ ] Validación de ECS contra el esquema oficial de Elastic en CI
- [ ] `refuse_overwrite` también para enlaces duros (identificador de archivo
      por sistema)
- [ ] La GUI, al rechazar sin leer el cuerpo, debe responder 403/413 antes
      de cerrar; hoy en Windows el cliente puede recibir un *reset*

**Criterio:** el corpus real no da falsos positivos High; cada regla tiene
al menos un verdadero positivo real; 24 h de fuzzing guiado sin hallazgos.

## 0.9 — Rendimiento y operación en vivo

Objetivo: cerrar el criterio pendiente de la Fase 2.

- [ ] Banco de rendimiento reproducible (`socshark dev bench` sobre una
      captura grande sintética) en CI, con umbral de regresión
- [ ] **≥ 200 Mbps sostenidos** en vivo en un portátil de referencia
      (Windows + Npcap y Linux), sin pérdidas del kernel
- [ ] TUI y GUI fluidas con 10 000 flujos (lista virtualizada, perfilado
      del JSON)
- [ ] Captura en vivo probada en hardware real en los tres sistemas. Hoy:
      Windows solo con el `wpcap.dll` de Wine, y macOS sin probar tras
      cambiar a rutas absolutas
- [ ] Rotación de la salida JSONL del daemon y unidad systemd y servicio de
      Windows de ejemplo
- [ ] AF_XDP como backend de alto rendimiento en Linux (opcional, detrás de
      *feature*)

**Criterio:** 200 Mbps durante 10 min con < 0,1 % de pérdidas y memoria
estable (sin crecer) en las tres plataformas.

## 0.10 — Atribución de proceso y privilegios mínimos (Fase 3)

Objetivo: la característica diferencial y el modelo de privilegios que
promete `docs/security.md`.

- [ ] **Separar privilegios**: `socshark-capture-helper` mínimo con
      `cap_net_raw` (sin parsers), y el resto sin capacidades. El instalador
      deja de dar `setcap` al binario completo
- [ ] Probes eBPF con aya: `tcp_v4_connect`, `inet_sock_set_state`,
      `udp_sendmsg`
- [ ] Correlación de la *cookie* de socket con (pid, exe, uid) en el
      enriquecedor; columnas Proceso/Usuario en TUI, GUI y JSONL
- [ ] Atribución en macOS (`proc_pidfdinfo` o `nettop`) para igualar
      Linux y Windows

**Criterio:** un flujo de `curl` muestra `process_name=/usr/bin/curl` antes
de que el primer paquete llegue al disector; los parsers corren sin ninguna
capacidad (comprobado con `getpcaps`).

## 0.11 — Ecosistema (Fase 4)

- [ ] **Plugins WASM** (wasmtime) con la API WIT de
      [wasm-plugins.md](wasm-plugins.md): límite de *fuel*, firma Ed25519 y
      dos plugins oficiales (HTTP y SMB)
- [ ] **Sesiones persistentes** (DuckDB o Parquet) y consultas analíticas
      entre capturas
- [ ] GeoIP/ASN offline con un lector `.mmdb` propio → `dst_geo_asn`
- [ ] Más protocolos: QUIC (JA4 de QUIC), HTTP/2 con SNI/ALPN, SMB2, RDP,
      Kerberos (para detecciones de movimiento lateral)
- [ ] Push a TheHive y salida Sigma o Suricata EVE

**Criterio:** un plugin comunitario corre en sandbox y enriquece flujos
reales; un Wazuh de laboratorio recibe flujos con etiquetas ATT&CK
correctas.

## 1.0 — Producto

- [ ] GUI empaquetada (Tauri) con instalador firmado; SequenceView de
      handshakes y decodificador estilo CyberChef
- [ ] **Interfaz en inglés y español** (hoy solo español) y documentación
      completa en inglés
- [ ] Distribución: winget, Homebrew, `.deb`/`.rpm`, actualización
      automática opcional
- [ ] **Releases firmados**: firma de los binarios (Authenticode en Windows,
      notarización en macOS), procedencia SLSA y `SHA256SUMS` firmado (hoy
      solo garantiza integridad, no autenticidad)
- [ ] Política de seguridad (`SECURITY.md`) con canal de reporte y SLA
- [ ] API estable del JSONL y del DSL con versionado semántico

**Criterio:** una persona sin conocimientos técnicos instala la app, abre
una captura y entiende las tres primeras historias sin ayuda (prueba de
usabilidad con 5 personas).

---

## Fuera de alcance (declarado)

- Captura inalámbrica (802.11): requiere otro stack de radios; quizá como
  proyecto hermano.
- Interceptar o bloquear tráfico: soc-shark es solo lectura por diseño.
- Sustituir el SIEM: soc-shark alimenta SIEMs, no los reemplaza.
