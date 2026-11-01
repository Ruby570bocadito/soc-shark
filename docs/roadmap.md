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
| Atribución de proceso por eBPF | ⏭️ después de la 1.0 (hoy: tabla de sockets) |
| Tauri, plugins WASM, DuckDB | ⏭️ después de la 1.0 |

La **auditoría de octubre de 2026** (ver CHANGELOG, «Sin publicar») cerró
todos los fallos reproducidos:

- caídas por capturas o peticiones manipuladas (*carving* chunked, GUI sin
  autenticar, filtros anidados);
- falsos positivos de túnel DNS;
- fragmentos IPv4 tomados por TCP/UDP;
- el pool de disección, que no paralelizaba;
- endurecimiento de instaladores y CI.

Los tests pasaron de 209 a 281 (304 tras el primer bloque de la 0.8).

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

## Alcance de la 1.0 (decisión de noviembre de 2026)

La hoja de ruta anterior metía en la 1.0 eBPF, un daemon con privilegios
separados, Tauri, plugins WASM, DuckDB, cuatro protocolos nuevos, AF_XDP y
cuatro canales de distribución: años de trabajo para un proyecto pequeño, y
una meta que se alejaba cada vez que se cerraba una casilla.

La 1.0 se redefine como **lo que ya funciona, verificado y accesible**:

1. **Confianza**: lo que dice la herramienta es correcto frente a capturas
   reales (corpus con *golden files*, Wazuh con test de contrato).
2. **Rendimiento suficiente**: el cuello de botella medido (*carving*)
   resuelto y la GUI fluida con miles de flujos.
3. **Accesible**: interfaz en inglés y español, política de seguridad y
   formato de salida versionado.

Todo lo demás pasa a [Después de la 1.0](#después-de-la-10) sin perderse:
son ideas buenas, no requisitos para llamar «terminado» al producto.

## 0.8 — Confianza en los datos

- [x] **Fuzzing guiado por cobertura**: `cargo-fuzz` con 10 objetivos y job
      nocturno en CI (`fuzz/`, `.github/workflows/fuzz.yml`). Destapó la
      reserva de 256 MiB del lector pcap: corregido
- [x] **Túnel DNS por volumen** (`DnsVolumeTracker`)
- [x] **Beaconing con jitter aleatorizado** (mediana + MAD)
- [x] Validación de ECS contra el esquema oficial (v8.11) en CI
- [x] `refuse_overwrite` para enlaces duros; rechazos completos en la GUI
- [x] **Arnés del corpus** (`corpus/`, test `corpus`): cada captura declara
      su verdad de campo (reglas que *deben* saltar y que *no deben*) y un
      *golden file* con el resultado esperado; `SOCSHARK_BLESS=1` lo
      regenera. Sembrado con los escenarios sintéticos de `socshark-testgen`
- [x] **Test de contrato Wazuh**: forma del JSON fijada en un test y
      `docs/wazuh/local_rules.xml` listo para copiar
- [ ] **Capturas reales en el corpus** (públicas y sin datos personales:
      ejemplos de Wireshark, Malware-Traffic-Analysis, CICIDS). Ver
      [corpus/README.md](../corpus/README.md). Al menos un verdadero
      positivo real por regla. *Primer bloque hecho:* 12 capturas del wiki
      de Wireshark con la verdad de campo escrita antes de pasarlas. Dieron
      2 falsos positivos High (DNS-TUNNELING con el localizador de AD,
      FILE-MASQUERADING con HTML comprimido), ya corregidos; INSECURE-PORT
      tiene 3 verdaderos positivos reales; y la shell remota en el puerto
      53, que no detectaba nada, dio lugar a la regla `NON-DNS-ON-53`
      (T1571; 1 VP real, 0 FP). Sigue como fallo conocido la shell en el
      puerto 80. *Pendiente:* capturas de ataques reales para el resto de
      reglas (escaneo, túnel, beacon, T1036)
- [ ] `local_rules.xml` probado contra un manager de laboratorio en Docker
      (`wazuh-logtest`)

**Criterio:** el corpus real no da falsos positivos High y cada regla tiene
al menos un verdadero positivo real.

## 0.9 — Rendimiento suficiente

- [x] Banco reproducible (`socshark dev bench`) con umbral en CI
- [x] **Optimizar el *carving***: el coste era casi todo SHA-256 de los
      cuerpos tallados (que además copiaba el cuerpo entero) y una búsqueda
      byte a byte. Ahora SHA-256 sin copia, búsqueda por primer byte (~4,7×)
      y flujos tallados en paralelo. La etapa pasó de ~0,6 s a ~0,15 s con
      1M paquetes; `dev bench` (500k paquetes, Windows, 12 núcleos) de
      ~350k a ~450-510k paquetes/s
- [x] Presupuesto de reensamblado configurable (`--stream-budget-mib`) y
      tallado temprano: al pasar de la mitad del presupuesto se tallan y
      liberan los streams de las conexiones ya cerradas. Con 1M paquetes
      `dev bench` talla 9 000 archivos en vez de 4 500 (el resto se perdía
      sin avisar). Siguen faltando ~1 000 en ese caso extremo, con 20 000
      conexiones abiertas a la vez
- [x] GUI fluida con 10 000 flujos: `/api/flows` sin árbol `Value`
      (~13× más rápido) y tabla pintada por trozos con el orden memorizado;
      ningún bloqueo de la ventana pasa de ~80 ms (el `JSON.parse`)
- [x] TUI con 10 000 flujos: solo se construyen las filas que caben y el
      panel de alertas se calcula al cambiar el filtro, no en cada
      fotograma. 7,4 → 0,4 ms por fotograma (50 → 0,4 ms con 20 000
      alertas)
- [ ] Captura en vivo probada a mano en Windows + Npcap, Linux y macOS.
      *Hecho:* Windows 11 **sin** Npcap (el caso más común al pulsar «En
      vivo» por primera vez): la CLI y la GUI lo explican y la GUI enlaza
      la descarga, en español y en inglés. *Pendiente:* capturar de verdad
      con Npcap instalado, y Linux y macOS

**Criterio:** 10 000 flujos se abren y filtran sin bloqueos perceptibles;
captura en vivo verificada en los tres sistemas.

## 1.0 — Producto

- [x] Política de seguridad ([SECURITY.md](../SECURITY.md)) con canal de
      reporte y plazos
- [x] **Formato JSONL versionado**: cada flujo lleva `schema_version`; los
      cambios incompatibles suben su número mayor (ver
      [data-model.md](data-model.md))
- [x] **Interfaz en inglés y español**: la GUI con selector de idioma
      (frases, historias, paquetes, estadísticas, mapa e informe), sin
      tocar el JSONL ni los `alert.id` (ADR-015). La TUI, los mensajes de
      la CLI y `socshark report` siguen en español por ahora
- [ ] Probar los instaladores en limpio: Windows 11 (PowerShell 5.1),
      Ubuntu, Fedora y macOS
- [ ] Release desde el flujo de Actions con todo lo anterior

**Criterio:** una persona sin conocimientos técnicos instala la app, abre
una captura y entiende las tres primeras historias sin ayuda (prueba con
5 personas, en inglés o en español).

---

## Después de la 1.0

Ordenado por valor estimado. Ninguno bloquea la 1.0.

### 1.x — Mejoras incrementales

- `--workers N` que gane a un hilo (paralelizar el agregador por hash de
  flujo o eliminar la copia `into_owned`)
- ≥ 200 Mbps sostenidos en vivo con < 0,1 % de pérdidas
- Rotación del JSONL del daemon; unidad systemd y servicio de Windows
- GeoIP/ASN offline con lector `.mmdb` propio
- Salida Sigma o Suricata EVE; push a TheHive
- Distribución: winget, Homebrew, `.deb`/`.rpm`
- Releases firmados (Authenticode, notarización, SLSA, `SHA256SUMS` firmado)

### 2.0 — Arquitectura

- **Privilegios separados**: `socshark-capture-helper` mínimo con
  `cap_net_raw` y parsers sin capacidades (ver [security.md](security.md))
- **eBPF**: probes con aya (`tcp_v4_connect`, `inet_sock_set_state`,
  `udp_sendmsg`) y atribución de proceso antes del primer paquete
  (hoy se atribuye con la tabla de sockets del sistema). Tipos ya listos en
  `socshark-ebpf-common`
- Atribución en macOS
- **Plugins WASM** con la API de [wasm-plugins.md](wasm-plugins.md)
- Sesiones persistentes (DuckDB o Parquet)
- Más protocolos: QUIC, HTTP/2, SMB2, RDP, Kerberos
- GUI empaquetada con Tauri; SequenceView; decodificador tipo CyberChef
- AF_XDP en Linux

## Fuera de alcance (declarado)

- Captura inalámbrica (802.11): requiere otro stack de radios; quizá como
  proyecto hermano.
- Interceptar o bloquear tráfico: soc-shark es solo lectura por diseño.
- Sustituir el SIEM: soc-shark alimenta SIEMs, no los reemplaza.
