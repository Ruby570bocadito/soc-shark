# Seguridad de la herramienta

soc-shark procesa datos controlados por atacantes (paquetes de red) y,
además, es una herramienta potente que puede abusarse si se compromete. Este
documento cubre las dos caras: **seguridad frente a los datos** (parsers
robustos, fuzzing) y **seguridad de la herramienta** (modelo de privilegios,
superficie de ataque).

## Modelo de privilegios objetivo

El principio rector: **solo un proceso mínimo toca el kernel; todo lo demás
corre sin privilegios**. No es un lujo arquitectónico: un parser de
protocolos es, estadísticamente, el componente con más bugs por línea de un
analizador de tráfico, y no debe ejecutarse nunca con capacidades del
sistema.

```text
┌────────────────────────────────────────────────────────────────┐
│ KERNEL                                                         │
│   eBPF maps ← probes (connect, socket state, SSL_read/write)   │
└───────▲────────────────────────────────────────────────────────┘
        │ ring buffer (solo lectura de eventos)
┌───────┴──────────────┐          ┌────────────────────────────┐
│ socshark-daemon      │ gRPC/UDS │ socshark-engine (sin caps) │
│ CAP_NET_RAW, CAP_BPF │─────────►│  dissectors + pool         │
│ solo captura         │ eventos  │  SOC/heurísticas           │
│ NO interpreta L7     │ flujos   │  plugins WASM (sandbox)    │
└──────────────────────┘          │  TUI / GUI                 │
                                  └────────────────────────────┘
```

| Componente | Capacidades | Superficie |
|---|---|---|
| `socshark-daemon` (F3) | CAP_NET_RAW, CAP_BPF, sin red saliente, sin disco salvo pidfile | mínima por diseño: solo captura y publicación |
| `socshark-engine` | **ninguna** | parsers, plugins, heurísticas: lo que más falla, menos privilegios |
| UI (TUI/GUI) | solo lectura del engine | aislada por proceso |

### Modelo real hoy (v0.7)

La separación de arriba es el **objetivo**, todavía no está implementada.
Hoy hay captura en vivo (ADR-009) pero **un único binario `socshark`** hace
todo: captura, parsers, heurísticas SOC, TUI y la GUI HTTP local.

- **Linux**: `install.sh` aplica `setcap cap_net_raw,cap_net_admin=ep` al
  binario instalado (desactivable con `SOCSHARK_NO_SETCAP=1`). Esas
  capacidades las tiene **el proceso entero**, parsers y servidor de la GUI
  incluidos, mientras dure. `CAP_NET_RAW` es la que hace falta para abrir la
  captura; `CAP_NET_ADMIN` solo la piden algunos sistemas para el modo
  promiscuo/monitor. Se conceden como *effective + permitted*, sin
  *inheritable*: los programas que lance `socshark` no las heredan.
- **macOS**: sin capacidades; ver la red en vivo requiere `sudo` (o ChmodBPF).
- **Windows**: el binario corre como usuario normal; el permiso de captura lo
  gestiona el driver Npcap.

Quien no quiera que el binario completo tenga esas capacidades puede
instalar con `SOCSHARK_NO_SETCAP=1` y limitarse a abrir archivos `.pcap`, o
capturar con otra herramienta (`dumpcap`, `tcpdump`) y analizar el fichero
después. El trait `CaptureSource` y la frontera de datos (`EnrichedFlow`) ya
están diseñados para que separar el daemon privilegiado del engine sin
privilegios sea un cambio de composición, no una reescritura; es trabajo
futuro (Fase 3).

## Seguridad frente a los datos: parsers hostiles

Los paquetes son entrada no confiable al 100%. Las reglas del código (todas
verificables con grep y exigidas en revisión):

1. **Cero `unwrap`/`expect`/indexing directo en rutas de parseo.** Todo
   acceso a bytes usa `get()`, `try_into()` o comprobaciones explícitas de
   longitud; los casos inválidos devuelven `None`.
2. **Límites anti-explosión.** DNS: máximo 16 preguntas, 64 respuestas, 32
   etiquetas por nombre, 16 saltos de puntero de compresión (mata el bucle
   `0xc00c → 0xc00c`). Pcap: `incl_len` acotado a 256 MiB. Flujos: tabla
   acotada a `max_flows` con expulsión de los más antiguos (que se exportan,
   no se descartan); reensamblado con presupuesto global de 256 MiB y tope de
   segmentos por dirección; estado SOC (escaneos, DNS pasivo, equipos)
   acotado con expulsión de lo menos reciente.
3. **Recorte defensivo de longitudes mentirosas.** `total_len` IPv4,
   `length` UDP y `data_offset` TCP se *clamp*ean contra el tamaño real
   disponible: un paquete crafted que miente sobre su longitud no consigue
   leer fuera de rango ni ocultar datos.
4. **Sin recursión en datos.** La resolución de nombres DNS es iterativa con
   tope de saltos; no hay estructuras recursivas alimentadas por entrada.

### Fuzzing (implementado en Fase 2)

CI ejecuta en cada build el **fuzzer determinista en proceso**
(`socshark dev fuzz --seed S --iterations N`): splitmix64 propio sin
dependencias muta el corpus del escenario demo (volteo de bits, sustitución
de bytes, truncados, basura final, zeroizado de rangos, intercambio de
posiciones y empalmes entre tramas, además de mentiras de `orig_len`) y
hace pasar cada lote por el pipeline completo: *dissector → agregador con
reensamblado → expiración con relojes arbitrarios → enriquecimiento SOC →
evaluación DSL*. La propiedad verificada es *no panic, no hang* sobre toda
la superficie, no solo los parsers. El corpus es reproducible: un fallo
imprime semilla e iteración (`socshark dev fuzz --seed <S> --iterations
<N+1>` lo reconstruye).

Como siguiente nivel de cobertura, `cargo-fuzz`/libFuzzer (cobertura guiada,
instrucciones en CONTRIBUTING.md) cubriría los objetivos por componente:

- `fuzz_parse_dns(payload)`, `fuzz_parse_ipv4(payload)`,
  `fuzz_parse_tcp(payload)`, `fuzz_parse_udp(payload)`,
  `fuzz_parse_ethernet(frame)`.
- `fuzz_pcap(bytes)`: el lector completo con archivos corruptos.
- `fuzz_filter(input)`: el parser del DSL con entrada arbitraria (un DSL es
  también superficie de ataque si se le pegan expresiones hostiles desde un
  SIEM).

Corpus inicial: el generador `socshark-testgen` produce tramas válidas que
sirven de seeds de alta calidad (ya integradas en el fuzzer determinista).

### Captura en vivo: superficie adicional

El backend en vivo (ADR-009) introduce dos superficies propias, ambas
acotadas:

- **FFI libpcap vía dlopen.** Solo se cargan sonames estándar de libpcap
  (en Windows, el `wpcap.dll` de Npcap: primero la ruta absoluta
  `%SystemRoot%\System32\Npcap\wpcap.dll`, para no cargar una DLL
  plantada en el directorio de trabajo) y únicamente se resuelven símbolos
  de la API estable, con firmas auditadas contra `pcap/pcap.h` (y el
  layout de Windows: `timeval` de 32 bits, `pcap_stat` ampliado). Si la
  biblioteca falta o está rota, la apertura falla con error controlado; no
  hay rutas de pánico asociadas al FFI. El handle se usa desde un único
  hilo y `Drop` libera en orden garantizado (`pcap_freecode` → `pcap_close`
  → `dlclose`). La única llamada desde otro hilo es `pcap_breakloop`
  (diseñada para ello), protegida por un cerrojo que `Drop` toma antes de
  cerrar: nunca actúa sobre un handle liberado.
- **Lista de interfaces.** Direcciones y estado se leen de `pcap_addr`/
  `sockaddr` solo para las familias IPv4/IPv6 (desplazamientos fijos por
  plataforma, incluido el `sa_len` de BSD/macOS); cualquier otra familia se
  ignora.
- **Privilegios de captura.** Solo el backend de captura *necesita*
  CAP_NET_RAW (o root), pero hoy comparte proceso con el resto del pipeline:
  con `setcap` las capacidades las tiene todo el binario (ver «Modelo real
  hoy» arriba). En Fase 3 la captura se separará en proceso propio (daemon
  privilegiado + engine sin privilegios). El filtro BPF se compila
  con `pcap_compile` y baja al kernel: el tráfico filtrado no llega
  siquiera al userspace, reduciendo la superficie expuesta a los parsers.

## Superficie de ataque de la propia herramienta

| Vector | Mitigación | Fase |
|---|---|---|
| Pcr corrupto → parser → RCE con privilegios | Rust memory-safe + reglas de parseo + fuzzing + separación daemon/engine | F1 (base) / F3 (separación) |
| Plugins de terceros maliciosos | Sandbox WASM sin red, sin FS, con límite de combustible y firma de autores | F4 |
| Archivo de proyecto malicioso (pcap trampa) | Mismo tratamiento que tráfico en vivo: los parsers no distinguen origen | F1 |
| Exfiltración desde la herramienta (la herramienta ve secretos) | Sin red saliente en el daemon; TLS descifrado solo con opt-in explícito y banner legal | F3 |
| Negación de servicio por explosión de flujos (river of SYNs) | `max_flows` + expulsión LRU + contadores acotados | F1 |
| Deserialización hostil (JSONL de terceros) | `serde` sin `deserialize_any` polimórfico; en F4 el import SIEM valida con esquema estricto | F4 |

### GUI local: superficie adicional

`socshark gui` abre un servidor HTTP en `127.0.0.1` (ADR-013). Lo que podría
atacarlo es una web maliciosa abierta en el mismo navegador o un dato
hostil de la propia captura:

- **CSRF / lectura desde otra web**: toda la API exige un token aleatorio
  de sesión que solo conoce la página servida; al ser una cabecera propia,
  el navegador exige un preflight CORS que el servidor nunca aprueba.
- **DNS rebinding**: se rechaza cualquier petición cuyo `Host` no sea
  exactamente `127.0.0.1:puerto`, `localhost:puerto` o `[::1]:puerto`,
  incluida la página (que contiene el token).
- **Inyección desde la captura** (dominios, rutas, nombres de archivo): el
  frontend nunca usa `innerHTML` con datos y la CSP (`default-src 'none'`,
  solo scripts y estilos propios) impide ejecutar o cargar nada externo.
  Hay prueba de extremo a extremo con un nombre DNS
  `<img src=x onerror=alert(1)>` que recorre todas las vistas (lista de
  paquetes, contenido, estadísticas, menús). La CSP tampoco admite
  `style="…"`: posiciones y anchos se fijan por CSSOM.
- **Captura en vivo desde la ventana**: `POST /api/live/start` exige el
  token como el resto de la API (una web ajena no puede iniciarla). Solo
  escucha; no inyecta tráfico. El tráfico de la propia ventana se excluye
  con BPF. Memoria acotada: 500.000 paquetes / 256 MiB y 20.000
  conversaciones terminadas; lo más antiguo se descarta.
- **Agotamiento**: cabeceras 16 KiB, cuerpo 512 MiB, lecturas con timeout
  de 30 s y tramas en memoria acotadas a 256 MiB. Endurecimiento en curso:
  el cuerpo de una petición solo se lee después de validar `Host` y el
  token (una petición no autenticada no puede hacer subir 512 MiB), tope de
  conexiones concurrentes, y profundidad de anidamiento de los filtros DSL
  limitada a 128 (una expresión con miles de paréntesis no agota la pila).
- **Nombres anunciados por la red** (DHCP, mDNS, LLMNR, NetBIOS): los
  parsers acotan longitudes y opciones y limpian los nombres (solo
  caracteres imprimibles, 63 como mucho) antes de usarlos; son
  informativos y ninguna alerta depende de ellos (un equipo puede mentir).
  Solo se aceptan para direcciones de la red local.
- **Apodos**: se guardan en `apodos.json` en la carpeta de configuración
  del usuario, con escritura atómica; las claves se validan (`mac:…` o
  `ip:…`) y los apodos se limpian (40 caracteres, sin controles). Fichero
  acotado a 2.000 entradas.
- **Programa por conexión**: se lee la tabla de sockets del propio sistema
  (`/proc` en Linux; `GetExtendedTcpTable` y
  `QueryFullProcessImageNameW` en Windows). Solo lectura y solo de esta
  máquina; nada sale de ella.
- **Informe HTML**: todo dato de la captura pasa por un escapado HTML y el
  archivo declara su propia CSP (`default-src 'none'`, sin scripts); hay
  test con nombres DNS y de archivo maliciosos.
- **pcapng**: tamaño de bloque acotado, paquetes de interfaces no
  declaradas rechazados, test que corrompe cada byte del archivo.

## El descifrado TLS y la ética

El módulo de uprobes a `SSL_read/SSL_write` (Fase 3) es la característica más
potente y la más sensible del proyecto. Reglas de diseño que lo acotan:

1. **Opt-in explícito** con flag de línea de comandos dedicado y banner en
   stderr que recuerda la legislación aplicable.
2. **Solo procesos propios**: filtra por PID permitido; nunca intercepta
   procesos de otros usuarios por defecto.
3. **No persistencia por defecto**: el material descifrado vivirá solo en
   memoria de la sesión; un volcado a disco requeriría un flag explícito
   (previsto como `--dump-tls`, **no implementado**: hoy no existe ni el
   descifrado TLS ni ese flag).
4. **Auditoría**: cada activación se registra en el log con timestamp y uid
   del operador.

Ningún diseño técnico convierte una herramienta legítima en un uso legítimo:
la responsabilidad operativa recae en el equipo que la despliega, dentro del
marco legal de su jurisdicción y de su política corporativa de
monitorización (ver README, sección Ética).
