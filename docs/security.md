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

En Fase 1 la separación no existe todavía porque no hay captura en vivo: el
binario lee archivos y no pide ninguna capacidad. El trait `CaptureSource` y
la frontera de datos (`EnrichedFlow`) ya están diseñados para que la
separación sea un cambio de composición, no una reescritura.

## Seguridad frente a los datos: parsers hostiles

Los paquetes son entrada no confiable al 100%. Las reglas del código (todas
verificables con grep y exigidas en revisión):

1. **Cero `unwrap`/`expect`/indexing directo en rutas de parseo.** Todo
   acceso a bytes usa `get()`, `try_into()` o comprobaciones explícitas de
   longitud; los casos inválidos devuelven `None`.
2. **Límites anti-explosión.** DNS: máximo 16 preguntas, 64 respuestas, 32
   etiquetas por nombre, 16 saltos de puntero de compresión (mata el bucle
   `0xc00c → 0xc00c`). Pcap: `incl_len` acotado a 256 MiB. Flujos: tabla
   acotada a `max_flows` con expulsión de los más antiguos.
3. **Recorte defensivo de longitudes mentirosas.** `total_len` IPv4,
   `length` UDP y `data_offset` TCP se *clamp*ean contra el tamaño real
   disponible: un paquete crafted que miente sobre su longitud no consigue
   leer fuera de rango ni ocultar datos.
4. **Sin recursión en datos.** La resolución de nombres DNS es iterativa con
   tope de saltos; no hay estructuras recursivas alimentadas por entrada.

### Plan de fuzzing (Fase 2)

Los parsers son objetivos ideales para `cargo-fuzz`:

- `fuzz_parse_dns(payload)`, `fuzz_parse_ipv4(payload)`,
  `fuzz_parse_tcp(payload)`, `fuzz_parse_udp(payload)`,
  `fuzz_parse_ethernet(frame)`: objetivo *no crash, no hang* en cualquier
  entrada.
- `fuzz_pcap(bytes)`: el lector completo con archivos corruptos (seeds del
  generador de la suite).
- `fuzz_filter(input)`: el parser del DSL con entrada arbitraria (un DSL es
  también superficie de ataque si se le pegan expresiones hostiles desde un
  SIEM).

Corpus inicial: el generador `socshark-testgen` produce tramas válidas que
sirven de seeds de alta calidad. El gate de CI se añadirá junto con el
objetivo de fuzz en Fase 2.

## Superficie de ataque de la propia herramienta

| Vector | Mitigación | Fase |
|---|---|---|
| Pcr corrupto → parser → RCE con privilegios | Rust memory-safe + reglas de parseo + fuzzing + separación daemon/engine | F1 (base) / F3 (separación) |
| Plugins de terceros maliciosos | Sandbox WASM sin red, sin FS, con límite de combustible y firma de autores | F4 |
| Archivo de proyecto malicioso (pcap trampa) | Mismo tratamiento que tráfico en vivo: los parsers no distinguen origen | F1 |
| Exfiltración desde la herramienta (la herramienta ve secretos) | Sin red saliente en el daemon; TLS descifrado solo con opt-in explícito y banner legal | F3 |
| Negación de servicio por explosión de flujos (river of SYNs) | `max_flows` + expulsión LRU + contadores acotados | F1 |
| Deserialización hostil (JSONL de terceros) | `serde` sin `deserialize_any` polimórfico; en F4 el import SIEM valida con esquema estricto | F4 |

## El descifrado TLS y la ética

El módulo de uprobes a `SSL_read/SSL_write` (Fase 3) es la característica más
potente y la más sensible del proyecto. Reglas de diseño que lo acotan:

1. **Opt-in explícito** con flag de línea de comandos dedicado y banner en
   stderr que recuerda la legislación aplicable.
2. **Solo procesos propios**: filtra por PID permitido; nunca intercepta
   procesos de otros usuarios por defecto.
3. **No persistencia por defecto**: el material descifrado vive en memoria
   de la sesión salvo `--dump-tls` explícito.
4. **Auditoría**: cada activación se registra en el log con timestamp y uid
   del operador.

Ningún diseño técnico convierte una herramienta legítima en un uso legítimo:
la responsabilidad operativa recae en el equipo que la despliega, dentro del
marco legal de su jurisdicción y de su política corporativa de
monitorización (ver README, sección Ética).
