# Arquitectura

## El problema que resolvemos

Un analista de SOC frente a Wireshark sufre tres fricciones estructurales que
ninguna configuración resuelve, porque son de diseño y no de pulido. Primera:
el modelo mental es *paquete-céntrico*, cuando la pregunta de seguridad es
*sesión-céntrica*; seguir una intrusión en una lista de miles de paquetes es
trabajo arqueológico. Segunda: no existe la noción de *relevancia*: un mDNS y
una exfiltración por DNS ocupan el mismo espacio visual y el mismo peso
cognitivo. Tercera: el analista no puede responder *«¿qué proceso hizo
esto?»* porque Wireshark vive en el userspace sin visibilidad del kernel.

soc-shark ataca las tres fricciones desde la arquitectura: el tipo de datos
central es el **flujo enriquecido** (`EnrichedFlow`), la capa SOC clasifica y
puntúa cada flujo automáticamente, y un módulo eBPF (Fase 3) inyectará la
atribución de proceso en tiempo de captura. El resto de este documento
describe cómo está organizado el código para sostener ese plan.

## Principios de diseño

1. **Flow-first.** Nada en la interfaz muestra un paquete suelto por defecto;
   el packet tree clásico existe, pero es el último recurso, no el punto de
   entrada. La unidad de exportación, de filtro y de alerta es el flujo.
2. **Privilegio mínimo radical.** Solo el *daemon* de captura toca el kernel
   (CAP_NET_RAW, CAP_BPF). Dissectors, plugins, heurísticas y UI corren sin
   privilegios: un bug en un parser nunca debe convertirse en un root
   exploit. Detalle completo en [security.md](security.md).
3. **Zero-copy donde importa.** Los dissectors trabajan con slices prestados
   del buffer de captura; solo se copian los metadatos pequeños y las cadenas
   DNS necesarias. El objetivo de rendimiento (Fase 2+) es que ningún byte
   del paquete se copie más de una vez desde el kernel.
4. **Sin panics en datos hostiles.** Los parsers procesan bytes controlables
   por un atacante. Todo acceso está acotado con `get`/`try_into`/límites
   explícitos y los casos degenerados devuelven `Option::None`. Los tests
   incluyen tramas truncadas y bucles de punteros DNS diseñados para colgar
   implementaciones ingenuas.
5. **Crates pequeños y DAG estricto.** El grafo de dependencias es un DAG
   donde `core` no depende de nadie y la CLI lo junta todo. Esto mantiene
   los tiempos de compilación bajos y las fronteras de responsabilidad
   claras.
6. **Dependencias externas mínimas.** Cinco crates externos (`serde`,
   `serde_json`, `thiserror`, `clap`, `anyhow`). Sin libpcap ni OpenSSL en
   Fase 1: el lector pcap y los checksums son propios y están testeados
   (ADR-003 en [decisions.md](decisions.md)).

## Mapa de crates

```text
                     ┌──────────────────────────────────────────┐
                     │              socshark-cli                │
                     │  (binario `socshark`: pipeline + salida) │
                     └──┬───────┬────────┬─────────┬─────────┬──┘
                        │       │        │         │         │
              ┌─────────▼─┐ ┌───▼────┐ ┌─▼──────┐ ┌▼───────┐ │
              │  capture  │ │dissect.│ │  flow  │ │ filter │ │
              │ (pcap,    │ │(L2-L7) │ │(agg.)  │ │ (DSL)  │ │
              │  CaptureSource)│    │ │        │ │        │ │
              └─────┬─────┘ └───┬────┘ └───┬────┘ └───┬────┘ │
                    │           │          │          │      │
                    └─────┬─────┴──────┬───┴──────────┴──────┤
                          │            │                     │
                     ┌────▼────┐  ┌────▼────┐                │
                     │ testgen │  │   soc   │◄───────────────┘
                     │(fixtures│  │(ruido,  │
                     │ + demo) │  │ riesgo) │
                     └────┬────┘  └────┬────┘
                          │            │
                          └──────┬─────┘
                            ┌────▼─────┐
                            │   core   │  ← no depende de nadie
                            └──────────┘
```

| Crate | Responsabilidad | Depende de |
|---|---|---|
| `socshark-core` | `EnrichedFlow`, `RawPacket`, `LinkType`, `PipelineConfig`, helpers DNS | — |
| `socshark-capture` | Trait `CaptureSource`, lector pcap y pcapng, captura en vivo (FFI libpcap/Npcap, ADR-009) y programa dueño de cada socket local | core |
| `socshark-dissectors` | Parsers Ethernet/IPv4/IPv6/TCP/UDP/DNS, `DissectorPipeline`, heurística L7, pool concurrente | core |
| `socshark-flow` | `FlowAggregator`: claves canónicas, contadores, expiración, reensamblado TCP, export | core, dissectors |
| `socshark-filter` | DSL: lexer, parser por precedencia, evaluador sobre flujos | core |
| `socshark-soc` | Ruido de fondo, DNS pasivo, riesgo/mini-IDS, resúmenes humanos, lenguaje claro (`explain`) y quién es quién (`hosts`, ADR-014) | core, flow, dissectors |
| `socshark-testgen` | Constructores de tramas con checksums reales + escenario demo | — (solo std) |
| `socshark-cli` | Orquestación, CLI (clap), TUI (Ratatui, feature `tui`), `follow`, salida tabla/JSONL, tests de integración | todos |

Dos decisiones de grafo merecen explicación. `socshark-testgen` no depende de
ningún crate del workspace: un fixture que dependiera del código bajo prueba
podría validar comportamientos erróneos por construcción, así que genera
tramas desde cero. Y `socshark-soc` recibe flujos ya exportados (no packets),
que es lo que permite que sus reglas sean *globales a la sesión*: el tracker
de escaneos necesita ver todos los flujos de un atacante juntos, cosa
imposible si solo mirara un paquete.

## Plataforma y stack

- **Lenguaje: Rust** (edition 2021, MSRV 1.75). Motivación completa en
  ADR-001: rendimiento comparable a C/C++ con las garantías de memoria que
  exige software que procesa datos hostiles a línea caliente.
- **Captura en Fase 1: archivos pcap clásicos** con lector propio. En Fase 2
  la captura en vivo va sobre libpcap cargada con `dlopen` (FFI propio,
  sin dependencias en tiempo de compilación, ADR-009) y AF_XDP llegará
  después para alto rendimiento; el trait `CaptureSource` abstrae ambas.
- **eBPF: aya** en Fase 3 (Rust puro, sin BCC ni clang en el host del
  usuario). Diseño en [ebpf-design.md](ebpf-design.md).
- **Interfaz: CLI, TUI (Ratatui) y GUI.** La GUI (ADR-013) es una página
  local servida por el propio binario; el lenguaje claro que muestra lo
  produce el motor (`socshark-soc::explain`). El modelo de datos está
  serializado precisamente para desacoplar la interfaz del núcleo: la TUI y
  la GUI consumen los mismos `EnrichedFlow` que imprime la tabla. Los
  nombres de los equipos (`socshark-soc::hosts`) también viven en el motor:
  el informe HTML (`socshark report`) y la GUI comparten frases.

## Evolución prevista del pipeline

Hoy el pipeline es un bucle secuencial simple, correcto y suficiente para
archivos pcap. El objetivo de Fase 2/3 es este, con cada etapa como unidad
independiente comunicada por buffers lock-free:

```text
  kernel                      userspace
┌─────────────────────┐   ┌────────────┐   ┌────────────┐   ┌──────────────┐   ┌──────────────┐
│ Ingestor            │   │ Enricher   │   │ Dissector  │   │ Stream       │   │ Indexer /    │
│ AF_XDP / eBPF ring  │ → │ eBPF: PID, │ → │ pool N     │ → │ Reassembler  │ → │ Store        │
│ (zero-copy)         │   │ usuario    │   │ workers    │   │ (TCP, DNS)   │   │ DuckDB/mmap  │
└─────────────────────┘   └────────────┘   └────────────┘   └──────────────┘   └──────────────┘
        │                        │               │                  │                  │
        └────────────── EnrichedFlow + canales MPSC/lock-free ──────────────────────┘
```

Cada etapa está aislada tras un trait o una frontera de datos ya definida en
Fase 1 (`CaptureSource` para el ingestor, `DissectedPacket` para el pool,
`EnrichedFlow` para el store), de modo que la paralelización no requiera
reescribir el código existente. El detalle etapa por etapa, con lo que ya
funciona y lo que falta, está en [pipeline.md](pipeline.md).

## Gestión de errores y observabilidad

Los errores se modelan con `thiserror` por crate (`CaptureError`,
`FilterError`) y la CLI los eleva con `anyhow` para imprimir contexto útil
(`no se pudo abrir el pcap X: ...`) y salir con código 1. El progreso y las
advertencias van por `stderr` para que `stdout` quede limpio para datos —
principio Unix que hace posible `socshark capture --json - | jq`. En Fase 2
se añadirá `tracing` con niveles y *spans* por flujo para depurar el pipeline
en producción sin sacrificar rendimiento (subscriber de bajo coste desactivado
por defecto).
