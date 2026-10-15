# 02 · Arquitectura

## Panorama

soc-shark es un **monorepo Rust** organizado como workspace con crates
independientes y acoplados solo por tipos explícitos. La regla de
dependencias es un DAG estricto:

```text
common ◀── capture-core ◀── dissectors ◀── flow-aggregator ◀── soc-engine
   ▲              │                                            │
   └──────────────┴────── storage-index · filter-dsl ──────────┘
                                 │
                              daemon (binario soc-shark)
```

Ningún crate del motor conoce la CLI; el daemon es una capa fina que
conecta pipeline + bridge del DSL + render.

## El pipeline de datos (fase 1)

```text
        ┌─────────────┐   ┌───────────┐   ┌──────────────────┐   ┌────────────────┐
archivo │PcapFileSource│──▶│  dissect  │──▶│SocEngine.observe │──▶│SessionTable.feed│
pcapng  │ (zero-copy)  │   │ (L2→L7)   │   │ passive DNS,     │   │ 5-tupla → flows │
        └─────────────┘   └───────────┘   │ carving, eventos  │   └────────────────┘
                                          └──────────────────┘
al agotar la fuente:
        SocEngine.enrich ──▶ alertas + riesgo + dominios + resúmenes + artefactos
                        ──▶ filter-dsl (FlowFacts) ──▶ informe / JSON / ECS
```

- **Ingestor**: `PcapFileSource`/`PcapngFileSource` entregan
  `PacketRecord<'a>` — vistas `&[u8]` sobre el buffer del archivo. Un
  registro corrupto produce `Err` y el barrido continúa.
- **Dissector**: `dissect(&rec, LinkType)` encadena L2→L3→L4→L7 y devuelve
  `DissectedPacket` con 5-tupla, protocolo L7 detectado (por puerto y
  *sniffing*) y payload de aplicación.
- **Enricher/SOC** (`SocEngine::observe_packet`): acumula passive DNS,
  eventos DNS (tunneling) y carving HTTP; `enrich` al final añade alertas,
  riesgo, dominios y resúmenes por flujo.
- **Indexer** (`storage-index`): `CaptureIndex` guarda el offset de cada
  paquete — la base del virtual scrolling y del acceso aleatorio.

## Etapas paralelas (fase 2)

La fase 1 es monohilo y streaming (suficiente para capturas de análisis).
La fase 2 separa etapas en hilos conectados con el ring buffer lock-free
ya implementado (`capture-core::ring_buffer::SpscRing`, potencia de dos,
política sin bloqueo del productor):

```text
[captura libpcap/AF_XDP] ──SpscRing──▶ [pool de dissectors] ──SpscRing──▶ [flow+SOC]
        │                                                                │
        └──────────── shm/mmap de paquetes crudos ───────────────────────┘
```

La estructura del código no cambia: cada etapa consume `PacketRecord`/
`DissectedPacket`; solo cambia quién llama a quién.

## Almacenamiento: de `read()` a mmap

Fase 1: el daemon lee el archivo completo con `std::fs::read` (avisa si
supera 1 GiB). Los lectores **ya son zero-copy sobre ese buffer**, así que
el paso a mmap (fase 2, `memmap2`) es transparente: cambia el origen del
`&[u8]`, no ninguna API. `CaptureIndex.entries[i].file_offset` apunta al
registro exacto, permitiendo:

- abrir capturas de decenas de GB con RAM constante,
- que la UI pida `packet(i)` y el SO traiga una página,
- volcar metadatos a SQLite/DuckDB para filtros instantáneos.

## El modelo de hilos objetivo (fase 3+)

Con eBPF, la atribución de procesos entra como **otra etapa del pipeline**:
los eventos `inet_sock_set_state` y `tcp_v4_connect` llenan un mapa
kernel→user que el enricher consulta por 5-tupla (ver `docs/08-ebpf.md`).
El TLS plaintext llega por uprobes y se inyecta como "payload virtual" del
flujo, sin cambiar el contrato `EnrichedFlow`.

## Comunicación motor ↔ UI (fase 2/4)

El diseño final separa `soc-shark-daemon` (captura, privilegios) de
`soc-shark-engine`/UI (sin privilegios) mediante **gRPC sobre Unix Domain
Sockets** (ver `docs/07-seguridad.md`). En fase 1 la CLI ejerce de cliente
único; el protocolo de mensajes queda definido por los JSON del informe
(`--json`) y los eventos (`--events`), que ya son estables.
