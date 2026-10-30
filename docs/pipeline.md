# El pipeline en detalle

El pipeline de soc-shark tiene cuatro etapas. Este documento describe, para
cada una, el **estado actual** (Fase 1, ya implementado y testeado), el
**objetivo** (Fase 2-4) y las decisiones que sostienen la transición. La
regla general es: cada etapa ya existe con su frontera de datos definitiva,
aunque su implementación interna sea hoy la versión secuencial simple.

```text
FASE 1 (hoy)      pcap ──► leer+disecar+agregar ──► enriquecer ──► filtrar ──► tabla/JSONL
OBJETIVO          AF_XDP ─► ring ─► enrich(eBPF) ─► pool workers ─► reassemble ─► store
                   ①Ingestor      ②Enricher        ③Dissector pool  ④Reassembler
```

## 1. Ingestor

**Hoy (Fase 1).** El trait `CaptureSource` (crate `socshark-capture`) define
el contrato: `next_packet()` devuelve `Ok(Some(RawPacket))` o `Ok(None)` al
acabar, y `link_type()` informa de la capa 2. Sobre ese contrato existe el
lector de **pcap clásico y pcapng** (`PcapFileReader`, detecta el formato
por la cabecera; en pcapng lee secciones con su orden de bytes, interfaces
con su resolución de tiempo y paquetes Enhanced/Simple): implementación
propia en Rust puro que soporta los cuatro magics del pcap clásico
(micro/nanosegundos × big/little-endian),
valida versiones, acota `incl_len` a 256 MiB para resistir archivos
corruptos, y distingue EOF limpio en límite de registro de archivo truncado a
mitad de payload. Los tests cubren los seis comportamientos límite incluyendo
pcap big-endian y nanosegundos sintéticos.

**Objetivo (Fase 2-3).** Dos backends en vivo detrás del mismo trait:

- *libpcap* (crate `pcap`): compatibilidad inmediata con cualquier Linux y
  macOS; requiere CAP_NET_RAW o root; soporta *pushdown* de filtros BPF al
  kernel, que reduce drásticamente el tráfico hacia userspace cuando el
  analista filtra por host.
- *AF_XDP* (Linux ≥ 4.18): cola de paquetes del kernel compartida con
  userspace sin copia por paquete; objetivo > 1 Gbps en hardware modesto.

En Fase 3 el ingestor pasa a ser un **daemon separado** con las capacidades
del sistema (CAP_NET_RAW, CAP_BPF) y publica paquetes por un anillo lock-free
en memoria compartida o por gRPC sobre Unix Domain Socket; el resto del
pipeline corre como proceso sin privilegios. Los detalles de seguridad están
en [security.md](security.md).

## 2. Enricher

**Hoy (Fase 1).** El enriquecimiento se hace en dos pasadas sobre los flujos
agregados (`socshark_soc::enrich_all`): la primera alimenta los trackers
globales (base de DNS pasivo y tracker de escaneos); la segunda etiqueta
cada flujo con dominio resuelto (`resolved_domain`), marca de ruido
(`is_background_noise`), riesgo y alertas (`risk_score`, `alerts`) y el
resumen humano (`human_summary`). Las dos pasadas son necesarias: una señal
visible solo globalmente (el escaneo repartido en N flujos de un SYN) o que
depende del orden (la IP que se resuelve *después* de que empieza el flujo
TCP) solo está disponible cuando ya se ha visto toda la captura.

**Objetivo (Fase 3).** El enricher pasará a estar *en línea*: un mapa
hash eBPF (LRU) correlaciona la 5-tupla de cada paquete con el PID/binario/
usuario capturado por los probes en el momento del `connect()`. El campo ya
existe en el modelo (`process_name`, `pid`, `user` en `EnrichedFlow`) y está
serializado, así que el cambio es rellenar datos, no modificar el formato.
Diseño completo en [ebpf-design.md](ebpf-design.md).

## 3. Dissector pool

**Hoy (Fase 1).** Un pipeline secuencial (`DissectorPipeline::dissect`):
Ethernet (con VLAN 802.1Q) → IPv4 (con verificación de checksum) → TCP/UDP →
DNS/L7. Los parsers son funciones puras `&[u8] -> Option<(Info, &[u8])>` que
prestan slices sin copiar el payload. La identificación L7 combina reglas de
puerto (53 DNS, 123 NTP, 443 TLS, 67/68 DHCP) con sniffing independiente del
puerto (banners SSH, métodos HTTP, bytes mágicos del record TLS) — útil
contra servicios que no escuchan donde "deberían". El DNS soporta compresión
de nombres con límites anti-bucle (16 saltos, 32 etiquetas) y DNS sobre TCP
con prefijo de longitud.

**Paralelismo (Fase 2, implementado).** Pool de N workers
(`socshark capture --workers N`) con despacho **por lotes y entrega
ordenada** (ADR-010): lotes de 4096 paquetes se reparten round-robin entre
workers y vuelven al agregador en el orden de envío, así que el resultado
es idéntico al secuencial (verificado E2E). El payload pasa de slice
prestado a `Cow`: cero copias en secuencial, una copia solo con
paralelismo. La variante por hash de `FlowKey` (mismo flujo = mismo worker,
sin barrera de lote) queda como evolución natural cuando el en vivo
necesite paralelismo por flujo; los dissectors de terceros (plugins WASM)
se registrarán en este pool
([wasm-plugins.md](wasm-plugins.md)). La firma de `dissect` no cambia: el
pool es un detalle de ejecución.

## 4. Stream Reassembler & Indexer

**Hoy (Fase 1).** El agregador (`socshark-flow`) convierte paquetes en
flujos: clave canónica bidireccional (`FlowKey` con extremos ordenados),
contadores por dirección, contadores de flags TCP, fusión de preguntas y
respuestas DNS por flujo, expiración por inactividad (`drain_expired`) y
expulsión bajo presión de memoria (`max_flows`: los flujos con `last_seen` más antiguo salen de la tabla para
acotar RAM en capturas largas o ataques de agotamiento de tabla, pero se
encolan y se exportan en el siguiente `drain_expired`/`finish()`, así que un
atacante no puede «borrar» un flujo C2 inundando la tabla). El reensamblado
TCP tiene además un presupuesto global (256 MiB), cuenta 64 B de sobrecarga
por segmento y admite como mucho 8 192 segmentos por dirección. La exportación (`finish()`) produce los
`EnrichedFlow` ordenados por primer avistamiento.

**Objetivo (Fase 2+).** Dos piezas nuevas sobre esta base:

- *Reensamblado TCP*: buffers de segmentos fuera de orden por dirección con
  recorte de bytes solapados, para Follow Stream y detección que requiera el
  payload completo (carving, fingerprinting JA4). Algoritmo: lista ordenada
  por seq con fusión de rangos y control de memoria por flujo.
- *Indexer*: los `EnrichedFlow` se escriben a un almacén consultable. En
  disco: DuckDB (consultas analíticas tipo "todos los flujos hacia ASN X con
  riesgo > 50") o SQLite para la versión ligera. En memoria: estructura
  ordenada por `last_seen` para la TUI virtualizada. El JSONL actual es la
  forma ya operativa de este mismo contrato de datos.

## Rendimiento

`socshark dev bench` mide el pipeline offline completo (lectura → disección
→ agregación → carving → SOC) sobre una captura sintética determinista:
5/10 de flujos HTTP con cuerpo (los talla el carving), 2/10 TLS con
ClientHello, 2/10 DNS y 1/10 UDP genérico, entrelazados en oleadas de 1 000
flujos. La misma semilla genera exactamente los mismos bytes; la generación
no entra en el tiempo medido.

```bash
cargo build --release
./target/release/socshark dev bench                      # ~1M paquetes, 20k flujos
./target/release/socshark dev bench --workers 4          # pool de disección
./target/release/socshark dev bench --packets 500000 --flows 10000 --seed 7 --json
```

Informa paquetes/s, Mbit/s (suma de bytes de trama), flujos, alertas,
archivos tallados, tiempo y pico de memoria residente (Linux y Windows).
Referencia (Windows, 22 hilos, release, por defecto: 1M paquetes, 685 MB):
~1,8 s, ~550 000 paquetes/s (~3 Gbit/s) con `--workers 1` y ~545 MiB de
pico (sobre todo el presupuesto de reensamblado de 256 MiB, que con 1M
paquetes se agota: 4 500 de 10 000 respuestas HTTP llegan a tallarse). Con
`--workers 4` no mejora: la disección es una fracción pequeña del tiempo
(el carving y el reensamblado pesan más) y el pool añade copia y sincronía.
El job `bench` del CI lo ejecuta en release con `--packets 500000 --json`,
sube el JSON como artefacto y falla si baja de un umbral conservador
(documentado en `.github/workflows/ci.yml`).

## Flujo de datos de extremo a extremo (ejemplo de la demo)

1. `PcapFileReader` entrega 19 tramas Ethernet.
2. `DissectorPipeline` las disecciona todas (19/19, 0 descartadas): 4 DNS,
   9 TCP, 2 UDP de ruido, ... y detecta L7: DNS×4, TLS, SSH, HTTP, NTP.
3. `FlowAggregator` las reduce a **12 flujos** bidireccionales: la respuesta
   DNS comparte flujo con su pregunta, los 8 paquetes de la sesión TLS son
   un solo flujo, y cada sonda del escaneo es un flujo distinto (otro
   puerto destino) — exactamente lo que el tracker de escaneos necesita.
4. `enrich_all` alimenta el DNS pasivo (1 entrada: `example.com` →
   93.184.216.34), detecta el escaneo (192.168.1.30 prueba 12 puertos de
   192.168.1.1 sin establecer conexión), puntúa y genera alertas con mapeo
   MITRE, y etiqueta el flujo HTTP hacia 93.184.216.34 con
   `resolved_domain = example.com` gracias al DNS pasivo.
5. La CLI excluye el ruido (NTP + mDNS: 2 flujos), aplica el filtro si lo
   hay, y emite tabla o JSONL.
