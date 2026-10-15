# Modelo de datos: `EnrichedFlow`

`EnrichedFlow` es la unidad de información de soc-shark. Todo el sistema
está diseñado alrededor de una regla: **un flujo completo, una estructura,
una línea de salida**. Este documento especifica cada campo, su tipo, su
significado y la fase en la que se rellena. La fuente canónica es
`crates/socshark-core/src/flow.rs`.

## Ciclo de vida del dato

```text
paquete ──► DissectedPacket (metadatos prestados) ──► FlowAccum (acumulación)
        ──► EnrichedFlow (export) ──► capa SOC (etiquetado) ──► salida/almacén
```

El flujo nace con el primer paquete de una 5-tupla canónica y muere en uno
de tres momentos: expira por inactividad (`idle_timeout_secs`), es expulsado
por presión de memoria (`max_flows`), o se exporta al terminar la captura
(`finish()`). Después de exportarse se enriquece con el contexto global de la
sesión y ya no muta: los consumidores (filtro, tabla, JSONL, futuros SIEM)
reciben datos inmutables.

## Tabla completa de campos

### Identificación y clasificación

| Campo | Tipo | Descripción | Se rellena en |
|---|---|---|---|
| `flow_id` | `FlowId(String)` | Identificador canónico bidireccional, p. ej. `tcp/192.168.1.1:22-192.168.1.30:40001`. Los extremos se ordenan para que A→B y B→A compartan id. | Agregador (F1) |
| `state` | `FlowState` | `Active` (recibe tráfico), `Idle` (sin cierre observado) o `Closed` (FIN o RST vistos). | Agregador (F1) |
| `transport` | `Transport` | `Tcp`, `Udp`, `Icmp` o `Other(nº protocolo IP)`. | Dissector (F1) |
| `l7_protocol` | `L7Protocol` | `Dns`, `Dhcp`, `Ntp`, `Http`, `Tls`, `Ssh`, `Unknown`. Detectado por puerto + sniffing. | Dissector (F1) |

### Extremos

| Campo | Tipo | Descripción | Se rellena en |
|---|---|---|---|
| `src_ip` / `dst_ip` | `IpAddr` | Extremos **según el primer paquete observado** (no canónicos: el analista piensa en "quién inició"). | Agregador (F1) |
| `src_port` / `dst_port` | `u16` | Puertos según el primer paquete; 0 para ICMP. | Agregador (F1) |
| `src_mac` / `dst_mac` | `Option<String>` | MACs del primer paquete si la captura es Ethernet, formato `aa:bb:cc:dd:ee:ff`. | Dissector (F1) |

### Temporalidad y volumen

| Campo | Tipo | Descripción | Se rellena en |
|---|---|---|---|
| `first_seen_micros` / `last_seen_micros` | `u64` | Timestamps Unix en microsegundos (los pcap nanosegundo se truncan a micros en Fase 1). | Ingestor (F1) |
| `duration_micros` | `u64` | `last_seen - first_seen`. | Agregador (F1) |
| `packets` / `bytes` | `u64` | Paquetes y bytes en dirección src→dst (bytes = longitud capturada, cabeceras incluidas). | Agregador (F1) |
| `packets_rev` / `bytes_rev` | `u64` | Paquetes y bytes en dirección dst→src. La asimetría es señal: un flujo solo-fwd hacia un puerto de servicio huele a escaneo o a envío. | Agregador (F1) |
| `tcp_flags` | `TcpFlagCounts` | Contadores acumulados de `syn`, `ack`, `fin`, `rst`, `psh`, `urg` en ambas direcciones. Base de varias reglas SOC. | Agregador (F1) |

### Enriquecimiento eBPF (Fase 3 — hoy siempre `None`)

| Campo | Tipo | Descripción |
|---|---|---|
| `process_name` | `Option<String>` | Binario que originó la conexión (probes kprobe/uprobe). |
| `pid` | `Option<u32>` | PID del proceso origen. |
| `user` | `Option<String>` | Usuario efectivo (uid resuelto en el momento del connect). |

### Enriquecimiento SOC

| Campo | Tipo | Descripción | Se rellena en |
|---|---|---|---|
| `resolved_domain` | `Option<String>` | Dominio de `dst_ip`: el qname propio si el flujo ES DNS; el lookup de la base de DNS pasivo si no. | Capa SOC (F1) |
| `dns` | `Option<DnsSummary>` | Resumen completo del intercambio DNS del flujo: preguntas, respuestas (A/AAAA/CNAME/NS/PTR), TTLs y rcode. | Agregador + SOC (F1) |
| `dst_geo_asn` | `Option<String>` | ASN/GeoIP del destino (bases offline Feodo/Tor/MaxMind). | Threat intel (F4) |
| `ja4_fingerprint` | `Option<String>` | Huella JA4 del handshake TLS del cliente. | Reassembler (F3) |

### Capa semántica (la cara visible del analista)

| Campo | Tipo | Descripción | Se rellena en |
|---|---|---|---|
| `is_background_noise` | `bool` | True para tráfico de mantenimiento (NTP, mDNS, LLMNR, SSDP, NetBIOS, DHCP...). La UI lo atenúa; nunca se borra. | Capa SOC (F1) |
| `human_summary` | `String` | Una línea en español: `DNS 192.168.1.30:53002 → 8.8.8.8:53: consulta <qname> (TXT)`. | Capa SOC (F1) |
| `risk_score` | `u8` | 0-100 por suma de reglas heurísticas (ver [soc-features.md](soc-features.md)). | Capa SOC (F1) |
| `alerts` | `Vec<Alert>` | Alertas disparadas: `id` estable, `name`, `severity` (Info→Critical), `detail` y `mitre` (p. ej. `T1048.003`). | Capa SOC (F1) |
| `extracted_files` | `Vec<ExtractedFile>` | Archivos reconstruidos del flujo: nombre, SHA-256, magic bytes y marca `masquerading_suspect` (nombre ≠ tipo real → T1036). | Carving (F4) |

## Estructuras anidadas

```rust
DnsSummary          { is_response, rcode, queries: Vec<DnsQuerySummary>, answers: Vec<DnsAnswerSummary> }
DnsQuerySummary     { name, qtype (u16) }
DnsAnswerSummary    { name, rtype, ttl, address: Option<IpAddr>, target: Option<String> }
TcpFlagCounts       { syn, ack, fin, rst, psh, urg (u32) }
Alert               { id, name, severity, detail, mitre: Option<String> }
ExtractedFile       { name, size, sha256, magic, masquerading_suspect }
```

## Claves canónicas: `FlowKey` y `FlowId`

La bidireccionalidad se resuelve normalizando los extremos: `FlowKey::new`
ordena el par `(IP, puerto)` con el orden total de `(IpAddr, u16)`, de modo
que el paquete A→B y su respuesta B→A caen en la misma entrada del HashMap.
El `flow_id` generado es estable entre ejecuciones (sin hash aleatorio), lo
que permite correlacionar exportaciones de distintas sesiones y usar el id
como clave en el futuro almacén DuckDB.

La dirección *original* (quién inició) se conserva por separado: los campos
`src_*` guardan el primer paquete observado. Es una decisión deliberada: el
id canónico es para máquinas, los extremos originales son para humanos.

## Serialización: JSONL y compatibilidad

Los flujos se serializan con `serde` como **JSON Lines**: un objeto por
línea, legible con `jq`, ingesta directa en SIEM y streaming sin cargar el
archivo entero. Las convenciones:

- Los enums se serializan por nombre (`"transport": "Udp"`,
  `"severity": "High"`).
- Los campos opcionales/futuros llevan `#[serde(default)]`: un JSON producido
  por una versión nueva sigue cargando en una versión vieja, y los campos
  que llegarán con eBPF/carving no rompen a los consumidores actuales.
- Ejemplo real (primer flujo de la demo, recortado):

```json
{"flow_id":"udp/8.8.8.8:53-192.168.1.10:53001","state":"Idle",
 "transport":"Udp","l7_protocol":"Dns","src_ip":"192.168.1.10",
 "src_port":53001,"dst_ip":"8.8.8.8","dst_port":53,
 "first_seen_micros":1700000000000000,"packets":1,"bytes":71,
 "packets_rev":1,"bytes_rev":87,"human_summary":"DNS ...: example.com → 93.184.216.34 (A)",
 "risk_score":0,"alerts":[],"extracted_files":[]}
```

El mapeo a ECS (Elastic Common Schema) para export SIEM está especificado en
[soc-features.md](soc-features.md) y se implementará en Fase 4 como una capa
de transformación que consume exactamente este JSON.
