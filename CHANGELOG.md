# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y [SemVer](https://semver.org/lang/es/).

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
