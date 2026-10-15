# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y [SemVer](https://semver.org/lang/es/).

## [0.1.0] — 2026-10-15

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
