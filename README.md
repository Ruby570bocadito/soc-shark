# soc-shark 🦈

**Analizador de tráfico de red de nueva generación, orientado a SOC** — un
Wireshark que habla idioma de analista: conversaciones en lugar de paquetes
sueltos, dominios en lugar de IPs secas, y detección Blue Team integrada
(beaconing, Masquerading, DNS tunneling) sin tocar un plugin.

> Estado: **fase 1 (motor) completada** — 99 tests en verde, std-only,
> zero-copy. Hoja de ruta completa en [`docs/11-hoja-de-ruta.md`](docs/11-hoja-de-ruta.md).

```text
$ soc-shark read examples/demo_soc_incident.pcap --iocs examples/iocs/sample_iocs.txt --no-color
═══ soc-shark 0.1.0 — Informe SOC ═══
Captura: examples/demo_soc_incident.pcap · 54 paquetes · 5.8 KiB · enlace Ethernet
Flujos: 15 (ruido 3 oculto) · Alertas: 11 C3 A8 M0 L0 · Artefactos: 2 · PassiveDNS: 4 pares
──────────────────────────────────────────────────────────────────────────────────────────────────────
#    TIEMPO       DUR      ORIGEN                 DESTINO                PROTO RESUMEN                            RIESGO
10   08:15:00.500 51.0s    192.168.1.50:49820     185.22.1.9:4444 [c2.e… HTTP  POST /gate.php (Host: c2.evil-dom… 100
6    08:14:10.500 900.00ms 192.168.1.50:49812     185.220.101.4:80 [upd… HTTP  GET /update.exe (Host: update.evi…  75
8    08:14:30.500 900.00ms 192.168.1.50:49815     45.33.32.156:80 [fact… HTTP  GET /factura.pdf (Host: factura.e…  60
11   08:16:00.000 0us      192.168.1.50:53534     192.168.1.1:53         DNS   Consulta DNS a7x9k2p1m4q8z5n3b6v1…  30
12   08:16:01.000 0us      192.168.1.50:53535     192.168.1.1:53         DNS   Consulta DNS z2x4v6n8m1q3w5e7r9t0…  30
13   08:16:02.000 0us      192.168.1.50:53536     192.168.1.1:53         DNS   Consulta DNS k9j7h5g3f1d2s4a6z8x0…  30
14   08:16:03.000 0us      192.168.1.50:53537     192.168.1.1:53         DNS   Consulta DNS e5r7t9y1u3i5o7p9a2s4…  30
0    08:14:00.500 0us      192.168.1.50:53530     162.159.200.123:53     DNS   Consulta DNS www.pool.ntp.org      0
...
── Radar SOC ──
  🚨 CRÍTICA Destino 185.220.101.4 en lista de IOCs (sample_iocs.txt) ×1
  🚨 CRÍTICA Beaconing hacia 185.22.1.9:4444 (CV 0.00, n=6) ×1 [T1071]
  🚨 CRÍTICA Destino 185.22.1.9 en lista de IOCs (sample_iocs.txt) ×1
  🚨 ALTA Ejecutable extraído por HTTP: update.exe ×1 [T1105]
  🚨 ALTA Ejecutable extraído por HTTP: factura.pdf ×1 [T1105]
  🚨 ALTA Masquerading: factura.pdf no es lo que dice ser ×1 [T1036]
  🚨 ALTA HTTP en puerto no estándar 4444 ×1 [T1071]
  🚨 ALTA Posible DNS tunneling hacia evil.ru ×4 [T1071.004]
── Artefactos extraídos ──
  📦 update.exe (616 bytes, magic MZ) sha256=832fa952375057c9
  📦 factura.pdf (308 bytes, magic MZ) ¡MASQUERADE! sha256=2e6870379f52298a
```

## Por qué no es "otro Wireshark"

| Problema clásico | Enfoque soc-shark |
|---|---|
| 80 filas de SYN/ACK/PSH por una petición | **Flow-First**: 1 fila por conversación, desplegable |
| IPs secas sin contexto | **Passive DNS + Host/SNI**: dominio junto a la IP |
| Fatiga visual (ARP/mDNS/NTP) | **Smart Noise Dimming**: ruido etiquetado y oculto por defecto |
| Dissectors en C explotables | **Rust std-only**, slicing comprobado, suite anti-panic |
| Detección solo con plugins externos | **Motor SOC nativo**: beaconing, carving, masquerading, tunneling, IOCs |
| Salidas incompatibles con el SIEM | **ECS JSONL** + regla Suricata en un flag |

## Compilar y ejecutar

```bash
# Requisitos: Rust estable (no hay dependencias externas: compila offline)
cargo build --release
./target/release/soc-shark read examples/demo_soc_incident.pcap --no-color

# Con threat intel local + exportación al SIEM
./target/release/soc-shark read captura.pcapng \
    --iocs examples/iocs/sample_iocs.txt \
    --filter 'flow.risk >= 30 and not flow.noise' \
    --export-ecs incidente.jsonl

# JSON completo / eventos por paquete / catálogo de campos
./target/release/soc-shark read captura.pcap --json
./target/release/soc-shark read captura.pcap --events --filter 'tcp.dstport == 4444'
./target/release/soc-shark fields
```

### Regenerar el escenario demo

```bash
python3 tools/gen_demo_pcap.py   # stdlib de Python, sin dependencias
```

Crea `examples/demo_soc_incident.pcap`: ARP/NTP/mDNS/SSDP de fondo, una
descarga de `update.exe` desde un rango Tor (IOC), una `factura.pdf` que es
un PE (Masquerading T1036), beaconing C2 exacto (POST cada 10 s al 4444) y
consultas TXT de alta entropía (DNS tunneling).

## Arquitectura (monorepo Rust, std-only)

```text
crates/
├── common/            JSON, SHA-256, Base64, entropía, IP/CIDR, tiempo, tipos SOC
├── capture-core/      pcap + pcapng zero-copy · PacketSource trait · SpscRing lock-free
├── dissectors/        layer2 (Eth/ARP/SLL) · layer3 (IPv4/IPv6) · layer4 (TCP/UDP/ICMP)
│                      layer7 (DNS con compresión, HTTP, TLS+JA4-like) · view.rs (dissect)
├── flow-aggregator/   SessionTable (5-tupla) · passive DNS · ruido · resumen humano
│                      └── EnrichedFlow: LA fila legible que consume cualquier UI
├── soc-engine/        file_carver · anomaly_detector · beacon_detect · threat_intel
│                      rules_eval (MITRE) · siem_exporter (ECS/Suricata)
├── filter-dsl/        lexer + Pratt parser + VM · catálogo de campos
├── storage-index/     índice de offsets por paquete · stats columnares · plan mmap
└── daemon/            binario soc-shark (pipeline + CLI + puente DSL)
apps/                  TUI (fase 2) y GUI Tauri (fase 4): diseño en docs/09
plugins-sdk/           plantilla de disector Wasm (fase 5)
docs/                  toda la documentación del proyecto
```

Pipeline (fase 1, streaming monohilo; fase 2 lo paraleliza con `SpscRing`):

```text
pcap/pcapng ─▶ dissect ─▶ SocEngine.observe (passive DNS, carving, DNS events)
                        ─▶ SessionTable.feed (conversaciones)
al agotar: SocEngine.enrich (alertas, riesgo, dominios, resúmenes)
         ─▶ filter-dsl ─▶ informe SOC / JSON / ECS
```

## Diseño de seguridad desde el día 1

- **Privilegios separados**: en fase 2 el daemon (CAP_NET_RAW/CAP_BPF) solo
  captura; la disección corre como usuario sin privilegios. Un bug en un
  parser malicioso cuelga un hilo de usuario, nunca root.
  Ver [`docs/07-seguridad.md`](docs/07-seguridad.md).
- **Cadena de suministro mínima**: cero dependencias externas en fase 1
  (ADR-0001) — nada que auditar más allá de este repo.
- **Memoria segura**: todos los parsers aceptan bytes hostiles; los tests
  barren truncados en cada longitud y entrada pseudoaleatoria.

## Documentación

| Doc | Contenido |
|---|---|
| [docs/01-vision.md](docs/01-vision.md) | Problema, killer features y comparativa con Wireshark |
| [docs/02-arquitectura.md](docs/02-arquitectura.md) | Pipeline, crates, threading y plan mmap |
| [docs/03-modelo-de-datos.md](docs/03-modelo-de-datos.md) | `EnrichedFlow`, `PacketRecord`, JSON de ejemplo |
| [docs/04-dissectors.md](docs/04-dissectors.md) | Guía de dissectors y reglas de seguridad |
| [docs/05-filter-dsl.md](docs/05-filter-dsl.md) | Gramática, campos y 20 ejemplos |
| [docs/06-soc-engine.md](docs/06-soc-engine.md) | Detectores, umbrales y mapeo MITRE ATT&CK |
| [docs/07-seguridad.md](docs/07-seguridad.md) | Modelo de amenazas y separación de privilegios |
| [docs/08-ebpf.md](docs/08-ebpf.md) | Diseño eBPF (fase 3): atribución de procesos y TLS |
| [docs/09-ui-tui-gui.md](docs/09-ui-tui-gui.md) | TUI y GUI SOC (fases 2 y 4) |
| [docs/10-siem-y-formatos.md](docs/10-siem-y-formatos.md) | ECS, Wazuh/Elastic/TheHive, Suricata |
| [docs/11-hoja-de-ruta.md](docs/11-hoja-de-ruta.md) | Fases 1-5 con criterios de aceptación |
| [docs/adr/](docs/adr) | Decisiones arquitectónicas (ADRs 0001-0006) |

## Licencia

MIT — ver [LICENSE](LICENSE).
