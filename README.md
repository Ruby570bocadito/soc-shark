# soc-shark

**Analizador de tráfico de red orientado a SOC/Blue Team, diseñado para superar a Wireshark en el flujo de trabajo del analista de seguridad.**

Wireshark responde a la pregunta *«¿qué hay en este paquete?»*. **soc-shark responde a *«¿qué está pasando en mi red y qué me debería preocupar?»*.** Ese es el cambio de paradigma que guía todo el proyecto: sesiones en lugar de paquetes, significado en lugar de hex, alertas en lugar de scrolling manual.

[![CI](https://github.com/soc-shark/soc-shark/actions/workflows/ci.yml/badge.svg)](https://github.com/soc-shark/soc-shark/actions/workflows/ci.yml)
![Estado](https://img.shields.io/badge/fase-2%20de%204-blue)
![Licencia](https://img.shields.io/badge/licencia-MIT-green)

---

## Características clave (visión de producto)

| Función | Descripción | Estado |
|---|---|---|
| **Atribución de proceso con eBPF** | Cada flujo muestra PID, binario y usuario que lo originó | Diseño (`docs/ebpf-design.md`) — Fase 3 |
| **TLS 1.3 transparente** | Descifrado vía uprobes a `SSL_read/SSL_write`, sin `SSLKEYLOGFILE` | Diseño — Fase 3+ |
| **Plugins WASM en sandbox** | Dissectors seguros escritos por la comunidad, sin riesgo de RCE | Diseño (`docs/wasm-plugins.md`) — Fase 4 |
| **Decodificador CyberChef integrado** | Pipelines Base64→XOR→Zlib→JSON sobre payloads | Fase 4 |
| **Detección pasiva y fingerprinting** | JA4/JA4+, HASSH, entropía, beaconing | Fase 3 |
| **IPv6 completo** | Dissector con extensiones, claves de flujo v4/v6 y literales v6 en el DSL | **Implementado** |
| **Follow Stream** | Reensamblado TCP por dirección: orden, retransmisiones, huecos, hexdump | **Implementado** |
| **TUI interactiva (Ratatui)** | Lista Flow-First + panel de alertas + filtro DSL en vivo | **Implementado** |
| **Paradigma Flow-First** | 1 línea = 1 sesión; expansión bajo demanda | **Núcleo implementado** |
| **Mini-IDS heurístico** | Túnel DNS, escaneos SYN, puertos inseguros | **Implementado** |
| **DNS pasivo** | Dominio ↔ IP observados, etiqueta el resto de flujos | **Implementado** |
| **Smart Noise Dimming** | NTP/mDNS/SSDP marcados como ruido y atenuados | **Implementado** |
| **Export SIEM** | JSONL → ECS / Wazuh / TheHive | Fase 4 (JSONL ya disponible) |

## Estado actual: Fase 1 completa ✅ · Fase 2 en curso (4/7)

El pipeline completo funciona de extremo a extremo sobre archivos pcap: **lectura → disección (Ethernet/IPv4/IPv6/TCP/UDP/DNS) → agregación de flujos bidireccionales → enriquecimiento SOC → filtro DSL → tabla/TUI/JSONL/follow**. 94 tests automatizados cubren parsers (incluido el barrido anti-panic), agregador, reensamblado, DSL, capa SOC e integración.

### Inicio rápido

Requisitos: Rust 1.75+ (`rustup install stable`).

```bash
# 1. Compilar
cargo build --release

# 2. Generar una captura de demostración con eventos SOC interesantes
./target/release/socshark dev sample-pcap -o demo.pcap

# 3. Analizarla
./target/release/socshark capture -r demo.pcap
```

Salida real de la demo (21 paquetes → 11 flujos relevantes, ruido excluido):

```text
═══ soc-shark · 11 flujos (demo.pcap) ═══
FLUJO                                                        L7        PAQ      BYTES  RIESGO  ALERTAS
tcp/93.184.216.34:443-192.168.1.10:52000                     TLS         7      406 B       0  -
udp/2001:4860:4860::8888:53-fd00::10:53010                   DNS         2      216 B       0  -
udp/8.8.8.8:53-192.168.1.30:53002                            DNS         1      137 B      45  DNS-TUNNELING
tcp/93.184.216.34:80-192.168.1.20:40111                      HTTP        1      101 B       0  -
tcp/192.168.1.1:22-192.168.1.30:40001                        ?           1       54 B      30  PORT-SCAN
...

─── Alertas SOC ───
▸ (alta) Posible túnel DNS · udp/8.8.8.8:53-192.168.1.30:53002 ·
  qname 'az3k9...chfdgs.tun.evil.example' (77 caracteres, entropía 5.09 ≥ 3.50) · MITRE T1048.003
▸ (media) Posible escaneo de puertos · tcp/192.168.1.1:22-192.168.1.30:40001 ·
  5 SYNs sin respuesta hacia 192.168.1.1:22 · MITRE T1046

Estadísticas: 21 paquetes leídos · 21 diseccionados · 0 descartados · 13 flujos
```

El flujo `udp/2001:4860:4860::8888:53-...` es el intercambio **DNS sobre IPv6**
que incluye la demo desde la Fase 2 (respuesta AAAA incluida).

### Comandos

```bash
# Tabla resumen (por defecto)
socshark capture -r captura.pcap

# Volcado JSONL completo a fichero o stdout
socshark capture -r captura.pcap --json flujos.jsonl
socshark capture -r captura.pcap --json - | jq '.risk_score'

# Filtrar con el DSL (ver docs/filter-dsl.md)
socshark capture -r captura.pcap -f "tcp.port == 443"
socshark capture -r captura.pcap -f "ip.version == 6 || flow.risk >= 50"
socshark capture -r captura.pcap -f "!(flow.noise)" --show-noise

# Seguir un stream TCP reensamblado (texto o hexdump)
socshark follow -r captura.pcap --flow "93.184.216.34:443"
socshark follow -r captura.pcap --flow "93.184.216.34:443" --hex

# Explorar la captura con la TUI (Flow-First + alertas + filtro DSL)
socshark tui -r captura.pcap

# Captura en vivo (stub informativo hasta tener backend libpcap/AF_XDP)
socshark daemon --iface eth0
```

## Estructura del repositorio

```text
soc-shark/
├── crates/
│   ├── socshark-core/         # EnrichedFlow, paquetes crudos, configuración
│   ├── socshark-capture/      # Trait CaptureSource + lector pcap (Rust puro)
│   ├── socshark-dissectors/   # Ethernet, IPv4, TCP, UDP, DNS + pipeline L7
│   ├── socshark-flow/         # Agregador de flujos bidireccionales
│   ├── socshark-filter/       # DSL de filtrado (lexer, parser, evaluador)
│   ├── socshark-soc/          # Ruido, DNS pasivo, riesgo, resúmenes humanos
│   ├── socshark-testgen/      # Constructores de tramas + escenario demo
│   └── socshark-cli/          # Binario `socshark` + tests de integración
├── docs/                      # Documentación completa (índice en docs/index.md)
│   ├── architecture.md        # Visión general y decisiones técnicas
│   ├── pipeline.md            # Las 4 etapas del pipeline
│   ├── data-model.md          # EnrichedFlow campo por campo
│   ├── security.md            # Modelo de privilegios y threat model
│   ├── filter-dsl.md          # Gramática y campos del DSL
│   ├── tui.md                 # La TUI Flow-First (atajos, paneles, diseño)
│   ├── ebpf-design.md         # Diseño eBPF (procesos, TLS, correlación)
│   ├── wasm-plugins.md        # Diseño del sandbox de plugins
│   ├── soc-features.md        # Funciones SOC (Flow-First, IDS, SIEM)
│   ├── soc-mitre-mapping.md   # Detecciones ↔ MITRE ATT&CK
│   ├── roadmap.md             # Fases 0-4 con criterios de aceptación
│   └── decisions.md           # ADRs (decisiones de arquitectura)
├── examples/demo.pcap         # Captura de demostración lista para analizar
└── .github/workflows/ci.yml   # fmt + clippy -D warnings + test + build
```

## Calidad

- **94 tests** unitarios y de integración (`cargo test --workspace`),
  incluido el barrido anti-panic y el reensamblado con segmentos fuera
  de orden.
- **`cargo clippy -D warnings`** y **`cargo fmt --check`** en CI, sin excepciones.
- **Parsers sin `panic`**: todo acceso a bytes está acotado; los paquetes
  malformados (incluidos los crafted por un atacante) producen `None`, nunca un crash.
- **Dependencias mínimas**: `serde`, `serde_json`, `thiserror`, `clap`,
  `anyhow` y —tras la feature `tui`, desactivable— `ratatui` + `crossterm`.
  Nada de libpcap, OpenSSL ni runtimes externos en Fase 1/2.

## Ética y uso responsable

soc-shark es una herramienta **defensiva** para analistas de SOC, Blue Team e
investigadores. Capturar tráfico de redes que no administras puede ser ilegal
en tu jurisdicción. Úsala exclusivamente en redes propias o con autorización
explícita y, en entornos laborales, conforme a tu política de monitorización.
El diseño de privilegios (`docs/security.md`) está pensado para que la
herramienta sea difícil de abusar incluso comprometida.

## Licencia

MIT — ver [LICENSE](LICENSE).
