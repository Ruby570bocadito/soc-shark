# 11 · Hoja de ruta

La base (fase 1) está **completa y probada** (99 tests). Las fases siguientes
acumulan sobre contratos ya estables.

## ✅ Fase 1 — El esqueleto y el motor (hecho)

Criterios de aceptación **cumplidos**:

- [x] Workspace Rust monorepo que compila **sin dependencias externas**.
- [x] Lectura pcap (μs/ns, ambos endianness) + pcapng (EPB/SPB/tsresol).
- [x] Dissectors manuales Ethernet, ARP, VLAN, IPv4, IPv6, TCP, UDP, ICMP,
      DNS (compresión), HTTP/1.1, TLS ClientHello (JA4-like).
- [x] Salida estructurada JSON (`--json`, `--events`) y tabla SOC.
- [x] Flow-First: conversaciones bidireccionales, passive DNS, resumen
      humano, noise dimming.
- [x] Motor SOC: beaconing, carving+Masquerading, port mismatch, DNS
      tunneling, direct-IP, IOCs offline, ECS + Suricata.
- [x] Filter DSL (Pratt) sobre flujos y paquetes.
- [x] Suite anti-panic + escenario demo reproducible.

## Fase 2 — Captura en vivo, daemon y TUI

- [ ] `PacketSource` en vivo: libpcap (feature `live`) y AF_XDP (Linux).
- [ ] **mmap store** (`memmap2`, ADR de dependencia): capturas de 20 GB con
      RAM constante; `CaptureIndex` ya guarda offsets.
- [ ] **soc-shark-daemon**: captura con CAP_NET_RAW → shm; engine/UI sin
      privilegios (gRPC sobre UNIX socket) — `docs/07-seguridad.md` §3.
- [ ] **Pipeline multihilo** con `SpscRing` (etapa captura → disección).
- [ ] **TUI Ratatui**: tabla virtualizada de flujos, acordeón `▶`, filtro
      DSL en vivo, `E` export ECS, navegación Vim.
- [ ] tcp_reassembly (streams TCP) para carving multi-paquete y
      `StreamInspector`.
- Criterio: capturar 5 min en una interfaz real sin drops > 0.1% a 100 Mbps
  y triajear en la TUI sin salir a la shell.

## Fase 3 — La magia de eBPF

- [ ] `sock_tracker.bpf.c` (`inet_sock_set_state`, `tcp_v4_connect`) + mapa
      kernel→user con TTL → columna Proceso/PID.
- [ ] `tls_uprobe.bpf.c` (OpenSSL/BoringSSL/GnuTLS) → plaintext sin
      SSLKEYLOGFILE (solo bajo privilegios, documentado y marcado).
- [ ] Resolución `/proc`: exe, cmdline, usuario, contenedor Docker/K8s.
- [ ] JA4 canónico + JA4+ y HASSH (SSH KEXINIT disector).
- [ ] Reglas Sigma simplificadas evaluadas sobre el DSL.
- [ ] MMDB offline (GeoIP/ASN) + feeds IOC locales actualizables.
- Criterio: el demo ejecutado en laboratorio muestra proceso correcto y el
  filtro `proc.name == python3` aísla el beacon.

## Fase 4 — GUI moderna y SOC diario

- [ ] Tauri + Svelte: FlowAccordion, RadarSidebar, SequenceView,
      StreamInspector (CyberChef), ClassicPacketTree, TopologyMap WebGL.
- [ ] Virtual scrolling sobre `CaptureIndex` (1 M flujos, 120 FPS).
- [ ] Exportación SIEM integrada (`E`/`S`) y generación de reglas.
- [ ] theming `soc_dark.css` + modos claro/oscuro.
- Criterio: triaje del demo en < 30 s desde abrir la app a leer el radar.

## Fase 5 — Ecosistema de plugins Wasm

- [ ] Contrato WIT del disector (bytes → eventos normalizados) y runtime
      `wasmtime` con límites de memoria/fuel.
- [ ] `plugins-sdk`: plantilla Rust→Wasm, ejemplo `custom_protocol`,
      publicación y firma de plugins.
- [ ] Marketplace local: carga de `.wasm` firmados por el operador.
- Criterio: un disector de protocolo C2 custom corre sandboxeado sin poder
  corromper el motor (fuzz del host).

## Backlog congelado (ideas, no compromisos)

- QUIC completo (Initial + ClientHello en CRYPTO frames).
- SMB2/3 disector con carving.
- Comparador de capturas (diff de flujos entre baseline e incidente).
- Modo "cinta de incidente": exportar captura recortada al flujo seleccionado.
