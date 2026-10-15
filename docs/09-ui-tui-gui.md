# 09 · UI: TUI (fase 2) y GUI SOC (fase 4)

El motor ya entrega `EnrichedFlow` (legible, completo y estable); las UIs
son capas de presentación sobre el mismo contrato.

## El layout SOC Flow (referencia de diseño)

```text
+--------------------------------------------------------------------------------------------------+
| 🔍 Filtro: [ alert.max_severity == HIGH or proc.name == "powershell.exe" ] [Modo: SOC Flow]      |
+------------------+-------------------------------------------------------------------------------+
| RADAR SOC (IOCs) | FLUJO/TIEMPO      | ORIGEN (PROCESO)      | DESTINO (CONTEXTO) | RESUMEN   |
|------------------|-------------------|-----------------------|--------------------|-----------|
| 🚨 Alertas (3)   | ▼ #104 10:14:02   | 💻 192.168.1.50:49812 | 🌍 185.22.1.9:4444 | 🚨 Beacon |
|  - Beaconing C2  |   (Dur: 51.0s)    | ⚙️ powershell.exe     | [c2.evil-domain.ru]| POST /up  |
|  - SMB Lateral   |   ├─ Pkt 1 [SYN]  |    (PID: 4120)        | Sin DNS previo     |           |
|  - DNS Tunneling |   └─ +16 paquetes |                       |                    |           |
| 📦 Artefactos(2) | ▶ #105 10:14:05   | ⚙️ svchost.exe        | 🖥️ DC01.corp.local | 🔑 SMBv2  |
+------------------+-------------------------------------------------------------------------------+
| DETALLE DEL FLUJO (#104)                                                                         |
| [Línea de Tiempo] [Stream Decodificado] [Árbol clásico/Hex]                                      |
+--------------------------------------------------------------------------------------------------+
```

## TUI (fase 2) — Ratatui

- **Tabla virtualizada de flujos** (una fila = `EnrichedFlow`), colores por
  `risk_score`, ruido gris tenue u oculto (tecla `n`).
- Barra de filtro con el DSL real (autocompletado del catálogo
  `registry::FIELDS`), re-evaluación instantánea vía `FlowFacts`.
- Acordeón `▶/▼`: al expandir, el motor lee `packet_offsets` del
  `CaptureIndex` (mmap) y renderiza la lista de paquetes del flujo.
- Navegación estilo Vim: `j/k` mover, `/` filtro, `Enter` expandir,
  `E` exportar ECS del flujo, `S` regla Suricata, `q` salir.
- Modo headless para SSH/servidores; el motor ya separa salida y análisis
  (`daemon/src/output.rs` es el esqueleto de la vista textual).

## GUI (fase 4) — Tauri + Svelte/React + WebGL

Componentes (carpetas ya creadas en `apps/soc-gui/`):

| Componente | Función |
|-----------|---------|
| `RadarSidebar/` | Alertas, IOCs y artefactos extraídos en tiempo real |
| `FlowAccordion/` | La tabla principal por conversaciones desplegables |
| `SequenceView/` | Diagrama cliente↔servidor paso a paso (handshake → POST → descarga) |
| `StreamInspector/` | Conversación reconstruida + decodificador CyberChef (Base64/XOR/Zlib/JSON) |
| `ClassicPacketTree/` | Árbol estilo Wireshark + hexdump (solo cuando se baja al bit) |
| `TopologyMap/` | Grafo IP↔proceso en WebGL |

Datos: WebSockets/gRPC sobre el socket UNIX del daemon; el estado reactivo
consume `EnrichedFlow` JSON (contrato ya congelado en `docs/03`).

## Paleta semántica (`apps/soc-gui/themes/soc_dark.css`)

- **Rojo** `#e5484d` — CRITICAL / riesgo ≥ 60
- **Ámbar** `#f5a623` — HIGH-MEDIUM / riesgo ≥ 30
- **Gris tenue** `#6b7280` — ruido de fondo
- **Cian** `#4cc2ff` — información/selección
- Tipografía monoespaciada para tablas; densidad configurable.

Los mismos colores que ya emite el CLI vía `common::ansi` (fuente única de
verdad semántica).

## Rendimiento objetivo

- 120 FPS de scroll con 1 M de flujos: virtual scrolling sobre
  `CaptureIndex` (paginación mmap).
- El filtrado corre en el motor (DSL compilado una vez) — la UI nunca
  re-implementa la semántica.
