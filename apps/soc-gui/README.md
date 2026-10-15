# apps/soc-gui — GUI de escritorio SOC (fase 4)

Estado: **no implementada todavía**. Esta carpeta fija el esqueleto de
componentes y el theming semántico acordados en
[`docs/09-ui-tui-gui.md`](../../docs/09-ui-tui-gui.md).

## Stack previsto

- **Tauri 2** (Rust backend, webview): consume ~10x menos RAM que Electron
  y reutiliza el motor sin duplicar capas.
- Frontend: Svelte 5 (o React 19) + TypeScript.
- Render acelerado: WebGL para el grafo de topología y las líneas de tiempo.
- Datos: gRPC/WebSocket sobre el socket UNIX del daemon (contrato: JSON de
  `EnrichedFlow` — `docs/03-modelo-de-datos.md`).

## Componentes (carpetas previstas)

| Carpeta | Componente |
|---------|-----------|
| `src/components/RadarSidebar/` | Alertas, IOCs y artefactos en vivo |
| `src/components/FlowAccordion/` | Tabla principal por conversaciones desplegables |
| `src/components/SequenceView/` | Diagrama cliente ↔ servidor paso a paso |
| `src/components/StreamInspector/` | Stream reconstruido + CyberChef (Base64/XOR/Zlib/JSON) |
| `src/components/ClassicPacketTree/` | Árbol Wireshark + hexdump (nivel de profundidad) |
| `src/components/TopologyMap/` | Grafo IP ↔ proceso en WebGL |
| `src/stores/` | Estado reactivo conectado al daemon |
| `themes/soc_dark.css` | Paleta semántica (ya incluida) |

## Regla de oro

La GUI **no re-implementa lógica**: filtrado (DSL), riesgo, resúmenes y
carving viven en el motor; la GUI solo presenta y manda comandos.
