# Índice de documentación

| # | Documento | Qué encontrarás |
|---|-----------|-----------------|
| 01 | [Visión y objetivos](01-vision.md) | El problema de Wireshark para un SOC, killer features y comparativa |
| 02 | [Arquitectura](02-arquitectura.md) | Pipeline de datos, crates del monorepo, threading y plan de almacenamiento |
| 03 | [Modelo de datos](03-modelo-de-datos.md) | `PacketRecord`, `DissectedPacket`, `EnrichedFlow`, JSON de ejemplo |
| 04 | [Dissectors](04-dissectors.md) | Protocolos soportados, reglas de seguridad y guía para añadir nuevos |
| 05 | [Filter DSL](05-filter-dsl.md) | Gramática, catálogo de campos, ejemplos de consultas |
| 06 | [Motor SOC](06-soc-engine.md) | Detectores, umbrales, risk score y mapeo MITRE ATT&CK |
| 07 | [Seguridad](07-seguridad.md) | Modelo de amenazas, separación de privilegios, cadena de suministro |
| 08 | [eBPF (fase 3)](08-ebpf.md) | Atribución de procesos, llaves TLS por uprobes, diseño de maps |
| 09 | [UI: TUI y GUI](09-ui-tui-gui.md) | Layout SOC Flow, componentes Tauri, paleta semántica |
| 10 | [SIEM y formatos](10-siem-y-formatos.md) | ECS, Wazuh, Elastic, TheHive, reglas Suricata |
| 11 | [Hoja de ruta](11-hoja-de-ruta.md) | Fases 1-5 con criterios de aceptación y backlog |
| ADR | [adr/](adr/) | Decisiones arquitectónicas registradas |

## Convenciones

- Idioma: **español** (términos técnicos en inglés cuando son estándar del sector).
- Código: identificadores en inglés, comentarios y docs en español.
- Los ejemplos de salida provienen del escenario demo real
  (`tools/gen_demo_pcap.py` → `examples/demo_soc_incident.pcap`).
