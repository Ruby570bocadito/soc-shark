# Documentación de soc-shark

Índice de toda la documentación del proyecto. La documentación está en
español y el código (identificadores y APIs) en inglés, decisión formalizada
en [decisions.md](decisions.md) (ADR-007).

## Guía de lectura por perfil

- **Quiero probarlo ya** → [README](../README.es.md) (instalación en una línea; [in English](../README.md)) y [filter-dsl.md](filter-dsl.md).
- **Quiero una ventana fácil de entender, o ver mi red en tiempo real** → [gui.md](gui.md).
- **Quiero entender cómo funciona** → [architecture.md](architecture.md) →
  [pipeline.md](pipeline.md) → [data-model.md](data-model.md).
- **Voy a contribuir código** → [decisions.md](decisions.md) (ADRs obligatorios),
  [pipeline.md](pipeline.md) y los doc-comments de cada crate.
- **Soy analista SOC** → [soc-features.md](soc-features.md) y
  [soc-mitre-mapping.md](soc-mitre-mapping.md).
- **Me importa la seguridad de la herramienta** → [security.md](security.md).
- **Quiero saber qué viene después** → [roadmap.md](roadmap.md),
  [ebpf-design.md](ebpf-design.md) y [wasm-plugins.md](wasm-plugins.md).

## Documentos

| Documento | Contenido |
|---|---|
| [architecture.md](architecture.md) | Visión general, principios, mapa de crates, decisiones técnicas de plataforma |
| [pipeline.md](pipeline.md) | Las 4 etapas del pipeline: qué hace cada una hoy y cuál es el objetivo |
| [data-model.md](data-model.md) | `EnrichedFlow` campo por campo: tipos, significado y fase de activación |
| [security.md](security.md) | Modelo de privilegios, threat model de la propia herramienta, fuzzing |
| [filter-dsl.md](filter-dsl.md) | Gramática EBNF, campos soportados, semántica de operadores, ejemplos |
| [gui.md](gui.md) | La GUI: ventana estilo Wireshark explicada en lenguaje claro, en vivo o con capturas; API local y seguridad |
| [tui.md](tui.md) | La TUI Flow-First: atajos, paneles, modo offline y paso a vivo |
| [ebpf-design.md](ebpf-design.md) | Diseño completo del módulo eBPF: probes, correlación, aya, TLS |
| [wasm-plugins.md](wasm-plugins.md) | Diseño del runtime de plugins WASM: API, límites, firma |
| [soc-features.md](soc-features.md) | Paradigma Flow-First, mini-IDS, DNS pasivo, carving, threat intel, SIEM |
| [soc-mitre-mapping.md](soc-mitre-mapping.md) | Cada detección mapeada a MITRE ATT&CK, con su estado |
| [siem-export.md](siem-export.md) | Contrato de export a SIEM (ECS y Wazuh) campo a campo |
| [roadmap.md](roadmap.md) | Fases 0-4, criterios de aceptación y dependencias entre fases |
| [decisions.md](decisions.md) | Registro de decisiones de arquitectura (ADRs) |
