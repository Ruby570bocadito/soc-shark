# Documentación de soc-shark

Índice de toda la documentación del proyecto. La documentación está en
español y el código (identificadores y APIs) en inglés, decisión formalizada
en [decisions.md](decisions.md) (ADR-007).

## Guía de lectura por perfil

- **Quiero probarlo ya** → [README](../README.md#inicio-rápido) y [filter-dsl.md](filter-dsl.md).
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
| [ebpf-design.md](ebpf-design.md) | Diseño completo del módulo eBPF: probes, correlación, aya, TLS |
| [wasm-plugins.md](wasm-plugins.md) | Diseño del runtime de plugins WASM: API, límites, firma |
| [soc-features.md](soc-features.md) | Paradigma Flow-First, mini-IDS, DNS pasivo, carving, threat intel, SIEM |
| [soc-mitre-mapping.md](soc-mitre-mapping.md) | Cada detección mapeada a MITRE ATT&CK, con su estado |
| [roadmap.md](roadmap.md) | Fases 0-4, criterios de aceptación y dependencias entre fases |
| [decisions.md](decisions.md) | Registro de decisiones de arquitectura (ADRs) |
