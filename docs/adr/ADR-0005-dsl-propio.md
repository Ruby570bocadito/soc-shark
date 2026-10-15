# ADR-0005: DSL de filtrado propio (Pratt) en vez de heredar sintaxis BPF

- Estado: **aceptado** (fase 1)
- Contexto: el filtro es la interfaz principal del motor (barra de búsqueda
  de la UI, reglas de detección en fase 3). Opciones: sintaxis BPF/tcpdump,
  clonar la de Wireshark con una librería, o DSL propio.
- Decisión: DSL propio estilo Wireshark en subconjunto pragmático: campos
  punteados, operadores `== != > >= < <= contains`, booleanos `and/or/not`,
  campos a secas y literales IP validados. Implementado con lexer + Pratt
  parser + VM sobre `FactSource` (inversión de dependencias: el daemon
  implementa las fuentes de paquete y de flujo).
- Consecuencias:
  - (+) Campos SOC propios desde el día 1 (`flow.risk`, `proc.name`,
    `alert.max_severity`) que BPF no puede expresar.
  - (+) La misma expresión filtra paquetes y flujos; la VM corre en el
    motor (la UI nunca duplica semántica) y servirá para reglas Sigma
    simplificadas.
  - (−) No es sintaxis BPF: si en fases futuras se quiere offload al kernel,
    se compilará el AST a cBPF como optimización puntual (el AST es la
    fuente de verdad).
  - (−) Mantener parser propio (~500 líneas, testeadas) frente a depender de
    `nom`/`pest` — coherente con ADR-0001.
