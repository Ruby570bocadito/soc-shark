# ADR-0003: Paradigma Flow-First con inspección desplegable

- Estado: **aceptado** (fase 1)
- Contexto: el triaje SOC muere de fatiga de paquetes; Wireshark requiere
  "Follow TCP Stream" a mano para entender una conversación.
- Decisión: la unidad de la UI es la **conversación enriquecida**
  (`EnrichedFlow`): agrupación bidireccional por 5-tupla, dominio resuelto,
  resumen humano, riesgo y alertas. Los paquetes individuales existen
  (offsets indexados) pero son **nivel de profundidad** (acordeón `▶`,
  árbol clásico), no la vista por defecto. El ruido benigno se clasifica y
  se atenúa/oculta.
- Consecuencias:
  - (+) El triaje se lee en segundos; el motor SOC trabaja sobre flujos
    (beaconing, carving) sin el ruido de flags TCP.
  - (+) El contrato UI es estable y serializable (JSON/ECS).
  - (−) El usuario "de Wireshark" debe cambiar de hábito; se conserva el
    árbol clásico como pestaña opcional para no perder potencia.
  - (−) La agrupación bidireccional requiere mapear ambas direcciones de la
    tupla al mismo flujo (`SessionTable::get_or_create` prueba directa e
    invertida).
