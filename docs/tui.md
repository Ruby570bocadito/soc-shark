# La TUI de soc-shark

La interfaz de terminal (Fase 2) materializa el paradigma Flow-First: una
lista donde **cada línea es una conversación completa**, un panel lateral de
alertas SOC y una línea de filtro que habla el mismo DSL que la CLI. Está
construida con **Ratatui + crossterm** (feature `tui`, activada por defecto;
`cargo build --no-default-features` la excluye para builds mínimos).

## Arranque

```bash
socshark tui -r captura.pcap                  # toda la captura (ruido incluido, atenuado)
socshark tui -r captura.pcap -f "flow.risk >= 30"   # arranca ya filtrada
```

![La TUI con la captura de demostración](img/tui.png)

La TUI trabaja sobre **capturas guardadas** (pcap o pcapng): las analiza con
el mismo pipeline que `socshark capture` y muestra el resultado. Para ver la
red **en vivo** están la ventana (`socshark gui` → *En vivo*) y el daemon
(`socshark daemon`); que la TUI consuma el JSONL del daemon no cambiaría ni
una línea del modelo: los [`EnrichedFlow`](data-model.md) son la frontera
estable entre núcleo e interfaces.

## Atajos

| Tecla | Acción |
|---|---|
| `j` / `k`, flechas | Mover la selección en la lista de flujos |
| `g` / `G` | Saltar al primero / al último |
| `Enter` | Expandir el flujo seleccionado (panel de detalle) |
| `/` | Abrir la línea de filtro (DSL completo) |
| `Enter` (en filtro) | Aplicar el filtro; vacío = quitar filtro |
| `Esc` | Cancelar el filtro (o salir si no hay filtro activo) |
| `q` | Salir |

## Paneles

- **Lista de flujos (izquierda)**: `flow_id` canónico, protocolo L7,
  paquetes, bytes, riesgo y alertas de cada conversación. Los flujos de
  ruido de fondo se muestran atenuados en gris (*Smart Noise Dimming*), el
  riesgo medio en amarillo y el alto en rojo. La selección se resalta y el
  `flow_id` IPv6 se muestra con sus literales nativos.
- **Detalle (inferior, al expandir)**: temporalidad, volumen por dirección,
  dominio resuelto, resumen DNS (preguntas/respuestas/rcode), resumen
  humano, alertas con su técnica MITRE y —cuando llegue eBPF— proceso,
  PID y usuario.
- **Alertas SOC (derecha)**: todas las alertas de la vista actual, con la
  severidad y el flujo de origen; es el *radar* del analista.
- **Línea de estado (abajo)**: filtro activo, editor de filtro o error de
  sintaxis del DSL con la posición exacta (mismo parser que la CLI).

## Diseño y pruebas

El estado está aislado en `TuiApp` (selección con límites, vista filtrada,
expansión, edición de filtro), **testeado sin terminal** con una enum
`Key` lógica desacoplada de crossterm. El módulo `term` solo traduce
eventos de crossterm a `Key` y dibuja con Ratatui, de modo que las reglas
de comportamiento (filtrar, mover, expandir, errores de DSL que conservan
la vista anterior) quedan cubiertas por 5 tests unitarios además de los de
integración del pipeline.
