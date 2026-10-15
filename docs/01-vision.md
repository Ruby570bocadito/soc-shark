# 01 · Visión y objetivos

## El problema

Wireshark es la herramienta de disección más completa del mundo, pero fue
diseñada para ingeniería de protocolos, no para triaje de incidentes. Cuando
un analista SOC abre una captura se encuentra con tres fricciones que el
diseño de soc-shark ataca de frente:

1. **Fatiga de paquetes.** Una sola petición web genera decenas de filas
   (`SYN`, `ACK`, `PSH`, retransmisiones) mezcladas con ruido de fondo
   (ARP, mDNS, SSDP, NTP). El analista reconstruye mentalmente qué ocurrió
   en lugar de leerlo.
2. **Contexto perdido.** Se ven IPs y puertos; el dominio de la consulta
   DNS previa, el proceso local responsable o el país/ASN del destino
   requieren tres ventanas y memoria de trabajo.
3. **Detección delegada.** Para saber si hay beaconing, un ejecutable
   camuflado o DNS tunneling, hay que exportar a otra herramienta o escribir
   plugins en C — con el riesgo de explotación que eso implica.

## La respuesta: Flow-First + SOC nativo

soc-shark cambia el paradigma de la **tabla de paquetes** a la **tabla de
conversaciones enriquecidas**:

- Una conversación TCP/UDP completa es **una fila** desplegable (`▶`),
  con proceso local (fase 3), dominio resuelto, resumen en lenguaje humano
  y riesgo 0-100.
- El ruido benigno se **etiqueta y atenúa** (oculto por defecto).
- Un panel **Radar SOC** resume alertas e IOCs en los primeros segundos de
  triaje; el árbol clásico estilo Wireshark queda disponible como nivel de
  profundidad opcional ("bajada al bit").

## Killer features (roadmap completo)

| # | Feature | Estado |
|---|---------|--------|
| 1 | **Atribución de procesos vía eBPF** — `[PID: 4812 \| binario: python3 \| usuario: www-data]` en cada flujo | diseño (fase 3) |
| 2 | **Desencriptado TLS 1.3 transparente** — uprobes a `SSL_read`/`SSL_write` sin `SSLKEYLOGFILE` | diseño (fase 3) |
| 3 | **Plugins de disección en Wasm** — dissectors de terceros sandboxeados, sin riesgo de memoria | diseño (fase 5) |
| 4 | **Decodificador estilo CyberChef** — tuberías Base64 → XOR → Zlib → JSON beautifier sobre el payload | diseño (fase 4) |
| 5 | **Fingerprinting pasivo** — JA4-like (ClientHello) ya implementado; JA4+ y HASSH en fase 3 | parcial |
| 6 | **Motor SOC nativo** — beaconing, carving+Masquerading, DNS tunneling, port mismatch, IOCs offline | **fase 1 ✅** |
| 7 | **Exportación SIEM** — ECS JSONL y regla Suricata en un flag | **fase 1 ✅** |

## Comparativa honesta

| Capacidad | Wireshark | Zeek | soc-shark f1 |
|---|---|---|---|
| Disección profunda de protocolos | ★★★ | ★★ | ★ (Eth/TCP/UDP/DNS/HTTP/TLS) |
| Lectura de conversaciones por defecto | ✗ | parcial | ✓ |
| Dominio junto a la IP sin lookup manual | parcial | ✓ | ✓ (passive DNS) |
| Ruido atenuado por defecto | ✗ | ✗ | ✓ |
| Proceso local responsable | ✗ | ✗ | fase 3 (eBPF) |
| Detección integrada (beaconing/carving) | ✗ | scripting | ✓ heurísticas |
| Memoria segura ante paquetes maliciosos | C (riesgo) | C | **Rust std-only** |
| Salida SIEM directa | ✗ | ✓ logs | ✓ ECS JSONL |

La apuesta no es "más dissectors que Wireshark" (alcanzable e
innecesario), sino **mejor triaje por defecto** y una base de motor segura
donde la comunidad pueda añadir dissectors sin riesgo (Wasm, fase 5).

## Principios de producto

1. **El triaje manda**: la vista por defecto responde "¿qué pasó?" en
   segundos; el detalle de bits es opcional, no obligatorio.
2. **Cero sorpresas de seguridad**: nada de evaluar contenido de red en
   código sin sandbox; std-only y memoria segura primero.
3. **Offline-first**: GeoIP/ASN y IOCs locales; nada de telefonar a APIs de
   terceros con evidencias del incidente.
4. **Evidencia exportable**: todo lo que ves sale en ECS para el SIEM.
