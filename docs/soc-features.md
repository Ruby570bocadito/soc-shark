# Funciones SOC

Este documento describe la capa que hace de soc-shark una herramienta de
*análisis de seguridad* y no un tcpdump bonito: el paradigma Flow-First, la
traducción semántica, el Smart Noise Dimming, el mini-IDS heurístico, el DNS
pasivo y el plan de carving, threat intel y export SIEM. Cada sección indica
su estado (implementado / diseñado).

## Paradigma Flow-First (implementado)

La unidad de trabajo del analista no es el paquete: es la **sesión**. Un flujo
completo se presenta como una línea (`EnrichedFlow` → tabla hoy, acordeón en
la UI futura) y solo se expande a paquetes bajo demanda. Las consecuencias
de diseño ya visibles en Fase 1:

- Los contadores son **bidireccionales por dirección** (`packets/bytes` vs
  `packets_rev/bytes_rev`): la asimetría es una de las señales más baratas y
  más potentes. Un flujo con 8 paquetes hacia un servicio y 0 de vuelta no
  es "conversación": es sondeo o envío.
- Las alertas viven **en el flujo**, no en el paquete: el mini-IDS puede
  usar el historial completo de flags y volúmenes, no solo el byte actual.
- El filtro opera sobre campos enriquecidos (`flow.risk`, `dns.qname`), no
  solo sobre cabeceras: seleccionar "todo lo sospechoso" es una expresión,
  no una sesión de treinta filtros compuestos.

## Traducción semántica: `human_summary` (implementado)

Cada flujo lleva una línea en lenguaje humano generada por
`socshark-soc::summarize`. El objetivo es que un analista de guardia entienda
la sesión sin abrir el detalle:

- `DNS 192.168.1.30:53002 → 8.8.8.8:53: consulta az3k9...chfdgs.tun.evil.example (TXT)`
- `TLS 192.168.1.10:52000 → 93.184.216.34:443 · 7 paq · 406 B · cerrado · destino: example.com`
- `[ruido] NTP 192.168.1.10:123 → 17.253.0.1:123 · 1 paq · 76 B`

La prioridad de composición es: protocolo → dirección → detalle específico
del protocolo (qname, banner, método) → estado TCP → dominio resuelto →
resumen de alertas. En Fase 3 el resumen ganará "· proceso: /usr/bin/curl"
con la atribución eBPF.

## Smart Noise Dimming (implementado)

El 70-90% del volumen de una red corporativa es tráfico de mantenimiento que
oculta lo importante. La solución no es filtrarlo (se pierde contexto) sino
**marcarlo y atenuarlo**: `is_background_noise = true` y la UI lo muestra en
gris, colapsado o fuera de la vista por defecto, siempre recuperable con
`--show-noise`.

Puertos clasificados como ruido en Fase 1 (UDP, ambos extremos): NTP 123,
mDNS 5353, LLMNR 5355, SSDP 1900, NetBIOS 137/138, DHCP 67/68, rpcbind 111,
SNMP 161, syslog 514. TCP no se marca como ruido todavía (Fase 2 añadirá
sondeos de broadcast) y ARP se marcará cuando exista su dissector. El
criterio es conservador: es preferible mostrar de más que ocultar una señal.

## Mini-IDS heurístico (implementado)

Reglas de Fase 1, cada una con su mapeo MITRE (tabla completa en
[soc-mitre-mapping.md](soc-mitre-mapping.md)). El motor es aditivo: cada
regla suma a `risk_score` (tope 100) y emite alerta al superar su umbral.

| ID | Regla | Señal | Riesgo | Estado |
|---|---|---|---|---|
| `DNS-TUNNELING` | qname con longitud ≥ 30 **y** entropía de Shannon ≥ 3.5 | subdominios codificados (base32/hex) de exfiltración o C2 | +45 | **implementado** |
| `PORT-SCAN` | ≥ 4 SYNs sin ningún ACK de respuesta hacia el mismo (origen, destino, puerto) — tracker *entre flujos* | escaneo SYN (cada SYN cambia de puerto origen: patrón invisible por flujo aislado) | +30 | **implementado** |
| `INSECURE-PORT` | conexión a telnet 23/tcp | credenciales y comandos en texto claro | +35 | **implementado** |
| `EXPOSED-DB` | conexión directa a 3306/5432/1433/6379/27017 | base de datos alcanzable desde la red observada | +25 | **implementado** |

La entropía de Shannon por carácter distingue `www.ejemplo-corporativo.com`
(≈2.3 bits) de `az3k9t2wq7xm5vb8n...chfdgs` (≈4.9 bits). El umbral y la
longitud son configurables en `PipelineConfig` (`dns_entropy_threshold`,
`dns_tunnel_min_len`) para afinar por entorno sin tocar código.

## Passive DNS (implementado)

La base de DNS pasivo (`socshark-soc::passive_dns`) cachea las asociaciones
dominio ↔ IP de **todas las respuestas DNS observadas** y las reutiliza para
etiquetar cualquier flujo hacia esas IPs (`resolved_domain`). Es la respuesta
a la pregunta más frecuente del triage: *¿a qué dominio pertenece esta IP
con la que habla este binario?* — respondida sin consultas externas y sin
depender del orden (la resolución puede llegar después del flujo TCP; el
enriquecimiento se hace en dos pasadas sobre la captura completa).

En Fase 4 esta base persistirá en disco y expondrá la vista inversa
(¿qué IPs ha resuelto este dominio en las últimas horas?), el insumo básico
para cazar infraestructura compartida.

## File carving con detección de masquerading (Fase 4 — diseñado)

El reassembler de streams (Fase 2) permite reconstruir archivos transferidos
por HTTP y otros protocolos de texto. El pipeline previsto:

1. Detectar límites de objeto (cabeceras HTTP Content-Disposition/Content-Type
   y fronteras multipart).
2. Confirmar el tipo real con **magic bytes** (librería propia de firmas:
   PE32, ELF, PDF, ZIP, DOCX, JPEG...).
3. **SHA-256** del contenido (para VirusTotal/SIEM laterales) sin volcar a
   disco por defecto.
4. **T1036 Masquerading**: si el nombre declarado dice `.jpg` pero el magic
   dice PE32 → alerta inmediata y marcado `masquerading_suspect` (campo ya
   presente en `ExtractedFile`).

## Threat intel offline (Fase 4 — diseñado)

Sin conexión saliente: las bases se descargan aparte y se cargan como
archivos locales firmados. Piezas previstas: GeoIP/ASN (MaxMind GeoLite2)
para `dst_geo_asn` (campo ya en el modelo), listas de IOCs (Feodo Tracker de
C2 activos, Tor exit nodes), y comparación de `ja4_fingerprint` contra
listas públicas de malware. Toda coincidencia es una alerta `INFO`/`MEDIUM`
con la fuente citada, nunca una decisión automática de bloqueo.

## Detección de beaconing (Fase 3 — diseñado)

Algoritmo previsto sobre los `first_seen/last_seen` de los flujos por
(destino, puerto): agrupar intervalos entre conexiones de un mismo origen,
calcular regularidad (desviación estándar / media) y exigir mínimos de
muestras (≥ 8) y duración (≥ 30 min). Regularidad > 0.9 con jitter bajo es
el perfil de un implante con sleep fijo; el ruido humano no cumple ninguno
de los dos. Se emitirá como `T1071` (Application Layer Protocol) con el
periodo estimado en el detalle ("cada ~60.2s ±1.3s").

## Export a SIEM (Fase 4 — diseñado, contrato ya operativo)

El JSONL de hoy es ya el contrato de exportación. La capa ECS añadirá el
mapeo siguiente (transformación pura, sin tocar el núcleo):

| `EnrichedFlow` | ECS 8.x |
|---|---|
| `src_ip`/`dst_ip` | `source.ip` / `destination.ip` |
| `src_port`/`dst_port` | `source.port` / `destination.port` |
| `transport` | `network.transport` (normalizado: TCP→tcp...) |
| `l7_protocol` | `network.protocol` |
| `bytes + bytes_rev` | `network.bytes` |
| `packets + packets_rev` | `network.packets` |
| `first_seen_micros` | `@timestamp` |
| `resolved_domain` | `dns.question.name` / `destination.domain` |
| `process_name`/`pid` | `process.name` / `process.pid` |
| `risk_score`/`alerts` | `risk.score` / `message` + `rule.name` |

Además de ECS: salida nativa para Wazuh (decoder + reglas de ejemplo) y
case-management hacia TheHive (cada alerta ≥ HIGH como observable-artifact
agrupado por `flow_id`).
