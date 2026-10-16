# Export a SIEM

`socshark export` convierte los flujos enriquecidos de una captura a los
formatos que consumen los SIEM/EDR de laboratorio, sin tocar el núcleo del
pipeline (es una transformación pura sobre `EnrichedFlow`, módulo
`socshark-soc::siem`). Este documento es el contrato campo a campo: si algo
cambia, cambia aquí primero.

```bash
socshark export -r captura.pcap -F ecs   -o ecs.jsonl     # Elastic Common Schema
socshark export -r captura.pcap -F wazuh -o wazuh.jsonl   # decoder JSON de Wazuh
```

Flags compartidos con `capture`: `--filter`, `--show-noise`,
`--carve-files`, `--intel-feodo`, `--intel-tor` — el export ejecuta el
pipeline completo, así que los archivos tallados y las etiquetas intel
aparecen en el evento exportado.

## Formato ECS (`-F ecs`)

Un objeto JSON por línea. Campos estándar ECS 8.x donde existen; espacio
propio anidado `socshark.*` para lo que ECS no cubre (convención para campos
personalizados: la referencia `socshark.risk_score` corresponde al objeto
anidado `{"socshark": {"risk_score": ...}}`).

| `EnrichedFlow` | ECS | Notas |
|---|---|---|
| `first_seen_micros` | `@timestamp` | ISO-8601 UTC con microsegundos, conversión civil propia (ADR-012) |
| `src_ip` / `dst_ip` | `source.ip` / `destination.ip` | |
| `src_port` / `dst_port` | `source.port` / `destination.port` | |
| `transport` | `network.transport` | `tcp`/`udp`/`icmp`/`other` |
| `l7_protocol` | `network.protocol` | `dns`/`http`/`tls`/`ssh`/`ntp`/`dhcp`/`unknown` |
| `bytes + bytes_rev` | `network.bytes` | |
| `packets + packets_rev` | `network.packets` | |
| `duration_micros` | `event.duration` | **nanosegundos** (convención ECS) |
| `risk_score` | `event.severity` + `socshark.risk_score` | |
| `flow_id` | `flow.id` + `network.community_id` | el id canónico hace de correlador; sin hash de tuple 5-tuple por ahora |
| `src_mac` / `dst_mac` | `source.mac` / `destination.mac` | si la captura es Ethernet |
| `resolved_domain` | `destination.domain` | |
| `process_name` / `pid` / `user` | `process.name` / `process.pid` / `user.name` | vacíos hasta la correlación eBPF (Fase 3) |
| `dns` | `dns.question.*`, `dns.response_code`, `dns.answers[]` | `{name, type, data, ttl}` por respuesta |
| `tls_sni` | `tls.client.server_name` | campo ECS estándar |
| `ja4_fingerprint` | `tls.ja4` | extensión práctica (ECS aún no define JA4) |
| `alerts` | `rule.name[]`, `message`, `threat.technique.id[]` | IDs MITRE sin duplicados |
| `is_background_noise` | `socshark.background_noise` | |
| `state` | `socshark.flow_state` | `activo`/`inactivo`/`cerrado` |
| `threat_intel` | `socshark.threat_intel[]` | `FEODO-C2`, `TOR-EXIT` |
| `extracted_files` | `socshark.extracted_files[]` | `{name, size, sha256, magic, masquerading_suspect}` |
| `human_summary` | `socshark.human_summary` | la línea legible en español |

Constantes del evento: `event.module = "socshark"`,
`event.dataset = "network.flows"`, `event.kind = "event"`,
`event.category = ["network"]`, `event.type = ["connection"]`.

## Formato Wazuh (`-F wazuh`)

Evento plano pensado para el decoder JSON del manager (ingesta por fichero
con Filebeat/`socket` o agente). Los campos de cabecera que Wazuh reconoce
de serie alimentan sus dashboards de red sin decoders custom:

| Clave | Contenido |
|---|---|
| `program_name` | `"socshark"` (identifica el origen en los decoders) |
| `timestamp` | ISO-8601 UTC (mismo cálculo que ECS) |
| `srcip` / `srcport` / `dstip` / `dstport` / `protocol` | extremos del flujo (reconocidos de serie) |
| `data.socshark` | `{flow_id, risk_score, background_noise, l7, bytes, packets, duration_secs, human_summary}` |
| `data.domain` / `data.dns_qname` | dominio resuelto / qname propio |
| `data.tls_sni` / `data.tls_ja4` | SNI y huella JA4 |
| `data.threat_intel` | etiquetas offline (`FEODO-C2`, `TOR-EXIT`) |
| `data.extracted_files` | archivos tallados con su SHA-256 |
| `rule.level` | **solo con alertas**: severidad máxima mapeada a la escala Wazuh 0-15 (ver tabla) |
| `rule.description` | nombres de las alertas unidos por `; ` |
| `rule.mitre.id` | IDs ATT&CK de las alertas → módulo ATT&CK del manager |

Mapeo de severidad → `rule.level` de Wazuh:

| Severity (soc-shark) | `rule.level` (Wazuh) |
|---|---|
| Info | 2 |
| Low | 4 |
| Medium | 6 |
| High | 10 |
| Critical | 13 |

Un flujo **sin alertas** exporta sin `rule`: Wazuh lo archiva como evento
(no lo trata como alerta), que es exactamente el comportamiento deseado —
el volumen completo fluye al SIEM, pero solo las detecciones ruidan.

## Ingesta de laboratorio (receta Wazuh)

1. Exporta con `-F wazuh -o socshark.jsonl` y copia el fichero al manager
   (o móntalo en `/var/log/socshark/`).
2. Declara un localfile que lea el JSONL y el decoder JSON de serie hará el
   resto: `srcip`/`dstip` entran como campos indexados y `rule.level`
   eleva el evento a alerta.
3. Para indexar los MITRE, activa el módulo ATT&CK del manager
   (`alertsConfig`/`mitre`) — los IDs llegan en `rule.mitre.id`.
4. Las reglas de correlación específicas (p. ej. subir el nivel si
   `data.threat_intel` no está vacío) se escriben como reglas hijas del
   decoder `socshark`, fuera del alcance de la herramienta.

## Limitaciones declaradas

- `network.community_id` lleva el id canónico de soc-shark, no el hash
  oficial Community ID (requires SHA-1 sobre la 5-tuple normalizada); es un
  correlador interno estable, no el estándar. Cambiará si un SIEM lo exige.
- TheHive queda pendiente: el push por API exigiría un cliente HTTP propio
  (ADR-003 prohíbe dependencias nuevas para esto); el camino hoy es
  SIEM → TheHive mediante su integración nativa.
- El export es de archivo (`-r`); el daemon en vivo emite el JSONL nativo de
  soc-shark, cuya traducción a ECS/Wazuh puede hacerse con cualquier
  transformador externo o una pasada posterior de `export` sobre el pcap
  rotado.
