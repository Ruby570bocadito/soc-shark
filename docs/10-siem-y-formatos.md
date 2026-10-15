# 10 · SIEM y formatos de exportación

## ECS JSONL (`--export-ecs`)

Cada flujo visible se exporta como un evento por línea en **Elastic Common
Schema** + extensión `socshark.*`. Compatible con la ingesta de
Elasticsearch/Wazuh/TheHive (JSONL directo o Filebeat con `json` codec).

```json
{"@timestamp":"2025-06-10T08:15:00.500000Z",
 "event":{"kind":"alert","category":["network"],"type":"connection",
          "severity":5,"duration":51000000000,"dataset":"socshark.flows","module":"soc-shark"},
 "source":{"ip":"192.168.1.50","port":49820},
 "destination":{"ip":"185.22.1.9","port":4444,"domain":"c2.evil-domain.ru"},
 "network":{"transport":"tcp","bytes":876,"packets":18,"protocol":"HTTP"},
 "rule":{"name":["[CRITICAL] Beaconing hacia 185.22.1.9:4444 (CV 0.00, n=6)"],
         "category":["T1071"]},
 "message":"POST /gate.php (Host: c2.evil-domain.ru)",
 "file":{"hash":{"sha256":[]}},
 "socshark":{"flow_id":10,"risk_score":100,"is_background_noise":false,
             "domain_source":"passive_dns","state":"active",
             "alerts":[...],"extracted_files":[...]}}
```

### Mapeo de campos

| soc-shark | ECS |
|-----------|-----|
| `first_seen_us` | `@timestamp` (ISO-8601 UTC) |
| `key.src` / `key.sport` | `source.ip` / `source.port` |
| `key.dst` / `key.dport` | `destination.ip` / `destination.port` |
| `resolved_domain` | `destination.domain` |
| `proto` (6/17/1) | `network.transport` (tcp/udp/icmp) |
| `l7_protocol` | `network.protocol` |
| `bytes_c2s + bytes_s2c` | `network.bytes` |
| `packet_count` | `network.packets` |
| `duration_ms` | `event.duration` (nanosegundos ECS) |
| alertas | `rule.name[]` + `rule.category[]` (MITRE) |
| severidad por riesgo | `event.severity` (1-5) |
| artefactos | `file.hash.sha256[]` |
| el resto | `socshark.*` (nombrespaced, sin riesgo de colisión) |

## Regla Suricata (`--export-suricata`)

Genera una regla `alert` para el flujo de mayor riesgo — el primer paso del
containment que el analista puede ajustar y desplegar:

```text
alert tcp 192.168.1.50:49820 -> 185.22.1.9:4444 (msg:"soc-shark: Beaconing hacia 185.22.1.9:4444 (CV 0.00, n=6)"; flow:established; sid:9000010; rev:1;)
```

## Integraciones objetivo (fase 4)

| SIEM | Camino |
|------|--------|
| **Wazuh** | evento JSONL → `/var/ossec/logs/` o comando `wazuh-logtest`; mapping ECS→Wazuh directo vía `socshark.*` custom decoder |
| **Elastic** | Filebeat `input: file` con `parsers: - json` al índice `socshark-flows-*` |
| **TheHive** | `observable.ip` / `observable.domain` / `observable.file` (sha256) generados desde el informe JSON del flujo |
| **Defender/Cortex** | script de importación sobre el mismo JSON (roadmap) |

## Atajo de teclado

En TUI/GUI: `E` exporta el flujo seleccionado (ECS JSONL a clipboard/archivo
configurable); `S` genera la regla Suricata. En CLI, hoy:
`soc-shark read ... --export-ecs out.jsonl --export-suricata out.rules`.
