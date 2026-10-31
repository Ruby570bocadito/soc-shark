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
| `flow_id` | `socshark.flow_id` + `network.community_id` | el id canónico hace de correlador; sin hash de tuple 5-tuple por ahora |
| `src_mac` / `dst_mac` | `source.mac` / `destination.mac` | si la captura es Ethernet; formato ECS: mayúsculas separadas por guiones (`AA-BB-CC-DD-EE-FF`) |
| `src_ip` + `dst_ip` (calculado) | `network.direction` | `internal` (ambos extremos en red privada/local), `outbound` (de interna a externa), `inbound` (de externa a interna), `external` (ninguno interno) |
| `resolved_domain` | `destination.domain` | |
| `process_name` / `pid` / `user` | `process.name` / `process.pid` / `user.name` | vacíos hasta la correlación eBPF (Fase 3) |
| `dns` | `dns.question.*`, `dns.response_code`, `dns.answers[]` | `{name, type, data, ttl}` por respuesta |
| `tls_sni` | `tls.client.server_name` | campo ECS estándar |
| `ja4_fingerprint` | `socshark.tls_ja4` | ECS 8.x no define JA4: va en el espacio propio para validar contra el esquema |
| `alerts` | `rule.name[]`, `message`, `threat.technique.id[]` | IDs MITRE sin duplicados |
| `is_background_noise` | `socshark.background_noise` | |
| `state` | `socshark.flow_state` | `activo`/`inactivo`/`cerrado` |
| `threat_intel` | `socshark.threat_intel[]` | `FEODO-C2`, `TOR-EXIT` |
| `extracted_files` | `socshark.extracted_files[]` | `{name, size, sha256, magic, masquerading_suspect}` |
| `human_summary` | `socshark.human_summary` | la línea legible en español |

Constantes del evento: `event.module = "socshark"`,
`event.dataset = "network.flows"`, `event.category = ["network"]`,
`event.type = ["connection"]`. `event.kind` depende del flujo: `"alert"` si
tiene al menos una alerta y `"event"` si no (así los paneles de detecciones
de Elastic filtran por `event.kind: alert` sin reglas propias).

### Validación contra el esquema oficial

El test `crates/socshark-soc/tests/ecs_schema.rs` pasa los escenarios de
`socshark-testgen` por el pipeline completo (más una variante con todos los
campos opcionales poblados), genera los eventos con `to_ecs` y comprueba
cada ruta de campo contra la definición plana oficial de ECS
(`ecs_flat.yml`): que el campo exista y que el tipo JSON encaje con el tipo
ECS (`long` → entero, `keyword`/`date` → cadena, `ip` → IP válida,
`boolean` → booleano, `object` → objeto). Solo `socshark.*` y `labels.*`
quedan fuera del esquema, de forma explícita. El job `ecs` de CI descarga
la versión fijada (v8.11.0) y lo ejecuta; en local:

```bash
curl --proto '=https' -fsSLo ecs_flat.yml \
  https://raw.githubusercontent.com/elastic/ecs/v8.11.0/generated/ecs/ecs_flat.yml
SOCSHARK_ECS_FLAT=ecs_flat.yml cargo test -p socshark-soc --test ecs_schema
```

Sin `SOCSHARK_ECS_FLAT` el test avisa y se omite (así `cargo test` no
necesita red).

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
| `rule.level` | **solo con alertas**: severidad máxima mapeada a la escala Wazuh 0-15 (ver tabla). Es un dato más del evento, **no** fija el nivel de la alerta (ver abajo) |
| `rule.description` | nombres de las alertas unidos por `; ` |
| `rule.mitre.id` | IDs ATT&CK de las alertas (como dato; ver abajo) |

**Importante: lo decide Wazuh, no el JSON.** El decoder JSON de serie
extrae los campos del evento, pero en la alerta los que no son estáticos
(`srcip`, `dstip`, `srcport`, `dstport`, `protocol`…) aparecen bajo
`data.*` (`data.rule.level`, `data.rule.mitre.id`, …). El `rule.level` y el
`rule.mitre` reales de una alerta Wazuh los ponen **sus reglas**; un evento
que no case con ninguna regla de nivel ≥ `log_alert_level` no genera
alerta. Por eso la receta de abajo incluye reglas propias que leen el
`rule.level` sugerido por soc-shark.

Mapeo de severidad → `rule.level` sugerido:

| Severity (soc-shark) | `rule.level` (Wazuh) |
|---|---|
| Info | 2 |
| Low | 4 |
| Medium | 6 |
| High | 10 |
| Critical | 13 |

Un flujo **sin alertas** exporta sin `rule`: con las reglas de la receta
queda en nivel 0 (solo en el archivo de eventos si `logall` está activo),
que es el comportamiento deseado: el volumen completo puede llegar al SIEM,
pero solo las detecciones generan alerta.

## Ingesta de laboratorio (receta Wazuh)

1. Exporta con `-F wazuh -o socshark.jsonl` y copia el fichero al manager
   (o móntalo en `/var/log/socshark/`).
2. Declara un `localfile` con `<log_format>json</log_format>` que lea el
   JSONL: el decoder JSON de serie extrae los campos (`srcip`/`dstip`
   indexados; el resto bajo `data.*`). Esto **por sí solo no genera
   alertas**.
3. Copia las reglas de [`docs/wazuh/local_rules.xml`](wazuh/local_rules.xml)
   en el `local_rules.xml` del manager. Traducen el nivel sugerido a nivel
   real de alerta, etiquetan cada técnica MITRE que emite soc-shark y suben
   a 12 los destinos en threat intel. El test
   `crates/socshark-soc/tests/wazuh_contract.rs` comprueba en cada
   `cargo test` que el JSON tiene la forma que esas reglas esperan y que
   ninguna técnica ni nivel se queda sin regla (pendiente: probarlas contra
   un manager real con `wazuh-logtest`). Lo esencial de esas reglas:

   ```xml
   <group name="socshark,">
     <rule id="100200" level="0">
       <decoded_as>json</decoded_as>
       <field name="program_name">^socshark$</field>
       <description>soc-shark: flujo de red</description>
     </rule>
     <rule id="100201" level="4">
       <if_sid>100200</if_sid>
       <field name="rule.level">^4$|^6$</field>
       <description>soc-shark: $(rule.description)</description>
     </rule>
     <rule id="100202" level="10">
       <if_sid>100200</if_sid>
       <field name="rule.level">^10$</field>
       <description>soc-shark: $(rule.description)</description>
     </rule>
     <rule id="100203" level="13">
       <if_sid>100200</if_sid>
       <field name="rule.level">^13$</field>
       <description>soc-shark: $(rule.description)</description>
     </rule>
   </group>
   ```

   (Ajusta los niveles y los IDs a tu instalación; `Info` = 2 queda por
   debajo del `log_alert_level` por defecto y no alerta.)
4. MITRE: el módulo ATT&CK del manager usa el bloque `<mitre>` de la
   **regla** que dispara, no el JSON. Para verlo, crea reglas hijas por
   técnica (p. ej. `<field name="rule.mitre.id">T1071.004</field>` con
   `<mitre><id>T1071.004</id></mitre>`); sin ellas, los IDs quedan
   disponibles como dato en `data.rule.mitre.id`.
5. Otras correlaciones (p. ej. subir el nivel si `data.threat_intel` no
   está vacío) se escriben igual, como reglas hijas de `100200`, fuera del
   alcance de la herramienta.

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
