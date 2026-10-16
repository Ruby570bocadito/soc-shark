# Mapeo a MITRE ATT&CK

Toda detección de soc-shark se documenta con su técnica ATT&CK Enterprise
correspondiente. La columna Estado distingue lo ya implementado y testeado
de lo diseñado para su fase. Este documento es también el contrato con los
SIEM: los `alerts[].mitre` del JSONL llevan exactamente estos IDs.

## Enterprise ATT&CK v15 — cobertura actual

| ID | Técnica | Detección en soc-shark | Señal concreta | Estado |
|---|---|---|---|---|
| **T1048.003** | Exfiltration Over Alternative Protocol: DNS | `DNS-TUNNELING` | qname ≥ 30 caracteres con entropía de Shannon ≥ 3.5 bits (subdominio codificado) | **Implementado (F1)** |
| **T1046** | Network Service Discovery / Scanning | `PORT-SCAN` | ≥ 4 SYNs sin ACK hacia el mismo (src, dst, puerto) — tracker entre flujos | **Implementado (F1)** |
| **T1021** | Remote Services | `INSECURE-PORT` | Conexión a telnet 23/tcp (credenciales en claro) | **Implementado (F1)** |
| — (hardening) | Network Service Scanning (objetivo expuesto) | `EXPOSED-DB` | Conexión directa a 3306/5432/1433/6379/27017 | **Implementado (F1)** |
| **T1071** | Application Layer Protocol (genérico) | `BEACONING` | Intervalos entre paquetes del iniciador con CV ≤ 0.15, ≥ 6 intervalos, media entre 5 s y 1 h (excluye ruido atenuado) | **Implementado (F3)** |
| **T1036** | Masquerading: masquerade file type | `FILE-MASQUERADING` | Carving HTTP (Content-Length/chunked) + magic bytes propio: magic ≠ extensión declarada o doble extensión ejecutable (`informe.pdf.exe`) | **Implementado (F4)** |
| **T1071.001** | Application Layer Protocol: Web (C2 conocido) | `THREAT-INTEL-FEODO` | Destino en lista Feodo cargada con `--intel-feodo` (IP o CIDR, v4/v6) | **Implementado (F4)** |
| **T1090.003** | Proxy: Multi-hop Proxy | `TOR-USAGE` | Destino en la lista de nodos de salida de Tor cargada con `--intel-tor` | **Implementado (F4)** |

## Cobertura diseñada (fases 4 avanzada)

| ID | Técnica | Detección prevista | Señal concreta | Fase |
|---|---|---|---|---|
| **T1071.001** (JA4) | Application Layer Protocol: Web | Fingerprinting JA4/JA4+ contra listas públicas de malware | la huella ya se calcula (F3: `tls.ja4`); falta empaquetar las bases de huellas maliciosas | F4 avanzada |
| **T1040** | Network Sniffing | (nota) | soc-shark *habilita* la detección del resto; no se autodetecta en F1-F4 | n/a |
| **T1048** | Exfiltration (otros protocolos) | Volumen asimétrico anómalo | flujos con `bytes` ≫ `bytes_rev` hacia destinos no habituales | F4 avanzada |
| **T1021.001-005** | Remote Services: RDP/SMB/SSH/VNC | Contexto de uso | conexión a 3389/445/22/5900 con combinación de flags y volúmenes anómalos | F4 avanzada |

## Filosofía del mapeo

1. **Una alerta, una técnica** (o ninguna): los `alerts[].mitre` son IDs
   atómicos, no frases. Facilita dashboards ATT&CK Navigator y correlación
   en SIEM.
2. **El riesgo es aditivo, el ATT&CK no**: un flujo puede llevar varias
   alertas de técnicas distintas (túnel DNS + conexión posterior); la
   historia completa es del analista.
3. **Honestidad sobre límites**: una heurística de entropía detecta
   *posibles* túneles DNS, no certeza. El `detail` de cada alerta incluye
   los números que la dispararon (longitud, entropía, cuenta de SYNs) para
   que el analista valide en segundos y el false positive sea visible.
4. **Detección pasiva por diseño**: todo lo anterior funciona sin agentes
   en endpoints, sin TLS terminado y sin activar nada en el tráfico: el
   instrumento de un Blue Team que no puede modificar la red que vigila.

## Uso del mapeo en operación

- **ATT&CK Navigator**: exportar `flow_id, alert.id, mitre` de una sesión y
  pintar la capa de técnicas observadas durante el incidente.
- **TheHive/Wazuh**: el campo `mitre` alimenta directamente
  `tags: attack.t1048.003` convención de Wazuh.
- **Métrica de cobertura**: el equipo SOC puede medir qué técnicas de su
  threat model produce señal en su red real con esta tabla como checklist
  de lacrado.
