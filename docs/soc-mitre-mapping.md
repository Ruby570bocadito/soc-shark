# Mapeo a MITRE ATT&CK

Toda detección de soc-shark se documenta con su técnica ATT&CK Enterprise
correspondiente. La columna Estado distingue lo ya implementado y testeado
de lo diseñado para su fase. Este documento es también el contrato con los
SIEM: los `alerts[].mitre` del JSONL llevan exactamente estos IDs.

## Enterprise ATT&CK v15 — cobertura actual

| ID | Técnica | Detección en soc-shark | Señal concreta | Estado |
|---|---|---|---|---|
| **T1071.004** | Application Layer Protocol: DNS | `DNS-TUNNELING` | Subdominio largo y de alta entropía de Shannon: la entropía se calcula solo sobre las etiquetas a la izquierda del dominio registrable (aproximación eTLD+1), así que nombres legítimos largos como `settings-win.data.microsoft.com` no disparan | **Implementado (F1)** |
| **T1071.004** | Application Layer Protocol: DNS | `DNS-TUNNELING` (volumen) | Un cliente consulta ≥ 50 subdominios únicos de un mismo dominio registrable en 10 min (excluye PTR/`.arpa`, mDNS `.local`, DNSBL y subdominios < 6 caracteres): túneles de baja entropía (dnscat2/iodine con etiquetas cortas). Detalle «N subdominios únicos de X en 10 min» | **Implementado (0.8)** |
| **T1046** | Network Service Discovery / Scanning | `PORT-SCAN` | Escaneo vertical: un origen prueba ≥ 10 puertos distintos de un host sin establecer conexión (sin respuesta, RST/ACK o half-open) — tracker entre flujos | **Implementado (F1, corregido)** |
| **T1046** | Network Service Discovery / Scanning | `NETWORK-SWEEP` | Barrido horizontal: un origen prueba el mismo puerto en ≥ 20 hosts sin establecer conexión | **Implementado** |
| — (aviso) | — | `REPEATED-ATTEMPTS` | ≥ 4 intentos fallidos del mismo origen al mismo host:puerto sin llegar a escaneo (servicio caído, C2 muerto, sondeo insistente); severidad baja | **Implementado** |
| **T1021** | Remote Services | `INSECURE-PORT` | Conexión a telnet 23/tcp que no es una sonda fallida ni del equipo consigo mismo (credenciales en claro) | **Implementado (F1)** |
| — (hardening) | Network Service Scanning (objetivo expuesto) | `EXPOSED-DB` | Conexión a 3306/5432/1433/6379/27017 que no es una sonda fallida ni del equipo consigo mismo (misma dirección o loopback) | **Implementado (F1)** |
| **T1571** | Non-Standard Port | `NON-DNS-ON-53` | Flujo por el puerto 53 con datos y sin ningún mensaje DNS válido (una shell, VPN o control remoto donde el cortafuegos espera DNS). Caso real del corpus: shell de `cmd.exe` en TCP/53 | **Implementado (0.8)** |
| **T1071** | Application Layer Protocol (genérico) | `BEACONING` | Intervalos entre paquetes del iniciador con CV ≤ 0.15, ≥ 6 intervalos, media entre 5 s y 1 h (excluye ruido atenuado) | **Implementado (F3)** |
| **T1071** | Application Layer Protocol (genérico) | `BEACONING` (jitter, severidad baja) | Beacon con jitter aleatorio (Cobalt Strike `jitter` 30-50%): ≥ 12 intervalos con mediana en [5 s, 1 h], MAD/mediana ≤ 0.35 y ≥ 90% de intervalos en [0.4, 2]×mediana (entre conexiones); CV ≤ 0.30 dentro de un flujo. Solo si la prueba estricta no pasa | **Implementado (0.8)** |
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
  `tags: attack.t1071.004` convención de Wazuh.
- **Métrica de cobertura**: el equipo SOC puede medir qué técnicas de su
  threat model produce señal en su red real con esta tabla como checklist
  de lacrado.
