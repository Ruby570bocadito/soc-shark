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
| `DNS-TUNNELING` (T1071.004) | subdominio (etiquetas a la izquierda del dominio registrable) largo **y** con entropía de Shannon alta | subdominios codificados (base32/hex) de exfiltración o C2 | +45 | **implementado** |
| `DNS-TUNNELING` (volumen, T1071.004) | un cliente consulta ≥ 50 subdominios únicos de un mismo dominio registrable en 10 min — tracker *entre flujos* | túneles de baja entropía (etiquetas cortas o alfabetos reducidos) que la regla por consulta no ve | +45 (no se suma dos veces) | **implementado (0.8)** |
| `PORT-SCAN` | un origen prueba ≥ 10 puertos distintos de un host sin establecer conexión — tracker *entre flujos* | escaneo vertical (`nmap -sS`/`-sT`): cada sonda es un flujo distinto, invisible por flujo aislado | +30 | **implementado** |
| `NETWORK-SWEEP` | un origen prueba el mismo puerto en ≥ 20 hosts sin establecer conexión | barrido horizontal (gusanos, búsqueda de SMB/RDP abiertos) | +30 (una vez con `PORT-SCAN`) | **implementado** |
| `REPEATED-ATTEMPTS` | ≥ 4 intentos fallidos al mismo host:puerto sin llegar a escaneo | servicio caído, C2 muerto o sondeo insistente (severidad baja) | +10 | **implementado** |
| `INSECURE-PORT` | conexión a telnet 23/tcp que no es una sonda fallida | credenciales y comandos en texto claro | +35 | **implementado** |
| `EXPOSED-DB` | conexión a 3306/5432/1433/6379/27017 que no es una sonda fallida | base de datos alcanzable desde la red observada | +25 | **implementado** |

Una **sonda fallida** es un flujo TCP con SYN que nunca transportó datos
ni se cerró con FIN: sin respuesta (puerto filtrado), RST/ACK (cerrado) o
SYN/ACK seguido de RST del cliente (half-open). Los umbrales son
configurables en `PipelineConfig` (`scan_port_threshold`,
`scan_host_threshold`, `repeated_attempt_threshold`). El horizontal es más
alto porque el descubrimiento de red de Windows (SMB/NetBIOS) toca muchos
hosts del mismo puerto de forma legítima.

La heurística no mide el nombre completo sino **solo el subdominio**: las
etiquetas a la izquierda del dominio registrable (una aproximación de
eTLD+1: `ejemplo.com`, `ejemplo.co.uk`…). El dominio registrable lo elige
quien lo compra y no dice nada de lo que viaja en la consulta; lo que un
túnel codifica va en el subdominio. Medido sobre el nombre entero, incluso
un nombre normal como `www.ejemplo-corporativo.com` da ≈3.7 bits por
carácter, y nombres legítimos largos como `settings-win.data.microsoft.com`
se acercan a los umbrales; medido sobre el subdominio (`www`,
`settings-win.data`), quedan muy por debajo, mientras que
`az3k9t2wq7xm5vb8n...chfdgs.ejemplo.com` (base32/hex) sigue siendo largo y
de alta entropía. Los umbrales de longitud y entropía son configurables en
`PipelineConfig` (`dns_entropy_threshold`, `dns_tunnel_min_len`) para
afinar por entorno sin tocar código.

Del subdominio se descartan antes de medir las etiquetas que parecen datos
pero son estructura: los **GUID canónicos** (`8-4-4-4-12` hexadecimal) y las
**etiquetas de servicio cortas** de SRV y DNS-SD (`_ldap`, `_tcp`,
`_msdcs`…). El localizador de controladores de dominio de Active Directory
pregunta `_ldap._tcp.<GUID>.domains._msdcs.<bosque>` en cualquier red Windows
con dominio, y el GUID (36 caracteres hexadecimales) disparaba la regla: fue
el primer falso positivo High que encontró el corpus real (`dns.cap`). Un
túnel que codificara en forma de GUID necesitaría muchos nombres distintos y
lo caza la regla de volumen.

**Túnel DNS por volumen (0.8).** Un túnel que codifica con poca entropía o
en etiquetas cortas (`a0001.t.evil.com`, `a0002.t.evil.com`...) esquiva la
regla por consulta, pero no su volumen: para mover datos necesita muchos
subdominios *distintos* del mismo dominio. `DnsVolumeTracker`
(`socshark-soc::dns_volume`) cuenta, por (cliente, dominio registrable), los
subdominios únicos en una ventana deslizante y alerta `DNS-TUNNELING` con
detalle «N subdominios únicos de X en 10 min». Umbrales en `PipelineConfig`:
`dns_volume_threshold` (50), `dns_volume_window_secs` (600),
`dns_volume_min_subdomain_len` (6, sin puntos). No cuentan: PTR y todo
`.arpa`, mDNS (`.local`), consultas DNSBL (IPv4 invertida o nibbles IPv6
delante de la zona) ni subdominios cortos (`www`, `api`, `img1`). Una
navegación normal resuelve muchos nombres pero repartidos entre muchos
dominios y repitiendo los mismos. Estado acotado: 8 192 claves con desalojo
de la mitad más antigua; por clave solo hashes de 64 bits, y se deja de
contar al llegar al umbral. Funciona igual offline que en el daemon (el
contexto persiste entre lotes). Límites conocidos: un resolutor local
(Pi-hole, DC) agrega las consultas de todos sus clientes, y algunos
servicios legítimos hacen "DNS como API" (reputación de antivirus,
`*.googlevideo.com` en sesiones largas): conviene subir el umbral o
revisar el dominio antes de bloquear.

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

## File carving con detección de masquerading (Fase 4 — implementado)

El reassembler de streams (Fase 2) alimenta el tallado de archivos HTTP
(`socshark capture --carve-files`, módulo `socshark-soc::carve`). Por cada
flujo HTTP clasificado por la heurística L7, el stream del servidor se
recorre en busca de respuestas HTTP/1.x completas (keep-alive incluido: las
respuestas se emparejan con las peticiones del stream del cliente en orden):

1. Cuerpo por **Content-Length exacto** o por **Transfer-Encoding: chunked**
   (reensamblado propio de chunks; los separadores no son datos). Un cuerpo
   truncado (captura cortada o tope de 1 MiB por dirección) talla lo
   disponible: el SHA-256 deja de ser el del archivo original, pero la
   firma magic de la cabecera sigue siendo válida.
2. **Magic bytes propios** (misma filosofía sin dependencias, ADR-003):
   PE32 (MZ), ELF, Mach-O, PDF, ZIP/Office, OLE2, GZIP, RAR, 7Z, PNG, JPEG,
   GIF y scripts con shebang.
3. **SHA-256** del contenido reconstruido — la implementación de JA4
   (ADR-011) se centralizó en `socshark-core::hash` para reutilizarla aquí.
   Nada se vuelca a disco: el hash y la firma viven en el JSONL.
4. **T1036 Masquerading por dos vías**: magic ≠ extensión declarada (un
   `banner.jpg` cuyo contenido es PE32) y **doble extensión ejecutable**
   (`informe.pdf.exe`). El nombre viene de `Content-Disposition` y, si no,
   del basename de la ruta pedida **sin la query ni el fragmento** (en
   `/ads?url=…/download.html&color=…` la «extensión» no es
   `html&color=…`).
5. **Content-Encoding** (gzip, br, deflate…): los primeros bytes son los del
   compresor, no los del archivo, así que esos cuerpos no se juzgan por su
   firma (sin descompresor propio): se tallan solo por nombre o tipo
   binario, sin `magic` y sin veredicto T1036 por firma (la doble extensión
   sí cuenta). Una página HTML con gzip salía como «GZIP disfrazado de
   .html»: segundo falso positivo High del corpus real (`http.cap`).

Selección conservadora: no se talla toda respuesta 200 — solo si hay nombre
declarado, tipo binario (`application/*`) o firma conocida; las páginas
HTML/texto normales no inundan el modelo. Cota dura de 8 archivos por flujo.
La regla **R6** del mini-IDS alerta `FILE-MASQUERADING` (T1036, severidad
alta, +40 de riesgo) y cualquier ejecutable transferido suma +15 sin alerta
(distribución de software legítima). DSL: `file.name`, `file.magic`,
`file.count`, `file.masquerading`. El escenario demo incluye ya una descarga
de `factura.jpg` que es un PE (verificado por test E2E).

## Threat intel offline (Fase 4 — implementado la parte de listas; GeoIP/ASN pendiente)

Sin conexión saliente: las listas se descargan aparte (cron, curl, el propio
SOC) y se cargan como ficheros de texto plano
(`--intel-feodo fichero.txt`, `--intel-tor fichero.txt`; módulo
`socshark-soc::intel`):

- **Feodo Tracker** (C2 activos): una IP o CIDR por línea, `#` comentarios.
  Soporta v4 y v6, con normalización de la base del CIDR.
- **Tor Bulk Exit List**: se extrae la primera IP de cada línea (tolera el
  formato `ExitAddress <ip> <fecha>`).
- El parser es tolerante por diseño: comentarios, líneas vacías, líneas sin
  IP interpretable y bytes que no son UTF-8 se saltan sin error (las listas
  públicas cambian de formato con frecuencia).
- Redes demasiado amplias (más cortas que /8 en IPv4 o /16 en IPv6, p. ej.
  `0.0.0.0/0`) se rechazan con un aviso: marcarían media Internet.

Cada flujo cuyo **origen o destino** coincide lleva `threat_intel` lleno con las
etiquetas (`FEODO-C2`, `TOR-EXIT`) y la regla **R7** alerta: C2 de Feodo →
`THREAT-INTEL-FEODO` (alta, T1071.001, +45) y salida de Tor → `TOR-USAGE`
(media, T1090.003 — proxy multi-salto, +20). DSL: `intel.tag`. La
coincidencia es una señal, nunca una decisión de bloqueo: soc-shark es
solo lectura.

Pendiente (documentado en roadmap): GeoIP/ASN hacia `dst_geo_asn` exige un
lector `.mmdb` propio sin dependencias, y el hunting de `tls.ja4` contra
listas públicas exige empaquetar esas bases. Ambos encajan en la Fase 4
avanzada o contribuciones.

## Huella JA4 y SNI del ClientHello (Fase 3 — implementado)

Con cada flujo TCP cuyo iniciador envía un ClientHello TLS, el agregador
reconstruye el mensaje (acotado a 16 KiB, tolera que cruce segmentos y
registros) y calcula la huella **JA4** de FoxIO según su especificación
oficial: versión TLS, SNI, recuentos sin GREASE, hash de ciphers ordenados y
hash de extensiones (sin SNI/ALPN) más signature algorithms en orden de
aparición. El SHA-256 necesario es implementación propia (~80 líneas, ADR-011):
sin dependencias criptográficas para un resumen público.

- `ja4_fingerprint` p. ej. `t13d0208h2_777cda164f4b_af51ac0c444f`: identifica
  la librería/binario cliente aunque el tráfico vaya cifrado, y permite
  hunting contra bases públicas de huellas (ja4db) — Fase 4.
- `tls_sni`: el dominio que el propio cliente declara. El enriquecimiento lo
  usa como `resolved_domain` cuando no hubo DNS observable, así el flujo TLS
  siempre tiene dominio legible si el cliente lo envió.
- DSL: `tls.ja4 == "t13d0208h2_..."`, `tls.ja4 contains "8daaf6152771"`,
  `tls.sni contains "ejemplo"`.
- La huella se valida en CI contra los vectores canónicos del spec FoxIO
  (`t13d1516h2_8daaf6152771_e5627efa2ab1`), además de los vectores NIST del
  SHA-256.

QUIC/DTLS (`q`/`d` como primer carácter) queda para fases posteriores: exige
parser QUIC propio.

## Detección de beaconing (Fase 3 — implementado)

Implementada sobre una estadística de intervalos por flujo y dirección
iniciador (`IntervalStats`: ventana acotada de 33 timestamps → 32 intervalos,
media y desviación estándar poblacional, tolerante a reordenamiento de
captura). La regla `R5` del mini-IDS alerta `BEACONING` (MITRE **T1071**)
cuando se cumplen TODAS (umbrales configurables en `PipelineConfig`):

- ≥ `beacon_min_intervals` (6) intervalos → un beacon de 30 s alerta a los
  3 minutos, dentro del criterio de fase (< 5 min).
- Media de intervalos dentro de [`beacon_min_interval_secs` (5),
  `beacon_max_interval_secs` (3600)]: por debajo está el tráfico interactivo,
  por encima los keepalives y los polls de mantenimiento.
- Coeficiente de variación (std/mean) ≤ `beacon_max_cv` (0.15): el perfil de
  un sleep programado; el tráfico humano (CV > 0.3) queda fuera.
- El flujo no es ruido de fondo (NTP/mDNS son regulares por diseño y ya
  están atenuados).

El detalle de la alerta incluye el periodo estimado y su jitter
("intervalo medio 30.0s con jitter ±0.0% en 7 intervalos"), y los campos
`flow.interval_mean_secs` / `flow.interval_cv` son consultables en el DSL.
**Beaconing entre conexiones.** Un beacon más lento que el timeout de
inactividad (p. ej. cada 5 min con el daemon a 120 s) se parte en flujos de un
paquete. `FlowStartTracker` guarda los inicios de flujo por (origen, destino,
puerto, transporte) y aplica los mismos umbrales a los intervalos entre
conexiones: alerta `BEACONING` (T1071) con detalle «…entre conexiones».
Excluye DNS y ruido; acotado a 65 536 claves × 33 inicios.

**Beaconing con jitter aleatorio (0.8).** Un implante con `jitter` (Cobalt
Strike, Sliver...) sortea el CV ≤ 0.15: ±40% uniforme da CV ≈ 0.23. Cuando la
prueba estricta no pasa, se aplica sobre la misma serie una prueba tolerante
a jitter y, si pasa, se emite `BEACONING` (T1071) con **severidad baja y
+10** (la estricta: media y +20) y detalle «…con jitter ~X%…». Nunca salen
las dos.

- Entre conexiones (`FlowStartTracker` guarda los inicios crudos):
  ≥ `beacon_jitter_min_intervals` (12) intervalos, mediana en
  [`beacon_min_interval_secs`, `beacon_max_interval_secs`], MAD/mediana ≤
  `beacon_jitter_max_mad_ratio` (0.35; uniforme ±50% da ≈ 0.25) y ≥ 90% de
  los intervalos en [0.4, 2]×mediana. El tráfico humano es de cola pesada
  (MAD alto) y el de ráfagas deja muchos intervalos fuera de banda; un
  beacon perdido (intervalo doble) se tolera.
- Dentro de un flujo solo hay media y desviación (`IntervalStats`), así que
  se usa CV ≤ `beacon_jitter_max_cv` (0.30, cubre ±50% uniforme) con los
  mismos ≥ 12 intervalos y ventana de periodo.

El ruido de fondo (NTP...) sigue excluido. Falsos positivos esperables: polls
legítimos de aplicaciones con jitter propio (clientes de chat, agentes de
actualización); por eso la severidad es baja.

## Export a SIEM (Fase 4 — implementado ECS y Wazuh; TheHive pendiente)

`socshark export -r captura.pcap -F ecs|wazuh [-o salida.jsonl]` ejecuta el
pipeline completo (con `--carve-files` y `--intel-*` si se piden) y emite un
JSON por línea. El contrato campo a campo está en
[siem-export.md](siem-export.md); resumen:

- **ECS 8.x** (`-F ecs`, módulo `socshark-soc::siem::to_ecs`): campos
  estándar donde existen (`source.*`, `destination.*`, `network.*`,
  `dns.*`, `tls.client.server_name`, `event.duration` en ns,
  `threat.technique.id` con los MITRE de las alertas) y espacio propio
  anidado `socshark.*` (riesgo, ruido, archivos tallados, etiquetas intel).
  El `@timestamp` ISO-8601 se calcula con conversión civil propia
  (algoritmo de Hinnant, ADR-012): sin `chrono` para un solo formato.
- **Wazuh** (`-F wazuh`, `to_wazuh`): evento plano que el decoder JSON del
  manager consume de serie — `srcip`/`srcport`/`dstip`/`dstport`/`protocol`
  reconocidos, `data.*` anidado con el detalle (incluye archivos tallados e
  intel), y `rule.level` (escala 0-15: Info 2 → Critical 13) + `rule.mitre.id`
  cuando hay alertas, para que el evento entre como alerta correlacionada.
  Sin alertas el evento se archiva sin `rule`.

Pendiente: push hacia TheHive (exigiría cliente HTTP propio) y el mapeo ECS
completo de todos los campos secundarios.
