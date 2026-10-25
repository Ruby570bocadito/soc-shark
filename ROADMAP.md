# 🦈 SOC SHARK — Roadmap de expansión (0.8 → 2.0)

> Documento vivo. Parte del estado real del repositorio en la **0.7.0**
> (octubre de 2026) y propone cómo llevar SOC SHARK de «herramienta muy
> prometedora» a **producto de referencia para Blue Team y para cualquier
> persona que quiera entender su red**.
>
> El histórico de fases ya cerradas (0-4) y sus criterios sigue en
> [docs/roadmap.md](docs/roadmap.md). Este documento mira hacia delante.

---

## Índice

1. [Diagnóstico: dónde está el proyecto hoy](#1-diagnóstico-dónde-está-el-proyecto-hoy)
2. [Principios que este roadmap respeta](#2-principios-que-este-roadmap-respeta)
3. [Vista general por versiones](#3-vista-general-por-versiones)
4. [Ganancias rápidas (1-2 semanas)](#4-ganancias-rápidas-1-2-semanas)
5. [Línea A — README, documentación e imagen](#5-línea-a--readme-documentación-e-imagen)
6. [Línea B — Internacionalización (inglés de verdad)](#6-línea-b--internacionalización-inglés-de-verdad)
7. [Línea C — Captura y formatos](#7-línea-c--captura-y-formatos)
8. [Línea D — Disectores y protocolos](#8-línea-d--disectores-y-protocolos)
9. [Línea E — Motor SOC: detecciones nuevas](#9-línea-e--motor-soc-detecciones-nuevas)
10. [Línea F — Enriquecimiento e inteligencia](#10-línea-f--enriquecimiento-e-inteligencia)
11. [Línea G — Lenguaje de filtros (DSL)](#11-línea-g--lenguaje-de-filtros-dsl)
12. [Línea H — GUI: funciones nuevas](#12-línea-h--gui-funciones-nuevas)
13. [Línea I — GUI: pulido, UX y accesibilidad](#13-línea-i--gui-pulido-ux-y-accesibilidad)
14. [Línea J — TUI y CLI](#14-línea-j--tui-y-cli)
15. [Línea K — Rendimiento y escala](#15-línea-k--rendimiento-y-escala)
16. [Línea L — Persistencia y sesiones](#16-línea-l--persistencia-y-sesiones)
17. [Línea M — Integraciones (SIEM, SOAR, casos)](#17-línea-m--integraciones-siem-soar-casos)
18. [Línea N — eBPF y atribución de procesos](#18-línea-n--ebpf-y-atribución-de-procesos)
19. [Línea O — Plugins WASM](#19-línea-o--plugins-wasm)
20. [Línea P — Empaquetado, distribución y actualizaciones](#20-línea-p--empaquetado-distribución-y-actualizaciones)
21. [Línea Q — Seguridad de la propia herramienta](#21-línea-q--seguridad-de-la-propia-herramienta)
22. [Línea R — Calidad, tests y CI](#22-línea-r--calidad-tests-y-ci)
23. [Línea S — Comunidad y gobernanza](#23-línea-s--comunidad-y-gobernanza)
24. [Matriz de prioridades](#24-matriz-de-prioridades)
25. [Criterios para llamar «1.0» a la 1.0](#25-criterios-para-llamar-10-a-la-10)
26. [Ideas a largo plazo (2.x y más allá)](#26-ideas-a-largo-plazo-2x-y-más-allá)
27. [Riesgos y cómo mitigarlos](#27-riesgos-y-cómo-mitigarlos)

---

## 1. Diagnóstico: dónde está el proyecto hoy

### Lo que ya es fuerte

| Área | Estado en 0.7.0 |
|---|---|
| Arquitectura | Workspace de 9 crates con DAG limpio, `EnrichedFlow` como contrato único (Flow-First, ADR-002), 14 ADRs documentados. |
| Dependencias | 5 crates externos congelados + `ratatui`/`crossterm`. SHA-256, ISO-8601, HTTP local, FFI de libpcap: todo propio. |
| Robustez | Parsers sin panics, test de truncado masivo, fuzzing determinista de 50 000 iteraciones en CI (ya atrapó un panic real). |
| Captura | pcap + pcapng, en vivo con libpcap/Npcap cargados por `dlopen`, BPF al kernel, parada inmediata. |
| SOC | 7 reglas (R1-R7): túnel DNS, escaneo/barrido, telnet, BD expuesta, beaconing, encubrimiento T1036, threat intel. JA4, carving HTTP, export ECS/Wazuh. |
| Producto | GUI con historias en lenguaje claro, mapa de red, «quién es quién», informe HTML, TUI, instaladores en una línea y releases multiplataforma. |
| Tests | ~210 tests, `clippy -D warnings`, `rustfmt`. |

### Huecos detectados al revisar el código

Estos son los puntos concretos que motivan buena parte del roadmap:

1. **Link-layers limitados**: `LinkType` solo reconoce Ethernet y Raw IP
   (`crates/socshark-core/src/packet.rs`). Linux SLL/SLL2 (la interfaz
   `any`), BSD loopback (`lo0` de macOS) y 802.11/radiotap quedan como
   `Unknown` y **no se diseccionan**. En vivo, capturar en `any` en Linux no
   produce flujos.
2. **ARP e ICMP no se analizan**: ARP se descarta (`dissectors/src/lib.rs`),
   ICMP solo existe como `Transport::Icmp` sin tipo/código. Se pierden
   detecciones clásicas (ARP spoofing, ping sweep, túneles ICMP).
3. **L7 corto**: `L7Protocol` = DNS, DHCP, NTP, HTTP, TLS, SSH. Falta QUIC
   (≈ 30-40 % del tráfico web actual), SMB, RDP, Kerberos, LDAP, SMTP/IMAP,
   FTP, SNMP, MQTT, etc. No hay campos HTTP en el flujo (host, método, URI,
   user-agent, status) aunque el carving ya parsea las respuestas.
4. **La GUI lee la captura dos veces**: `Server::load` llama a
   `run_capture(path, …)` y luego a `PacketIndex::build(path)`
   (`crates/socshark-cli/src/gui/mod.rs`). Con capturas de varios GB se nota.
5. **Todo en memoria**: no hay persistencia de sesiones ni índice en disco;
   el límite práctico lo marca la RAM.
6. **Interfaz y documentación solo en español**, aunque el README principal
   está en inglés. Para el público internacional (la mayoría del Blue Team)
   esto es la barrera de adopción número uno.
7. **`dst_geo_asn`, `user`, eBPF, TLS 1.3, WASM, DuckDB, Tauri**: diseñados
   o con campo reservado, pero sin implementar.
8. **Windows real sin verificar** para la captura en vivo (probado con el
   `wpcap.dll` de Wine) y rendimiento en vivo sin medir sobre hardware real
   (criterio de Fase 2 pendiente: ≥ 200 Mbps sostenidos).
9. **Ficheros grandes del repo**: `oui_data.rs` (11 847 líneas) y
   `gui/mod.rs` (1 892), `app.js` (2 912) concentran mucha lógica; conviene
   modularizar antes de que crezcan más.
10. **CI**: sin matriz de sistemas operativos (solo `ubuntu-latest`), sin
    MSRV comprobado (se anuncia Rust 1.75), sin cobertura, sin
    `cargo-deny`/`cargo-audit`, sin tests del frontend.

---

## 2. Principios que este roadmap respeta

Nada de lo que sigue rompe las reglas no negociables de
[CONTRIBUTING.md](CONTRIBUTING.md):

- **Cero panics con entrada de red** → cada disector nuevo llega con su test
  de truncado, su entrada al fuzzer y casos hostiles.
- **Flow-First** → los protocolos nuevos enriquecen `EnrichedFlow`; los
  paquetes siguen siendo detalle, no producto.
- **Dependencias mínimas** → cada dependencia propuesta abajo va marcada con
  🧩 y **exige su ADR**. Se prefiere implementación propia cuando es razonable
  (como ya se hizo con SHA-256 o el HTTP local).
- **Solo lectura** → SOC SHARK observa; no bloquea ni inyecta tráfico.
- **Privilegio mínimo** → solo la frontera de captura toca privilegios.
- **Lenguaje claro primero** → cada función nueva debe poder explicarse en
  una frase a alguien que no sabe qué es TCP.

Leyenda de las tareas:

- 🟢 pequeño (≤ 2 días) · 🟡 medio (≤ 2 semanas) · 🔴 grande (> 2 semanas)
- 🧩 requiere dependencia nueva (y ADR)
- 🔐 requiere entorno privilegiado o hardware específico
- ⭐ alto impacto para usuarios

---

## 3. Vista general por versiones

```text
0.7.0  (hoy)  GUI + TUI + SOC + releases
  │
0.8.0  «Pulido y alcance»       ~6 semanas
  │     README/docs, i18n EN, SLL/loopback, ARP/ICMP, HTTP en flujo,
  │     GUI lee una vez, ganancias rápidas, CI multi-OS
  │
0.9.0  «Más protocolos, más detección»   ~8 semanas
  │     QUIC, SMB, Kerberos, RDP, SMTP/FTP, JA4S/JA4H, 10+ reglas nuevas,
  │     GeoIP/ASN (.mmdb propio), Sigma-lite, DSL 2.0
  │
0.10.0 «Escala y sesiones»       ~8 semanas
  │     índice en disco, capturas de 10+ GB, sesiones guardadas,
  │     ring buffer en vivo, medición de rendimiento real
  │
1.0.0  «Producto»                 ~8 semanas
  │     app de escritorio (Tauri), auto-actualización firmada,
  │     Windows real verificado, documentación completa EN/ES, API estable
  │
1.x    eBPF (proceso por conexión), TheHive/MISP, plugins WASM
  │
2.0    modo sensor/servidor multi-equipo, TLS 1.3 opt-in, ML ligero
```

Las fechas son orientativas para un equipo pequeño; lo importante es el
**orden** y los **criterios de salida** de cada versión.

---

## 4. Ganancias rápidas (1-2 semanas)

Cosas pequeñas con mucho retorno. Ideales para empezar o para nuevos
colaboradores (etiqueta `good first issue`).

- [ ] 🟢⭐ **Soportar Linux SLL (113) y SLL2 (276)** en `LinkType` y en el
      disector: desbloquea capturar en `any` y abrir capturas de `tcpdump -i any`.
- [ ] 🟢⭐ **BSD loopback / NULL (0) y LOOP (108)**: `lo0` en macOS y capturas
      de loopback de Windows (Npcap Loopback Adapter).
- [ ] 🟢 **ICMP tipo/código** en el flujo y en la vista de capas
      (`icmp.type`, `icmp.code` en el DSL).
- [ ] 🟢 **ARP básico**: disector + flujo de «descubrimiento» marcado como
      ruido de fondo, alimentando el «quién es quién» (IP ↔ MAC).
- [ ] 🟢⭐ **La GUI lee la captura una sola vez**: construir `PacketIndex` y
      flujos en una pasada compartida.
- [ ] 🟢 **`socshark --version` con commit y fecha de build** (útil en
      reportes de errores).
- [ ] 🟢 **`socshark completions <shell>`** (bash, zsh, fish, PowerShell) con
      `clap_complete` 🧩 o generación propia.
- [ ] 🟢 **Plantillas de issues** (`bug`, `feature`, `nueva detección`,
      `nuevo protocolo`) y de PR.
- [ ] 🟢 **Badge de tests y de cobertura** en el README.
- [ ] 🟢 **`examples/` más rico**: añadir `home.pcap` (escenario casa) y
      capturas pequeñas por detección (una por regla R1-R7), generadas con
      `socshark dev sample-pcap`.
- [ ] 🟢 **Mensaje claro al abrir un link-layer no soportado** en la GUI
      («Esta captura es Wi-Fi en modo monitor; aún no la entiendo») en vez de
      cero flujos silenciosos.
- [ ] 🟢 **Estadística «paquetes no entendidos»** en la barra de estado, por
      motivo (link-layer, truncado, protocolo desconocido).

---

## 5. Línea A — README, documentación e imagen

El README ya es bueno (instalación en una línea, vídeo, capturas). Objetivo:
que un visitante entienda en **10 segundos** qué es y en **2 minutos** lo
tenga funcionando y le haya sorprendido.

### A.1 README

- [ ] 🟢⭐ **Bloque «¿Por qué no Wireshark/Zeek/Suricata?»**: tabla
      comparativa honesta (qué hace mejor cada uno, cuándo usar SOC SHARK y
      cuándo no). Genera confianza y responde la primera pregunta de
      cualquier analista.
- [ ] 🟢 **«Prueba en 30 segundos sin red propia»**: `socshark gui -r
      examples/demo.pcap` destacado justo tras la instalación.
- [ ] 🟢 **GIFs cortos por función** (historias, mapa, en vivo, follow
      stream) además del vídeo general: se ven en GitHub sin hacer clic.
- [ ] 🟢 **Sección «Detecciones incluidas»** con la tabla regla → MITRE →
      ejemplo de frase en lenguaje claro.
- [ ] 🟢 **FAQ**: ¿necesito root? ¿envía datos a Internet? (no) ¿funciona
      con capturas de Wireshark? ¿qué tamaño máximo? ¿puedo usarlo en el
      trabajo?
- [ ] 🟢 **Sección «Privacidad»**: todo es local, sin telemetría, la GUI
      solo escucha en `127.0.0.1` con token.
- [ ] 🟢 Retirar la frase «The interface and the detailed documentation are
      in Spanish for now» cuando la Línea B esté hecha.
- [ ] 🟢 Badges: MSRV real comprobado en CI, cobertura, descargas del
      release, OpenSSF Scorecard.
- [ ] 🟢 Mantener `README.md` y `README.es.md` sincronizados con un check de
      CI (mismas secciones / mismos enlaces).

### A.2 Sitio de documentación

- [ ] 🟡⭐ **Sitio con mdBook** (o Zola) publicado en GitHub Pages desde
      `docs/`: buscador, navegación lateral, EN/ES.
- [ ] 🟡 **Tutoriales guiados** paso a paso, cada uno con su pcap:
  - «Mi primer análisis: ¿qué hace mi casa en Internet?»
  - «Cazar un beacon de C2»
  - «Detectar un escaneo de puertos y saber quién fue»
  - «Exportar a Elastic / Wazuh en 5 minutos»
  - «Capturar en vivo en Windows con Npcap»
  - «Escribir una regla de detección nueva»
- [ ] 🟡 **Referencia del DSL generada desde el código** (el registro de
      campos de `eval.rs` es la fuente de verdad → tabla automática).
- [ ] 🟢 **Referencia de la CLI generada** desde `clap` (páginas man con
      `clap_mangen` 🧩 o generador propio).
- [ ] 🟢 **Glosario** público (ya existe en la GUI): reutilizarlo en la web.
- [ ] 🟡 **Guía de arquitectura para contribuidores** con diagramas (flujo
      de un paquete desde `pcap_next_ex` hasta la frase en la GUI).
- [ ] 🟢 **Docs de API local de la GUI** en formato OpenAPI (aunque sea solo
      para uso interno, ayuda a integraciones y a Tauri).

### A.3 Imagen y marca

- [ ] 🟢 Logo en variantes (monocromo, favicon, icono de app 16-1024 px,
      `.ico`, `.icns`).
- [ ] 🟢 Paleta y tipografía documentadas (`docs/brand.md`).
- [ ] 🟢 Banner social para GitHub (`social preview`).
- [ ] 🟡 Vídeo de 2-3 minutos «caso real»: detectar un beacon desde cero.

---

## 6. Línea B — Internacionalización (inglés de verdad)

Hoy la GUI, la CLI, los mensajes de alerta y la documentación detallada
están en español (ADR-007). Para crecer hace falta inglés **sin perder el
español**.

- [ ] 🟡⭐ **ADR-015: i18n**. Decidir formato: catálogos propios en JSON/TOML
      embebidos con `include_str!`, clave → texto, con interpolación simple
      (sin dependencias). Fallback a inglés.
- [ ] 🟡⭐ **Frontend de la GUI**: extraer todas las cadenas de `app.js` e
      `index.html` a `assets/gui/i18n/{es,en}.json`; selector de idioma con
      detección por `navigator.language`; persistido en `localStorage`.
- [ ] 🔴⭐ **Motor de lenguaje claro** (`socshark-soc::explain`): las frases
      («El equipo «X» usó Telnet con el router») se construyen hoy en
      español. Pasar a plantillas por idioma con concordancia básica.
      Es la parte más delicada: el valor del producto está en estas frases.
- [ ] 🟡 **Alertas e historias**: título, explicación y «qué hacer» por
      idioma.
- [ ] 🟡 **Informe HTML** (`socshark report --lang en`).
- [ ] 🟡 **CLI**: mensajes de ayuda y errores en inglés por defecto, español
      con `LANG=es*` o `--lang es`.
- [ ] 🟡 **Docs en inglés**: traducir primero `gui.md`, `filter-dsl.md`,
      `soc-features.md`, `siem-export.md`; el resto después.
- [ ] 🟢 Test de CI: todas las claves existen en todos los idiomas.
- [ ] 🟢 Guía para traductores (añadir un idioma = añadir un JSON). Idiomas
      candidatos por la comunidad: portugués, francés, alemán, italiano.
- [ ] 🟢 Formato de números, fechas y tamaños según idioma
      (`1.234,5 KB` vs `1,234.5 KB`).

**Criterio de salida**: una persona que no sabe español puede instalar,
abrir la demo, entender todas las historias y exportar a su SIEM sin ver
una sola palabra en español.

---

## 7. Línea C — Captura y formatos

### C.1 Formatos de archivo

- [ ] 🟢⭐ Link-layers: SLL, SLL2, NULL/LOOP (ver ganancias rápidas).
- [ ] 🟡 **802.11 + radiotap** (solo lectura de capturas, extraer IP sobre
      Wi-Fi de datos no cifrados y nombres de redes). Revisar el «fuera de
      alcance»: leer capturas existentes es barato; capturar en modo
      monitor sigue fuera.
- [ ] 🟡 **Escribir pcapng** (además de `.pcap`) conservando comentarios de
      paquete y el nombre de la interfaz.
- [ ] 🟡 **Comentarios de paquete pcapng**: leerlos y mostrarlos; escribir
      las notas del analista (ver Línea H) como comentarios.
- [ ] 🟡 **Capturas comprimidas**: `.pcap.gz` / `.pcapng.gz` (inflate propio
      o `flate2` 🧩), `.zst` opcional.
- [ ] 🟢 **Abrir varias capturas a la vez** y fusionarlas por timestamp
      (`socshark capture -r a.pcap -r b.pcap`).
- [ ] 🟡 **Recortar / dividir capturas**: `socshark slice -r big.pcap
      --from … --to … -f "<dsl>" -o out.pcap` (como `editcap` + filtro).
- [ ] 🟢 **Detectar formato por contenido**, no por extensión (ya se hace
      por magic: documentarlo y cubrirlo con tests).
- [ ] 🟡 **Leer logs de Zeek (`conn.log`, `dns.log`) y EVE JSON de
      Suricata** como fuente de flujos: permite aplicar el motor de lenguaje
      claro y las historias a datos que el SOC ya tiene.

### C.2 Captura en vivo

- [ ] 🔐⭐ **Verificar en Windows real** con Npcap (Windows 10 y 11, Wi-Fi y
      Ethernet) y documentar el resultado. Añadir un runner `windows-latest`
      que al menos ejecute `daemon --list` con Npcap instalado en CI.
- [ ] 🟡⭐ **Ring buffer en disco** en vivo: guardar los últimos N MB/minutos
      para poder «rebobinar» y exportar el pcap del incidente.
- [ ] 🟡 **Rotación de ficheros** en el daemon (`--rotate 100MB`,
      `--rotate 1h`, `--keep 24`), como `dumpcap -b`.
- [ ] 🟡 **Captura en varias interfaces a la vez** (Wi-Fi + VPN).
- [ ] 🟡 **Pausar / reanudar** en la GUI sin perder el estado.
- [ ] 🟢 **Filtro de captura asistido**: plantillas BPF («solo mi equipo»,
      «sin streaming», «solo DNS») y validación con `pcap_compile` antes de
      empezar.
- [ ] 🔴🔐 **AF_XDP** (Linux) como backend de alto rendimiento, objetivo ya
      declarado en la Fase 2.
- [ ] 🔴🔐 **Captura remota**: `socshark sensor` en una Raspberry Pi o un
      puerto espejo que envía flujos (no paquetes) a la GUI de otro equipo,
      autenticado (ver 2.0).
- [ ] 🟡 **rpcap / sshdump**: capturar en un equipo remoto por SSH
      (`ssh host tcpdump -w - | socshark capture -r -`). Basta con soportar
      `-r -` (stdin) en streaming.

---

## 8. Línea D — Disectores y protocolos

Cada protocolo nuevo sigue la receta de CONTRIBUTING (parser con
`Option`, test de truncado, testgen, DSL, docs, MITRE si aplica) **y además**
su explicación en lenguaje claro para la vista de capas.

### D.1 Capa de red y transporte

- [ ] 🟢 ARP (request/reply, gratuitous ARP).
- [ ] 🟢 ICMP / ICMPv6 con tipo, código y mensajes embebidos
      (destination unreachable lleva la cabecera original: enlazarla al flujo).
- [ ] 🟡 NDP (ICMPv6 Neighbor/Router Discovery) para el «quién es quién» v6.
- [ ] 🟡 **Reensamblado de fragmentos IP** (hoy solo el primer fragmento v6).
- [ ] 🟢 GRE, VXLAN, GENEVE, MPLS: desencapsular y analizar el tráfico interior.
- [ ] 🟡 IPsec/ESP y WireGuard: reconocerlos y etiquetarlos como VPN
      («Este equipo tiene una VPN abierta con X»).
- [ ] 🟡 Métricas TCP: RTT, retransmisiones, ventana cero, RST inesperados
      → «la conexión iba lenta» explicado en lenguaje claro.

### D.2 Aplicación (por prioridad)

| Prioridad | Protocolo | Por qué | Campos DSL propuestos |
|---|---|---|---|
| ⭐⭐⭐ | **HTTP/1.x (petición)** | Ya se parsea la respuesta para carving; falta exponerlo | `http.host`, `http.method`, `http.uri`, `http.user_agent`, `http.status`, `http.content_type` |
| ⭐⭐⭐ | **QUIC / HTTP/3** | Gran parte del tráfico web; SNI en el Initial (descifrable con claves públicas del RFC 9001) | `quic.version`, `quic.sni`, JA4 para QUIC (`q…`) |
| ⭐⭐⭐ | **TLS ServerHello + certificados** | JA4S, emisor, caducidad, autofirmados (TLS 1.2) | `tls.version`, `tls.ja4s`, `tls.cert.issuer`, `tls.cert.subject`, `tls.cert.self_signed`, `tls.cert.expired` |
| ⭐⭐ | **SMB2/3** | Movimiento lateral, ransomware | `smb.command`, `smb.share`, `smb.filename` |
| ⭐⭐ | **Kerberos** | Kerberoasting, AS-REP roasting | `krb.msg_type`, `krb.realm`, `krb.cname`, `krb.etype` |
| ⭐⭐ | **RDP** | Acceso remoto, fuerza bruta | `rdp.cookie`, `rdp.security` |
| ⭐⭐ | **LDAP / CLDAP** | Reconocimiento AD | `ldap.op`, `ldap.base_dn` |
| ⭐⭐ | **SMTP / IMAP / POP3** | Credenciales en claro, exfiltración | `smtp.from`, `smtp.to`, `smtp.starttls` |
| ⭐⭐ | **FTP / TFTP** | Credenciales en claro, transferencia de ficheros (carving) | `ftp.user`, `ftp.command` |
| ⭐ | DNS ampliado | EDNS, DoH (por SNI conocido), DoT (853), registros TXT largos | `dns.txt`, `dns.ttl`, `dns.doh` |
| ⭐ | SNMP v1/v2c | Comunidad `public` en claro | `snmp.community` |
| ⭐ | MQTT / CoAP | IoT doméstico e industrial | `mqtt.topic`, `mqtt.client_id` |
| ⭐ | Modbus / DNP3 / S7 | OT/ICS (público industrial) | `modbus.function` |
| ⭐ | SSH ampliado | Banner, HASSH, versión | `ssh.banner`, `ssh.hassh` |
| ⭐ | WebSocket | Upgrade HTTP, C2 sobre WS | `ws.host` |
| ⭐ | SIP / RTP | VoIP | `sip.method`, `sip.from` |

### D.3 Vista de capas

- [ ] 🟡 Cada protocolo de la tabla, explicado campo a campo en la GUI
      (hoy hay explicación para las capas actuales).
- [ ] 🟢 Enlazar cada campo a su nombre en el DSL («clic derecho → filtrar
      por este valor» para *cualquier* campo, no solo IP/puerto/protocolo).
- [ ] 🟡 «Decodificar como…»: forzar un protocolo sobre un puerto no estándar
      (como *Decode As* de Wireshark).

---

## 9. Línea E — Motor SOC: detecciones nuevas

Hoy: R1-R7. Propuesta de reglas nuevas, todas con MITRE, umbral
configurable en `PipelineConfig`, test positivo y negativo, escenario en
`socshark-testgen` y frase en lenguaje claro + «qué hacer».

### E.1 Reglas nuevas

| Regla | Detección | MITRE | Depende de |
|---|---|---|---|
| R8 | **ARP spoofing / MITM**: misma IP con varias MAC, ARP gratuito sospechoso | T1557.002 | ARP |
| R9 | **Ping sweep** (ICMP echo a ≥ N hosts) | T1018 | ICMP |
| R10 | **Túnel ICMP** (payload grande/alta entropía) | T1095 | ICMP |
| R11 | **Fuerza bruta** (muchas conexiones cortas a SSH/RDP/SMB/FTP desde un origen) | T1110 | — |
| R12 | **Credenciales en claro** (HTTP Basic, FTP USER/PASS, POP3, IMAP, SMTP AUTH, telnet login) — se marca, **nunca se muestra la contraseña** | T1552 | HTTP, FTP, SMTP |
| R13 | **DGA**: dominios con alta entropía/n-gramas raros y muchos NXDOMAIN | T1568.002 | DNS |
| R14 | **Exfiltración por volumen**: ratio bytes salida/entrada anómalo hacia destino nuevo | T1048 | — |
| R15 | **Puerto no estándar para el protocolo** (TLS en 8443 vale, SSH en 443 no) | T1571 | heurística L7 |
| R16 | **Certificado TLS sospechoso**: autofirmado, caducado, CN ≠ SNI, emisor raro | T1587.003 | TLS cert |
| R17 | **JA4 conocido malicioso** (lista offline, p. ej. Cobalt Strike, Sliver) | T1071.001 | JA4 + intel |
| R18 | **User-agent sospechoso** (curl/python/powershell hacia Internet desde un puesto de usuario) | T1059 | HTTP |
| R19 | **Kerberoasting** (muchos TGS-REQ RC4 desde un origen) | T1558.003 | Kerberos |
| R20 | **SMB lateral** (un equipo de usuario hablando SMB con muchos equipos internos) | T1021.002 | SMB |
| R21 | **DNS a resolutor no corporativo / DoH** que salta la política | T1071.004 | DNS, TLS |
| R22 | **Nuevo dispositivo en la red** (MAC nunca vista) — muy útil en casa | — | sesiones (Línea L) |
| R23 | **Dispositivo IoT hablando con sitios inesperados** (perfil por fabricante) | — | OUI + historial |
| R24 | **Rogue DHCP** (más de un servidor DHCP respondiendo) | T1557.003 | DHCP |
| R25 | **LLMNR/NBT-NS poisoning** (respuestas de un host no autoritativo) | T1557.001 | discovery |

### E.2 Motor de reglas

- [ ] 🔴⭐ **Reglas declarativas** (ADR): definir detecciones simples en un
      fichero (`rules/*.toml`) usando el propio DSL como condición:
      ```toml
      [rule.ssh-from-iot]
      when = "tcp.port == 22 && host.vendor contains 'Espressif'"
      severity = "high"
      mitre = "T1021.004"
      title.es = "Un dispositivo IoT abrió SSH"
      title.en = "An IoT device opened SSH"
      ```
      Así los analistas añaden reglas sin recompilar.
- [ ] 🟡 **Importar Sigma (subconjunto de red)** y reglas de Suricata
      sencillas (ip/puerto/contenido) → traducirlas a reglas declarativas.
- [ ] 🟡 **Correlación entre flujos y en el tiempo**: «escaneo seguido de
      conexión exitosa al mismo puerto» → historia de severidad mayor.
- [ ] 🟡 **Supresiones / lista blanca** por regla, host o dominio, editables
      desde la GUI («esto es normal en mi red») y exportables.
- [ ] 🟡 **Puntuación de riesgo explicable**: desglose de por qué un flujo
      tiene 72/100 (qué regla sumó cuánto) visible en la GUI y en el JSONL.
- [ ] 🟡 **Línea base**: aprender durante X días qué es normal (destinos,
      horarios, volúmenes por equipo) y avisar de desviaciones.
- [ ] 🟢 **Tabla de cobertura MITRE** generada (matriz ATT&CK con las
      técnicas cubiertas resaltadas) en docs y en la GUI.

---

## 10. Línea F — Enriquecimiento e inteligencia

- [ ] 🟡⭐ **GeoIP/ASN con lector `.mmdb` propio** (formato MaxMind,
      compatible con las bases gratuitas de DB-IP o GeoLite2) → `dst_geo_asn`,
      bandera de país en la GUI, `geo.country`/`geo.asn` en el DSL.
- [ ] 🟡 **Gestor de feeds offline**: `socshark intel update` descarga
      (explícitamente, con opt-in) Feodo, Tor, abuse.ch URLhaus/ThreatFox,
      listas de JA4 maliciosos, y las guarda firmadas/con hash en
      `~/.socshark/intel/`. Nunca automático sin permiso.
- [ ] 🟡 **Formatos de IOC**: CSV genérico, STIX 2.1 (indicadores
      ip/dominio/hash), MISP JSON.
- [ ] 🟡 **Hash de ficheros tallados contra listas** (MalwareBazaar offline).
- [ ] 🟢 **Categorías de dominios** conocidos (CDN, telemetría de Microsoft,
      Apple, Google, redes sociales, streaming) para explicar mejor
      («su televisor habló con Netflix») y reducir ruido.
- [ ] 🟡 **Nombres de servicios cloud por rangos IP publicados** (AWS, Azure,
      GCP, Cloudflare): «un servidor de Amazon en Irlanda».
- [ ] 🟢 **Reverse DNS opcional** (opt-in, porque genera tráfico) para IPs
      sin nombre.
- [ ] 🟡 **Perfil de dispositivo** (fingerprint DHCP opción 55, mDNS, UA):
      «parece un iPhone», «parece una Smart TV Samsung».
- [ ] 🟢 Actualización automática del OUI en CI (`scripts/gen_oui.py`
      mensual con PR automático) y sacar `oui_data.rs` a un fichero de
      datos comprimido embebido para no inflar el código fuente.

---

## 11. Línea G — Lenguaje de filtros (DSL)

- [ ] 🟢 Operadores `matches` (regex 🧩 o glob propio), `in {a, b, c}`,
      `startswith`, `endswith`.
- [ ] 🟢 CIDR en comparaciones: `ip.dst in 10.0.0.0/8`.
- [ ] 🟢 Rangos: `tcp.port in 1..1024`.
- [ ] 🟢 Tiempo: `flow.start > "2026-10-25 10:00"`, `flow.duration > 60s`.
- [ ] 🟢 Tamaños con unidades: `flow.bytes > 10MB`.
- [ ] 🟡 Campos de equipo: `host.name`, `host.vendor`, `host.nick`,
      `host.is_router`, `host.is_this_computer`.
- [ ] 🟡 Campos de alerta: `alert.code == "BEACONING"`, `alert.mitre == T1071`.
- [ ] 🟡 **Autocompletado** en la GUI y la TUI (campos, operadores y valores
      vistos en la captura).
- [ ] 🟡 **Filtros guardados** con nombre («Solo lo de Ana»,
      «Tráfico raro de la tele»), exportables.
- [ ] 🟢 **Traducir filtros de Wireshark** comunes a DSL
      (`ip.addr==x && tcp.port==443` ya casi coincide; documentar diferencias
      y aceptar alias).
- [ ] 🟢 **Filtro → BPF**: cuando la expresión es traducible, ofrecer usarla
      también como filtro de captura.
- [ ] 🟡 **Constructor visual de filtros** para el modo Simple
      («Mostrar conversaciones de [equipo] con [Internet] que sean [peligrosas]»).
- [ ] 🟢 Fuzzing específico del parser del DSL con gramática generativa.

---

## 12. Línea H — GUI: funciones nuevas

### H.1 Análisis

- [ ] 🟡⭐ **Línea de tiempo del incidente**: historias y eventos clave en un
      eje temporal con zoom (seleccionar un rango filtra todo).
- [ ] 🟡⭐ **SequenceView**: diagrama de secuencia de un handshake o de una
      conversación (SYN, SYN/ACK, ClientHello…), ya previsto en Fase 4.
- [ ] 🔴⭐ **Decodificador estilo CyberChef** en «Contenido»: Base64, hex,
      URL, XOR, gzip/zlib, JSON bonito, con pipeline encadenable — previsto
      en Fase 4.
- [ ] 🟡 **Ficheros tallados** como vista propia: lista, tipo, hash, botón
      «guardar» (con aviso de seguridad) y «copiar SHA-256».
- [ ] 🟡 **Comparar dos capturas** (antes/después): equipos nuevos, destinos
      nuevos, historias nuevas.
- [ ] 🟡 **Notas y marcadores del analista** en flujos, paquetes e
      historias; se guardan en la sesión y salen en el informe.
- [ ] 🟡 **Estado de las historias**: nueva / revisada / falso positivo /
      escalada. Alimenta las supresiones (Línea E).
- [ ] 🟡 **Estadísticas avanzadas**: gráfica I/O por equipo, top
      dominios, distribución de tamaños de paquete, TLS por versión, mapa de
      calor hora × día.
- [ ] 🟡 **Mapa del mundo** (con GeoIP) además del mapa de la red local.
- [ ] 🟡 **Mapa de red mejorado**: agrupar por subred/VLAN, arrastrar nodos,
      fijar posiciones, exportar PNG/SVG, animación del tráfico en vivo.
- [ ] 🟢 **Búsqueda global** (Ctrl+K): equipos, dominios, historias,
      paquetes por contenido (texto o hex).
- [ ] 🟢 **Ir al paquete N**, paquete siguiente/anterior del mismo flujo.

### H.2 En vivo

- [ ] 🟡⭐ **Panel «Ahora mismo»**: quién está usando la red en este momento,
      velocidad por equipo (subida/bajada), en estilo «monitor de actividad».
- [ ] 🟡 **Alertas configurables**: qué severidad notifica, horario de
      silencio, sonido.
- [ ] 🟡 **Modo vigilancia en segundo plano** (bandeja del sistema con Tauri):
      avisa aunque la ventana esté cerrada.
- [ ] 🟢 Indicador de pérdida de paquetes del kernel más visible, con
      consejo («cierra otras capturas / usa un filtro»).

### H.3 Informe

- [ ] 🟡⭐ **Informe ejecutivo vs técnico**: dos plantillas (una página
      para dirección; detalle con IOCs y MITRE para el equipo).
- [ ] 🟡 Exportar a **PDF** (impresión del navegador ya funciona: plantilla
      de impresión cuidada) y **Markdown**.
- [ ] 🟢 Anexo de **IOCs** (IPs, dominios, hashes, JA4) en CSV/STIX.
- [ ] 🟢 Logo y nombre de organización configurables en el informe.

---

## 13. Línea I — GUI: pulido, UX y accesibilidad

### I.1 Pulido

- [ ] 🟡⭐ **Tabla de conversaciones virtualizada** (hoy pinta de 2 000 en
      2 000, hasta 10 000): lista infinita fluida con 1 M de filas.
- [ ] 🟢 Estados vacíos cuidados en todas las vistas («No hay historias:
      ¡buena señal!») con siguiente paso sugerido.
- [ ] 🟢 Esqueletos de carga y barra de progreso al abrir capturas grandes
      (con porcentaje real de bytes leídos y opción de cancelar).
- [ ] 🟢 Tooltips coherentes y glosario ampliado a todos los términos.
- [ ] 🟢 Recordar disposición (paneles, columnas, vista, tema) entre sesiones.
- [ ] 🟢 Columnas configurables (mostrar/ocultar/reordenar) en paquetes y
      conversaciones.
- [ ] 🟢 Reglas de color personalizables (como las *coloring rules* de
      Wireshark, pero con el DSL).
- [ ] 🟢 Iconos por tipo de dispositivo en el mapa y en las frases
      (📱 💻 🖨️ 📺 🔌).
- [ ] 🟢 Microinteracciones: transición al cambiar de vista, resaltado al
      filtrar con clic derecho, *toast* de «filtro aplicado — deshacer».
- [ ] 🟢 Tema de **alto contraste** además de claro/oscuro.
- [ ] 🟢 Densidad compacta / cómoda.
- [ ] 🟡 **Tour de bienvenida** interactivo (3-4 pasos) la primera vez.
- [ ] 🟢 Paleta de comandos (Ctrl+Shift+P) con todas las acciones y sus atajos.

### I.2 Accesibilidad (WCAG 2.1 AA)

- [ ] 🟡⭐ Auditoría completa: contraste, foco visible, navegación solo con
      teclado en todas las vistas, roles ARIA en tablas virtualizadas,
      lector de pantalla en historias y frases.
- [ ] 🟢 No depender solo del color (✓ ! ✕ ya ayuda; revisar gráficas y mapa).
- [ ] 🟢 Respetar `prefers-reduced-motion` y `prefers-color-scheme`.
- [ ] 🟢 Tamaños de fuente escalables sin romper el diseño.

### I.3 Calidad del frontend

- [ ] 🟡 **Modularizar `app.js`** (2 900 líneas) en módulos ES nativos
      (`views/`, `api.js`, `i18n.js`, `state.js`) sin introducir build
      tooling: el binario sigue embebiendo ficheros estáticos.
- [ ] 🟡 Tests del frontend con Playwright (abrir la demo, comprobar
      historias, filtrar, cambiar de vista, tema oscuro) en CI.
- [ ] 🟢 Tests visuales de regresión (capturas de pantalla comparadas) para
      las vistas principales.
- [ ] 🟢 Lint de JS/CSS (configuración mínima) en CI.

---

## 14. Línea J — TUI y CLI

### J.1 TUI

- [ ] 🟡⭐ **TUI en vivo** (`socshark tui -i eth0`): el modelo ya está
      preparado para consumir el JSONL del daemon.
- [ ] 🟡 Vista de paquetes y de capas en la TUI (paridad básica con la GUI).
- [ ] 🟡 Vista «quién es quién» y de historias en la TUI.
- [ ] 🟢 Temas de color y modo monocromo (terminales sin color, accesibilidad).
- [ ] 🟢 Ayuda contextual (`?`) con todos los atajos.
- [ ] 🟢 Soporte de ratón (clic en filas, scroll).
- [ ] 🟢 Exportar desde la TUI (JSONL / pcap del flujo seleccionado).

### J.2 CLI

- [ ] 🟢 `socshark stats -r cap.pcap` (estadísticas en tabla/JSON, como
      `capinfos` + `tshark -z`).
- [ ] 🟢 `socshark hosts -r cap.pcap` (quién es quién por terminal).
- [ ] 🟢 `socshark stories -r cap.pcap` (historias en texto/Markdown/JSON).
- [ ] 🟢 `socshark carve -r cap.pcap -o dir/` (extraer ficheros a disco).
- [ ] 🟢 `socshark slice` / `merge` (ver Línea C).
- [ ] 🟢 `socshark rules list|test|lint` para el motor declarativo.
- [ ] 🟢 `socshark intel update|list` (opt-in).
- [ ] 🟢 `socshark doctor`: comprueba libpcap/Npcap, permisos, versión,
      navegador para la GUI, y dice exactamente qué falta.
- [ ] 🟢 Salida `--format table|json|csv|md` homogénea en todos los comandos.
- [ ] 🟢 Códigos de salida documentados (útil en scripts: 0 sin alertas,
      2 con alertas ≥ umbral → `socshark capture --fail-on high` para CI/CD
      de redes o laboratorios).
- [ ] 🟢 Fichero de configuración `~/.config/socshark/config.toml`
      (umbrales, idioma, tema, feeds, supresiones) además de flags.
- [ ] 🟢 Leer de **stdin** (`-r -`) en streaming.

---

## 15. Línea K — Rendimiento y escala

- [ ] 🟢⭐ **Benchmarks reproducibles** (`cargo bench` o binario propio) con
      capturas sintéticas de 1 GB / 10 GB generadas por `socshark-testgen`;
      publicar resultados en el README y vigilar regresiones en CI.
- [ ] 🟢⭐ **Una sola pasada** en la GUI (ver ganancias rápidas).
- [ ] 🟡 **Lectura con mmap** de capturas (la v0.1 ya tenía el diseño
      `mmap_store`) para no cargar el fichero en RAM.
- [ ] 🟡 **Índice de paquetes compacto** (offset + longitud + flujo en
      12-16 bytes por paquete) para capturas de decenas de millones.
- [ ] 🟡 **Carga progresiva**: mostrar flujos e historias mientras se lee el
      fichero (el pipeline ya es incremental).
- [ ] 🟡 Perfilado (flamegraphs) de disección, agregador y `explain`;
      eliminar asignaciones en el camino caliente (`String` → `&str`/`Arc<str>`
      donde se pueda).
- [ ] 🟡 Paralelismo por defecto (`--workers` automático según núcleos) una
      vez medido que compensa.
- [ ] 🔐 **Criterio pendiente de Fase 2**: ≥ 200 Mbps sostenidos en vivo y
      TUI fluida con 10 k flujos, medido en hardware real y documentado.
- [ ] 🟡 Límites de memoria visibles al usuario («usando 1,2 GB; los flujos
      más antiguos se resumen») en vez de comportamiento silencioso.
- [ ] 🟢 Tamaño del binario: medir y vigilar (objetivo < 15 MB comprimido).

**Objetivo 0.10**: abrir una captura de 10 GB en < 60 s en un portátil
normal, con < 2 GB de RAM, y navegarla con fluidez.

---

## 16. Línea L — Persistencia y sesiones

- [ ] 🔴⭐ **ADR: almacenamiento**. Opciones: DuckDB 🧩 (ya previsto en la
      Fase 4; potente para analítica pero pesado), SQLite 🧩 (ligero,
      universal) o formato propio columnar + índice. Recomendación: empezar
      por un formato propio simple (flujos JSONL comprimido + índice de
      paquetes binario) y valorar DuckDB solo para consultas analíticas.
- [ ] 🟡⭐ **Guardar / abrir sesión** (`.socshark`): captura + flujos +
      apodos + notas + estado de historias + filtros. Abrir una sesión es
      instantáneo (no recalcula).
- [ ] 🟡 **Historial en vivo**: en modo vigilancia, guardar flujos (no
      paquetes) de días/semanas para responder «¿cuándo apareció este
      equipo?», «¿con quién habló la tele ayer?».
- [ ] 🟡 Consultas sobre el histórico con el DSL y con agregaciones
      (`socshark query "dns.qname contains 'tiktok'" --group-by host.name`).
- [ ] 🟢 Retención configurable y borrado seguro («olvidar todo»).
- [ ] 🟢 Exportar/importar apodos y supresiones (compartir entre equipos).

---

## 17. Línea M — Integraciones (SIEM, SOAR, casos)

- [ ] 🔐 **Verificar Wazuh y Elastic en laboratorio** (criterio pendiente
      de Fase 4): `docker compose` en `deploy/lab/` con Elastic + Wazuh que
      reciba el export y un test que lo compruebe.
- [ ] 🟡 Envío directo (no solo ficheros): **syslog** (RFC 5424, UDP/TCP/TLS),
      **HTTP JSON** genérico (webhook), **Elasticsearch bulk API**,
      **Splunk HEC**. Requiere cliente HTTP mínimo (propio o 🧩 `ureq`).
- [ ] 🟡 **OCSF** como tercer formato de export (estándar en auge:
      AWS Security Lake, Splunk).
- [ ] 🟡 **TheHive / Cortex**: crear caso desde una historia con observables
      (IP, dominio, hash) — previsto en Fase 4.
- [ ] 🟡 **MISP**: exportar evento con atributos; importar como intel.
- [ ] 🟢 **Exportar reglas Suricata/Sigma** desde una historia («convierte
      esta detección en una regla para mi IDS»).
- [ ] 🟢 **Zeek-like logs** (`conn.log`/`dns.log` TSV) para integrarse con
      herramientas que ya los consumen.
- [ ] 🟢 Notificaciones: Telegram, Slack, Discord, ntfy, e-mail (opt-in,
      pensadas para el usuario doméstico en modo vigilancia).
- [ ] 🟢 Dashboards de ejemplo para Kibana y Grafana en `deploy/`.

---

## 18. Línea N — eBPF y atribución de procesos

Diseño ya completo en [docs/ebpf-design.md](docs/ebpf-design.md); tipos
compartidos ya implementados en `socshark-ebpf-common`.

- [ ] 🔴🔐🧩 Probes `tcp_v4_connect`/`tcp_v6_connect`, `inet_sock_set_state`,
      `udp_sendmsg` con aya.
- [ ] 🔴🔐 Daemon de privilegios separados que publica eventos por UDS.
- [ ] 🟡 Correlación socket → (pid, exe, uid) en el enriquecedor; columnas
      Proceso/Usuario en TUI, GUI y JSONL.
- [ ] 🟡 Atribución también para **conexiones muy cortas** (hoy pueden
      escaparse entre dos fotos de la tabla de sockets).
- [ ] 🟡 **macOS**: atribución de procesos (hoy solo Linux/Windows) vía
      `proc_pidfdinfo`/`libproc` o NetworkExtension.
- [ ] 🟡 **Windows**: enriquecer con ETW (Microsoft-Windows-Kernel-Network)
      como alternativa a la foto de la tabla de sockets.
- [ ] 🟢 Reglas que usan el proceso: «`powershell.exe` descargó un ejecutable»,
      «un proceso sin firmar habla con Internet».
- [ ] 🔴🔐 **TLS 1.3 transparente (uprobes en `SSL_read/SSL_write`)**: solo
      con opt-in explícito, banner legal y auditoría (ya contemplado en
      [docs/security.md](docs/security.md)). También: aceptar
      `SSLKEYLOGFILE` para descifrar capturas propias — **mucho más barato y
      portable**, recomendable hacerlo primero.

---

## 19. Línea O — Plugins WASM

Diseño en [docs/wasm-plugins.md](docs/wasm-plugins.md).

- [ ] 🔴🧩 Runtime con wasmtime, límites de *fuel* y memoria, API WIT.
- [ ] 🟡 SDK para Rust y para lenguajes que compilan a WASM (TinyGo,
      AssemblyScript), con plantilla `cargo generate`.
- [ ] 🟡 Firma Ed25519 de plugins y lista de confianza.
- [ ] 🟡 Plugins oficiales de ejemplo: disector de un protocolo IoT,
      enriquecedor de dominios, regla de detección compleja.
- [ ] 🟡 Catálogo de plugins de la comunidad (índice en un repo aparte).
- [ ] 🟢 Alternativa ligera previa: las **reglas declarativas** (Línea E)
      cubren el 80 % de los casos sin WASM. Hacerlas antes.

---

## 20. Línea P — Empaquetado, distribución y actualizaciones

- [ ] 🔴⭐🧩 **App de escritorio con Tauri** reutilizando el frontend actual:
      icono en el dock/menú inicio, ventana nativa, bandeja del sistema,
      asociación de ficheros `.pcap`/`.pcapng` (doble clic abre SOC SHARK).
- [ ] 🟡⭐ **Instaladores nativos**: MSI/MSIX (Windows, con opción de
      instalar Npcap), `.dmg` firmado y notarizado (macOS), `.deb`, `.rpm`,
      AppImage y Flatpak (Linux).
- [ ] 🟡 **Gestores de paquetes**: `winget`, `scoop`, Homebrew (tap propio,
      luego core), AUR, Nix, `cargo install socshark` (publicar en crates.io).
- [ ] 🟡 **Firma de binarios**: Authenticode (Windows), Apple Developer ID,
      y **firma con Sigstore/cosign + provenance SLSA** en el release
      (GitHub artifact attestations) para todos.
- [ ] 🟢 **`socshark update`** (o aviso en la GUI) que comprueba el último
      release (opt-in, sin telemetría) y verifica firma + SHA-256.
- [ ] 🟢 Imagen **Docker** (`ghcr.io/…/socshark`) para el modo daemon/sensor
      y para análisis en CI: `docker run -v $PWD:/data socshark capture -r /data/x.pcap`.
- [ ] 🟢 Binario **Linux musl estático** (además de glibc 2.17) y
      **Windows ARM64**.
- [ ] 🟢 Paquete para **Raspberry Pi** documentado como «sensor doméstico».
- [ ] 🟢 SBOM (CycloneDX/SPDX) adjunto a cada release.

---

## 21. Línea Q — Seguridad de la propia herramienta

Una herramienta que lee tráfico hostil debe ser ejemplar.

- [ ] 🟡⭐ **Fuzzing guiado por cobertura** con `cargo-fuzz` (libFuzzer) para
      cada disector, el lector pcap/pcapng, el DSL y el carving; integrarse
      en **OSS-Fuzz**. (Hoy hay fuzzing determinista excelente, pero no
      guiado por cobertura.)
- [ ] 🟢 `cargo audit` + `cargo deny` (licencias, advisories, duplicados) en CI.
- [ ] 🟢 **OpenSSF Scorecard** y su badge; Dependabot/Renovate para
      Actions y crates.
- [ ] 🟢 Fijar las GitHub Actions por SHA, permisos mínimos (`permissions:`)
      en los workflows.
- [ ] 🟢 `SECURITY.md` con política de divulgación responsable y contacto.
- [ ] 🟡 Revisión de los ~100 usos de `unsafe` (FFI de libpcap, sockets,
      Windows): documentar el invariante de cada uno (`// SAFETY:`) y
      cubrirlos con Miri donde sea posible.
- [ ] 🟡 **Sandboxing del proceso de análisis**: separar captura
      (privilegiada) de disección (sin privilegios) en procesos distintos;
      en Linux, `seccomp` + `landlock` para el proceso de análisis.
- [ ] 🟢 Ficheros tallados: guardarlos siempre con extensión neutralizada
      (`.bin`) o en ZIP con contraseña `infected` (convención de la
      industria) para evitar ejecuciones accidentales.
- [ ] 🟢 Revisión de la GUI local: CSP ya estricta; añadir tests de CSRF,
      DNS rebinding (ya se comprueba `Host`), límites de tamaño de petición.
- [ ] 🟢 Redacción opcional de datos sensibles en exportaciones e informes
      (IPs internas, nombres de equipo) para poder compartir capturas.
- [ ] 🟡 **Anonimizar capturas** (`socshark anonymize`): reescribir IPs/MAC de
      forma consistente para compartir pcaps de incidentes o reportar bugs.

---

## 22. Línea R — Calidad, tests y CI

- [ ] 🟢⭐ **Matriz de CI**: Linux, Windows y macOS (hoy solo Ubuntu), más
      ARM64 cuando haya runners.
- [ ] 🟢 **MSRV en CI** (Rust 1.75 anunciado: comprobarlo con un job que
      use exactamente esa versión, o subir el MSRV y documentarlo).
- [ ] 🟢 **Cobertura** con `cargo llvm-cov` y objetivo mínimo por crate
      (dissectors/filter/soc ≥ 85 %).
- [ ] 🟡 **Corpus de pcaps reales** (públicos y con licencia compatible:
      Wireshark sample captures, Malware-Traffic-Analysis, CIC-IDS) en un
      repo/bucket aparte; tests de «no regresión» que comparan el JSONL
      generado con uno de referencia (*golden files*).
- [ ] 🟡 **Tests de detección con pcaps de malware reales** (en entorno
      aislado): tasa de detección y falsos positivos por regla,
      publicados.
- [ ] 🟢 Property-based testing (proptest 🧩 o generador propio) para el
      agregador de flujos y el reensamblado TCP.
- [ ] 🟢 Tests E2E del frontend (Playwright, ver Línea I).
- [ ] 🟢 Test de los instaladores en contenedores (Debian, Fedora, Arch,
      Alpine) y en Windows/macOS runners.
- [ ] 🟡 **Modularizar ficheros grandes**: `gui/mod.rs` (1 892 líneas) en
      `api/`, `session.rs`, `stories.rs`…; `explain.rs` (1 228) por dominio.
- [ ] 🟢 `cargo doc` sin warnings y publicado; doc-tests en las APIs públicas.
- [ ] 🟢 Release automático de notas desde CHANGELOG (ya existe) + check de
      que cada PR toca `## [Sin publicar]` cuando cambia comportamiento.
- [ ] 🟢 Conventional commits opcionales + `git-cliff` para generar el
      CHANGELOG (o mantenerlo a mano, como ahora, pero con check).

---

## 23. Línea S — Comunidad y gobernanza

- [ ] 🟢 `CODE_OF_CONDUCT.md` (Contributor Covenant).
- [ ] 🟢 CONTRIBUTING en inglés (y español), con «tu primer PR en 15 minutos».
- [ ] 🟢 Etiquetas: `good first issue`, `help wanted`, `protocolo`,
      `detección`, `gui`, `i18n`, `docs`.
- [ ] 🟢 **Issues creados desde este roadmap** (uno por tarea o por bloque)
      y un **GitHub Project** con columnas por versión.
- [ ] 🟢 GitHub Discussions: preguntas, ideas, «muestra tu red».
- [ ] 🟡 Programa de **«regla del mes»**: la comunidad propone detecciones
      con su pcap de prueba.
- [ ] 🟢 `GOVERNANCE.md` y `MAINTAINERS.md` cuando haya más de un mantenedor.
- [ ] 🟡 Presentar el proyecto: charla en un CON (RootedCON, BSides,
      EuskalHack, OWASP local), post técnico («cómo detectamos beacons sin
      dependencias»), Hacker News / r/netsec / r/blueteamsec.
- [ ] 🟢 Política de versiones y de soporte (qué versiones reciben parches).

---

## 24. Matriz de prioridades

Impacto para usuarios × esfuerzo. Empezar por arriba a la izquierda.

| | Esfuerzo bajo | Esfuerzo medio | Esfuerzo alto |
|---|---|---|---|
| **Impacto alto** | SLL/loopback · GUI lee una vez · ARP/ICMP · HTTP en flujo · README comparativo · CI multi-OS | i18n GUI + motor de frases · QUIC · GeoIP propio · reglas declarativas · tabla virtualizada · sesiones guardadas · benchmarks | App Tauri + instaladores nativos · índice en disco 10 GB · eBPF |
| **Impacto medio** | `doctor` · completions · plantillas de issues · `examples/` por regla · cargo-deny | JA4S/certificados · 10 reglas nuevas · TUI en vivo · informe ejecutivo · syslog/webhook · fuzzing cobertura | CyberChef · SequenceView · correlación temporal · línea base |
| **Impacto bajo** | Badges · brand.md · social preview | MQTT/Modbus · Zeek-like logs · notificaciones | Plugins WASM · AF_XDP · TLS 1.3 uprobes |

### Orden propuesto por versión

**0.8.0 — Pulido y alcance**
1. Ganancias rápidas completas (sección 4).
2. HTTP petición en el flujo + campos DSL.
3. i18n: infraestructura + GUI en inglés (motor de frases en inglés al menos
   para las 7 reglas actuales).
4. README: comparativa, FAQ, privacidad, GIFs.
5. CI: matriz OS, MSRV, cobertura, cargo-deny, SECURITY.md.
6. Verificación en Windows real.

**0.9.0 — Más protocolos, más detección**
1. QUIC Initial + SNI + JA4 QUIC.
2. TLS ServerHello/certificados + JA4S + R16.
3. SMB, Kerberos, RDP, SMTP/FTP (con R11, R12, R19, R20).
4. R8-R10, R13-R15, R24-R25.
5. GeoIP/ASN `.mmdb` propio + mapa del mundo.
6. Reglas declarativas + supresiones + riesgo explicable.
7. DSL 2.0 (CIDR, `in`, rangos, unidades, campos de host/alerta, autocompletado).

**0.10.0 — Escala y sesiones**
1. Benchmarks + perfilado.
2. mmap + índice compacto + carga progresiva.
3. Sesiones `.socshark` + notas + estado de historias.
4. Ring buffer en vivo y rotación.
5. Tabla virtualizada sin límite.
6. TUI en vivo.
7. Medición de rendimiento en vivo sobre hardware real.

**1.0.0 — Producto**
1. App Tauri + instaladores nativos firmados + asociación de ficheros.
2. Actualizaciones verificadas, Sigstore, SBOM.
3. Documentación completa EN/ES en sitio web, tutoriales.
4. Auditoría de accesibilidad AA.
5. Congelar y versionar: formato JSONL, contrato ECS/Wazuh, DSL, API local.
6. Laboratorio Elastic/Wazuh verificado en CI.

---

## 25. Criterios para llamar «1.0» a la 1.0

La 1.0 es una promesa de estabilidad. Se publica solo cuando **todos** se
cumplen:

- [ ] Instalable con un doble clic en Windows, macOS y Linux, con binarios
      firmados, y verificado en máquinas reales de cada sistema.
- [ ] Captura en vivo verificada en Windows 10/11, macOS (Intel y Apple
      Silicon) y al menos tres distribuciones Linux.
- [ ] Interfaz, frases, informe y documentación completos en **inglés y
      español**.
- [ ] Abre una captura de 10 GB en < 60 s y < 2 GB de RAM (medido y
      publicado).
- [ ] ≥ 20 detecciones con MITRE, cada una con pcap de prueba público,
      tests positivo/negativo y tasa de falsos positivos medida sobre
      tráfico doméstico y de oficina.
- [ ] Contratos versionados y documentados: JSONL de `EnrichedFlow`,
      ECS/Wazuh/OCSF, DSL y formato de sesión. Cambios incompatibles solo en
      2.0.
- [ ] Fuzzing guiado por cobertura sin hallazgos abiertos durante 30 días.
- [ ] Accesibilidad WCAG 2.1 AA en la GUI.
- [ ] Cobertura ≥ 80 % en los crates de parsing y SOC.
- [ ] Ningún issue `bug` de severidad alta abierto.

---

## 26. Ideas a largo plazo (2.x y más allá)

- **Modo sensor/servidor**: varios sensores ligeros (Raspberry Pi, puertos
  espejo, equipos de usuarios) envían flujos cifrados y autenticados a una
  consola central; vista unificada de toda la organización o de toda la
  casa (incluidos los móviles vía router).
- **Integración con el router doméstico** (OpenWrt, pfSense/OPNsense):
  paquete oficial que exporta flujos a SOC SHARK, para ver *toda* la casa
  sin espejar puertos.
- **Modelos ligeros locales** (sin nube): detección de anomalías por equipo,
  clasificación de tráfico cifrado por tamaño/tiempo de paquetes (tipo de
  app sobre TLS/QUIC), siempre explicables y opcionales.
- **Asistente en lenguaje natural opcional**: «¿qué hizo el portátil de Ana
  anoche?» → traducido a DSL y ejecutado localmente; con LLM local o, con
  consentimiento explícito, remoto, nunca enviando paquetes completos.
- **Modo formación / CTF**: escenarios guiados con preguntas («encuentra el
  equipo que exfiltra datos»), puntuación y pistas; ideal para cursos de
  Blue Team y universidades.
- **Modo «control parental» transparente**: informe semanal para familias
  («la consola habló con 40 sitios; ninguno peligroso»), sin bloquear
  (coherente con la filosofía de solo lectura).
- **Playbooks**: de una historia a una lista de pasos de respuesta
  interactiva, con registro de lo hecho para el informe.
- **Extensión para navegadores / app móvil** de solo lectura para recibir
  avisos del sensor doméstico.

---

## 27. Riesgos y cómo mitigarlos

| Riesgo | Mitigación |
|---|---|
| **Crecimiento de dependencias** (Tauri, wasmtime, DuckDB, mmdb…) rompe la filosofía de superficie mínima | Un ADR por dependencia; features opcionales (`--features desktop`, `wasm`, `store`); el binario CLI base sigue con las 5 dependencias actuales. |
| **i18n degrada la calidad de las frases**, el corazón del producto | Plantillas revisadas por hablantes nativos; tests de *snapshot* por idioma sobre el escenario demo; empezar por las 7 reglas actuales. |
| **Falsos positivos** con muchas reglas nuevas → fatiga de alertas | Cada regla con medición de FP sobre tráfico real antes de activarse por defecto; supresiones fáciles; reglas nuevas primero en modo «informativo». |
| **Parsers nuevos = superficie de ataque nueva** | Fuzzing guiado por cobertura obligatorio para cada disector; sandboxing del proceso de análisis. |
| **Plataformas sin probar** (Windows real, macOS) | Runners de CI por sistema; programa de *beta testers* con plantilla de informe; `socshark doctor`. |
| **Mantenimiento de un solo autor** | Documentación para contribuidores, issues pequeños etiquetados, gobernanza escrita antes de la 1.0. |
| **Uso indebido** (capturar redes ajenas) | Sección de uso responsable visible, sin funciones ofensivas, descifrado TLS solo opt-in con banner y auditoría. |
| **Rendimiento de la GUI web con capturas enormes** | Virtualización, paginación en la API local, carga progresiva y benchmarks en CI. |

---

<sub>Este roadmap se revisa al cerrar cada versión: las tareas hechas pasan
al CHANGELOG, las que cambian de prioridad se mueven en la matriz y las
nuevas ideas entran por Discussions o issues.</sub>
