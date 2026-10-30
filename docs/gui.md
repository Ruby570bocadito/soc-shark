# La GUI de soc-shark

`socshark gui` abre una ventana para explorar una captura **como en
Wireshark, pero explicada para cualquier persona**. Wireshark enseña campos
(`40001 → 22 [SYN] Seq=0 Win=1024`); soc-shark enseña frases: quién habló
con quién, qué hizo, si es normal y qué hacer si no lo es.

![La GUI con la captura de demostración](img/gui-explicacion.png)

## Arranque

```bash
socshark gui                              # ventana vacía: «En vivo» o abrir una captura
socshark gui -r captura.pcap              # abre ya una captura
socshark gui -r captura.pcap --intel-feodo feodo.txt --intel-tor tor.txt
socshark gui --no-open                    # solo imprime la dirección (http://127.0.0.1:8787/)
socshark gui --port 9000                  # otro puerto local
```

La ventana se abre sola: en Windows, como aplicación propia con Edge o
Chrome (modo `--app`, sin barra del navegador); en macOS y Linux, en el
navegador por defecto. Se cierra con **Ctrl+C** en la consola.

Sin captura abierta, la ventana da la bienvenida con las dos formas de
empezar: **ver la red en vivo** o **abrir una captura**.

![Bienvenida: ver la red en vivo o abrir una captura](img/gui-bienvenida.png)

Las capturas se pueden abrir con **Abrir**, con **Ctrl+O** o
**arrastrándolas a la ventana**. Formatos: **pcapng** (el que guarda
Wireshark por defecto) y pcap clásico.

## Ver la red en tiempo real

Botón **En vivo** (o **Ctrl+E**). La ventana pregunta por dónde escuchar y
lo dice en claro: **Tu red** (Wi-Fi o cable, con su dirección IP y si está
conectada), **Este mismo equipo** (loopback) y, plegadas, las interfaces
especiales (Bluetooth, NFLOG, adaptadores virtuales…). Opcionalmente, un
**filtro de captura** BPF (`port 53`, `host 192.168.1.10`…) que decide qué
se guarda; el filtro de la barra superior solo decide qué se muestra.

![Elegir la red que se quiere ver](img/gui-en-vivo.png)

Mientras captura:

- La ventana se actualiza **cada segundo**: conversaciones, historias,
  paquetes y estadísticas. Lo que estás mirando (la conversación elegida,
  el filtro, el desplazamiento) se conserva.
- En **Paquetes**, la lista **sigue los nuevos** (se puede desmarcar, o
  basta con desplazarse hacia arriba).
- La barra de estado muestra el tiempo capturando, los paquetes y los
  **perdidos por el sistema** si el equipo no da abasto.
- **Detener** es inmediato aunque no pase tráfico (`pcap_breakloop`). Lo
  capturado se queda para revisarlo con calma o **guardarlo** como `.pcap`.

Se guardan los últimos 500.000 paquetes (o 256 MiB) y las últimas 20.000
conversaciones terminadas; lo anterior se descarta para no agotar la memoria.
El tráfico de la propia ventana con soc-shark se excluye automáticamente.

**Permisos.** Capturar exige privilegios:

| Sistema | Qué hace falta |
|---|---|
| Windows | [Npcap](https://npcap.com) (el driver de Wireshark) con «WinPcap API-compatible Mode». Si lo instalaste restringido a administradores, abre la consola como administrador |
| Linux | `sudo socshark gui`, o una vez `sudo setcap cap_net_raw,cap_net_admin=ep $(which socshark)` |
| macOS | `sudo socshark gui`, o permisos de lectura en `/dev/bpf*` (los da el instalador de Wireshark) |

## Quién es quién

Una dirección como `192.168.1.30` no le dice nada a nadie. soc-shark llama
a cada equipo por lo que **él mismo anuncia** en la red:

| De dónde | Qué se aprende |
|---|---|
| DHCP (al conectarse a la red) | El nombre que el equipo se pone («iPhone-de-Ana», «DESKTOP-AB12») y su sistema («MSFT 5.0» → Windows, Android) |
| mDNS / LLMNR | Nombres `.local` y servicios: impresora, Chromecast, AirPlay, altavoz, domótica… con su nombre bonito («HP OfficeJet Pro 8020», «Salón») |
| NetBIOS | El nombre de los equipos Windows |
| La MAC | El **fabricante** (registro público del IEEE, solo marcas de casa y oficina: Apple, Samsung, Xiaomi, TP-Link, routers de operadora…) y si es una MAC **aleatoria** (móviles y portátiles con privacidad) |
| Por dónde sale el tráfico a Internet | Cuál es **el router** |
| En vivo | Cuál es **este ordenador** y **qué programa** abrió cada conexión (Chrome, Spotify, Outlook…; Linux y Windows) |

Las frases los usan: «El equipo «iPhone-de-Ana» (192.168.1.30) abrió una
conexión segura con www.instagram.com», «el equipo «DESKTOP-AB12» habló
con **el router** por Telnet», «El programa Outlook de este ordenador…».

Y puedes **ponerles nombre** tú («Portátil de Ana», «Tele del salón»):
botón *Ponerle nombre* en la explicación o en *Estadísticas → Equipos*, o
clic derecho. Se guarda en este ordenador (`apodos.json` en la carpeta de
configuración del usuario) y se usa en todas las capturas; al equipo se le
reconoce por su MAC, o por su IP si no se conoce.

Para probarlo sin red: `socshark dev sample-pcap --escenario casa -o casa.pcap`.

Ojo: un equipo puede mentir sobre su nombre. Todo esto es informativo:
ninguna alerta depende de ello.

## Qué hay en la ventana

Cuatro vistas, como las ventanas principales de Wireshark (teclas `1` a `4`):

| Vista | Qué muestra |
|---|---|
| **Conversaciones** | Una línea por conversación. En modo **Simple**, una frase («El equipo 192.168.1.10 abrió una conexión segura con store.ejemplo-corporativo.com»); en modo **Experto**, las columnas técnicas (inicio, protocolo, origen, destino, paquetes, bytes, duración, riesgo, alertas). Las columnas se ordenan con un clic |
| **Paquetes** | **Todos** los paquetes, uno a uno, como la lista principal de Wireshark: número, tiempo, origen, destino, protocolo, tamaño y una frase («Pide abrir una conexión (SYN)», «Saludo TLS del cliente…»). Coloreados por gravedad. Debajo, las capas explicadas y los bytes. Lista virtual: cientos de miles de paquetes sin bloquear la ventana. Doble clic: ir a su conversación |
| **Estadísticas** | Paquetes o datos **en el tiempo** (picos = ráfagas de actividad), **protocolos** por volumen, **servicios** (puertos de destino, con lo que es cada uno) y **equipos que más hablan** (con su nombre, marca, sistema; enviado, recibido, con cuántos, si están en tu red o en Internet). Un clic en cualquier fila filtra por ella |
| **Mapa** | Un **dibujo de la red**: tus equipos a la izquierda (con icono: ordenador, móvil, impresora, tele…), el router en el centro y los sitios de Internet a la derecha, por su nombre. Cuanto más gruesa la línea, más datos; en rojo o naranja (con su icono) lo peligroso o raro. Al pasar el ratón por un equipo se ilumina con quién habla; un clic filtra toda la ventana. También como lista |

![Lista completa de paquetes con capas y bytes](img/gui-paquetes.png)

A la izquierda, siempre (se oculta con **Ctrl+B**):

| Zona | Qué muestra |
|---|---|
| **Resumen** | Cuántas conversaciones son peligro (✕ en rojo), raras (! en naranja) y normales (✓ en verde), y cuánto tráfico hay. El color siempre va con su icono |
| **Lo que ha pasado** | Las alertas contadas como *historias*: un escaneo de 12 puertos es **una** historia, no 12 líneas. Cada una dice qué pasó y **qué hacer**, con su técnica MITRE ATT&CK enlazada |

Al elegir una conversación, abajo:

| Pestaña | Qué muestra |
|---|---|
| **Explicación** | La frase completa, si es normal, cada alerta explicada con su «qué hacer» y los datos de la conversación (cuándo, volumen, dominio, SNI, huella JA4, archivos extraídos…) |
| **Paquetes** | Los paquetes de esa conversación, con sus **capas** (cada campo y su significado) y sus **bytes**. Al pasar el ratón por una capa se iluminan sus bytes; al pasarlo por un byte, se ilumina su capa |
| **Contenido** | Lo que se dijeron, **tal cual** (el «Seguir flujo» de Wireshark): en azul lo que envió quien empezó, en naranja la respuesta; en texto o en hexadecimal, y con botón para copiar. Avisa si va cifrado o si faltan trozos |
| **Técnico** | El `EnrichedFlow` completo en JSON, igual que `socshark capture --json` |

![Contenido de una descarga HTTP: la petición y la respuesta tal cual](img/gui-contenido.png)

![Estadísticas: actividad en el tiempo, protocolos y servicios](img/gui-estadisticas.png)

![Mapa de una red de casa: el PC usó Telnet con el router (en rojo)](img/gui-mapa.png)

## Avisos e informe

- **Avisos** (la campana, o la casilla del diálogo *En vivo*): mientras
  capturas, en cuanto aparece algo **peligroso o raro** salta un aviso en
  la ventana y una **notificación del sistema** (la primera vez se pide
  permiso) con qué pasó y qué hacer; al pulsarla, te lleva a la historia.
  Si estás en otra ventana, el título cuenta los avisos pendientes. Las
  historias recién aparecidas llevan la marca «Nuevo».
- **Informe** (`Ctrl`+`I`): descarga un HTML de un solo archivo, en
  lenguaje claro, para guardar, imprimir o mandar a quien te ayuda con la
  informática: veredicto, lo que ha pasado con su «qué hacer», equipos de
  tu red (con nombre, marca y sistema), sitios de Internet, tipos de
  tráfico y las conversaciones a mirar. Las horas van en tu zona horaria.
  Desde la consola: `socshark report -r captura.pcapng -o informe.html
  --utc-offset 120`.

![Informe en lenguaje claro](img/gui-informe.png)

Las palabras técnicas (DNS, TCP, puerto, SYN, JA4…) aparecen subrayadas:
al pasar el ratón por encima se explican. El glosario completo y ejemplos
de filtros están en la ayuda (**F1** o el botón **?**). Los separadores
entre paneles se arrastran (o se ajustan con las flechas; doble clic los
devuelve a su sitio).

### Filtros

- **Todo** / **Solo lo importante** (oculta lo normal).
- **Tráfico de fondo**: NTP, mDNS y similares están ocultos por defecto
  (*Smart Noise Dimming*).
- **Filtro**: el mismo DSL que `socshark capture -f`
  ([filter-dsl.md](filter-dsl.md)), con historial. Si tiene un error, se
  señala la posición exacta.
- **Clic derecho** en cualquier conversación, paquete, equipo o servicio
  (como «Aplicar como filtro» de Wireshark): ver solo esa conversación, ese
  equipo (`ip.addr == …`), ese puerto o ese protocolo, u **ocultarlo**.
  Con «Añadir al filtro actual» se suma al que ya hay. También copia
  direcciones o el filtro.

Los tres filtros se aplican a la vez a las tres vistas: los números de la
lista, de los paquetes y de las estadísticas siempre cuadran.

### Atajos

| Tecla | Acción |
|---|---|
| `Ctrl`+`E` | Empezar / detener la captura en vivo |
| `Ctrl`+`O` | Abrir captura |
| `Ctrl`+`S` | Guardar como `.pcap` |
| `Ctrl`+`I` | Informe en lenguaje claro |
| `/` | Escribir un filtro |
| `1` `2` `3` `4` | Conversaciones / Paquetes / Estadísticas / Mapa |
| `↑` / `↓` | Moverse por la lista |
| `Menú` o `Mayús`+`F10` | Menú de filtros de la fila elegida |
| `Ctrl`+`B` | Mostrar u ocultar el resumen |
| `F1` | Ayuda y glosario |

Se recuerdan entre sesiones: modo, tema, vista, tamaño de los paneles,
historial de filtros, interfaz, filtro de captura y avisos.

### Comparado con Wireshark

| Wireshark | soc-shark |
|---|---|
| Lista de paquetes, detalle por capas, bytes | ✅ Igual, con cada capa y campo explicados |
| Captura en vivo con filtro de captura | ✅ (libpcap / Npcap) |
| Filtros de visualización, «Aplicar como filtro» | ✅ Por conversación (DSL propio; no todos los campos de Wireshark) |
| Seguir flujo TCP | ✅ «Contenido» (TCP y UDP) |
| Estadísticas: jerarquía de protocolos, endpoints, gráfica de E/S | ✅ Versión simplificada |
| Guardar / abrir capturas | ✅ Abre pcapng y pcap; guarda pcap |
| Resolución de nombres | ✅ Más allá: nombre que anuncia cada equipo, fabricante, router, apodos propios |
| Saber qué programa abrió cada conexión | ✅ En vivo (Linux y Windows) — Wireshark no lo hace |
| Mapa de quién habla con quién | ✅ Dibujo de la red — Wireshark no tiene uno así |
| Avisar cuando pasa algo e informe para personas | ✅ — Wireshark no lo hace |
| Detectar lo raro y decir qué hacer | ✅ Historias, semáforo, MITRE ATT&CK — Wireshark no lo hace |
| ~3.000 protocolos diseccionados | ❌ Hoy: Ethernet, IPv4/IPv6, TCP, UDP, ICMP, DNS, TLS, HTTP |
| Descifrar TLS con claves, VoIP, Bluetooth/USB, perfiles de color | ❌ No |

## Cómo está hecha

Decisión completa en [ADR-013](decisions.md). En resumen:

- **Página local servida por el propio binario**, sin dependencias nuevas:
  un servidor HTTP/1.1 mínimo (`socshark-cli::gui::http`) y tres archivos
  (`crates/socshark-cli/assets/gui/`: `index.html`, `app.css`, `app.js`)
  incrustados con `include_str!`. Sin frameworks ni CDN: funciona sin
  Internet.
- **El lenguaje claro vive en el motor**, no en la interfaz:
  `socshark-soc::explain` produce el semáforo, las frases, la explicación de
  cada alerta y las historias agrupadas. Cualquier interfaz (CLI, TUI, una
  futura app Tauri) puede reutilizarlo.
- **Índice de paquetes** (`socshark-cli::gui::packets`): tras el pipeline
  de flujos se relee la captura y cada trama se asocia a su conversación con
  la misma clave canónica del agregador (`FlowKey`). Al pedir un paquete se
  vuelve a diseccionar y se cuenta capa a capa, con el rango de bytes de
  cada una. Las tramas se guardan en memoria hasta 256 MiB; por encima, la
  lista sigue disponible pero sin contenido.

### API local

Todas las rutas `/api/*` exigen la cabecera `X-Socshark-Token`.

| Ruta | Respuesta |
|---|---|
| `GET /api/session` | Captura abierta, recuentos y semáforo global |
| `GET /api/stories` | Historias (alertas agrupadas) |
| `GET /api/flows?filter=DSL` | Conversaciones con su `explain`; `400` con `pos` si el filtro es inválido |
| `GET /api/flows/{i}/packets` | Paquetes de una conversación con su frase |
| `GET /api/flows/{i}/stream` | Contenido reensamblado por turnos (seguir flujo) |
| `GET /api/packets?offset&limit&…` | Página de la lista global de paquetes (máx. 1.000 filas) |
| `GET /api/packets/{n}` | Capas explicadas, rangos de bytes y volcado hexadecimal |
| `GET /api/stats?…` | Totales, protocolos, servicios y equipos |
| `GET /api/timeline?…` | Paquetes y bytes por intervalo (120 intervalos) |
| `GET /api/save.pcap` | Lo capturado/abierto como pcap clásico |
| `GET /api/live/ifaces` | Interfaces con descripción, direcciones y estado |
| `POST /api/live/start?iface=…&bpf=…` | Empieza la captura en vivo (sustituye la sesión) |
| `POST /api/live/stop` | La detiene; lo capturado se queda abierto |
| `GET /api/hosts` | Quién es quién: nombre, fabricante, sistema, papel, apodo y su clave |
| `POST /api/hosts/nick?key=mac:…\|ip:…&name=…` | Pone (o quita, con `name` vacío) un apodo y rehace las frases |
| `GET /api/map?…` | Nodos y enlaces del mapa de la red |
| `GET /api/report.html?tz=…` | El informe en lenguaje claro (descarga) |
| `POST /api/open?name=…` | Analiza la captura enviada en el cuerpo (máx. 512 MiB) |

Las rutas de paquetes, estadísticas, mapa y línea de tiempo aceptan los mismos
recortes que la ventana: `filter=DSL`, `noise=0` (sin tráfico de fondo) e
`important=1` (solo raro o peligro). En vivo, cada foto nueva incrementa
`generation` en `/api/session`; la ventana la consulta cada segundo.

## Seguridad

La captura la controla quien genera el tráfico: un nombre de dominio, una
ruta HTTP o un nombre de archivo pueden ser maliciosos. Por eso:

- El servidor **solo escucha en `127.0.0.1`**.
- Se exige la cabecera `Host` local exacta (`127.0.0.1:puerto`,
  `localhost:puerto`): bloquea el *DNS rebinding*.
- Toda la API exige un **token aleatorio de sesión** incrustado en la
  página. Una web ajena abierta en el mismo navegador no puede leerlo (misma
  política de origen) ni enviarlo (cabecera propia ⇒ preflight CORS que
  nunca se aprueba).
- El frontend **nunca usa `innerHTML` con datos**: todo se pinta como
  texto (también en la lista de paquetes, el contenido, las estadísticas y
  los menús). Verificado con una captura cuyo nombre DNS es
  `<img src=x onerror=alert(1)>`: se muestra literal y no se ejecuta nada
  en ninguna vista.
- Ni siquiera estilos en línea: la CSP no admite `style="…"`; la posición
  de las filas y el ancho de las barras se fijan por CSSOM.
- Cabeceras estrictas: CSP `default-src 'none'` (solo los tres archivos
  propios), `X-Frame-Options: DENY`, `nosniff`, `no-store`, `no-referrer`.
- Límites: cabeceras 16 KiB, captura subida 512 MiB, tiempo de lectura 30 s.
  Endurecimiento en curso: el cuerpo solo se lee tras validar `Host` y
  token (sin token no se acepta ni un byte de subida), número máximo de
  conexiones simultáneas, y anidamiento de filtros limitado a 128 niveles.
- **Privilegios**: en Linux, si `install.sh` aplicó `setcap`, el proceso de
  la ventana tiene `CAP_NET_RAW`/`CAP_NET_ADMIN` (es el mismo binario que
  captura); ver el modelo real en [security.md](security.md).
- **Apodos**: archivo local (`apodos.json`), claves validadas, apodos
  limpios y acotados. **Informe**: todo escapado y con CSP propia sin
  scripts.
- **En vivo**: solo se escucha (en modo promiscuo, como Wireshark); no se
  envía nada a la red. Iniciar una captura exige el token, como el resto de
  la API, así que una web ajena no puede ponerte a capturar.

## Próximos pasos

- Empaquetado como aplicación de escritorio (Tauri) reutilizando el mismo
  frontend.
- Tabla de conversaciones virtualizada (hoy se pintan de 2.000 en 2.000, y
  hasta 10.000; el resto, con un filtro).
- Más protocolos en la vista de capas (QUIC, SMB, DHCP…).
- Programa por conexión en macOS y con eBPF (también para conexiones
  muy cortas, que hoy pueden escaparse entre dos fotos).
- Probar la captura en vivo en Windows real con Npcap (verificada con el
  `wpcap.dll` de Wine).
