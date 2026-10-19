# La GUI de soc-shark

`socshark gui` abre una ventana para explorar una captura **como en
Wireshark, pero explicada para cualquier persona**. Wireshark enseña campos
(`40001 → 22 [SYN] Seq=0 Win=1024`); soc-shark enseña frases: quién habló
con quién, qué hizo, si es normal y qué hacer si no lo es.

![La GUI con la captura de demostración](img/gui-explicacion.png)

## Arranque

```bash
socshark gui                              # ventana vacía: abre la captura desde ella
socshark gui -r captura.pcap              # abre ya una captura
socshark gui -r captura.pcap --intel-feodo feodo.txt --intel-tor tor.txt
socshark gui --no-open                    # solo imprime la dirección (http://127.0.0.1:8787/)
socshark gui --port 9000                  # otro puerto local
```

La ventana se abre sola: en Windows, como aplicación propia con Edge o
Chrome (modo `--app`, sin barra del navegador); en macOS y Linux, en el
navegador por defecto. Se cierra con **Ctrl+C** en la consola.

Las capturas se pueden abrir con el botón **Abrir captura…**, con
**Ctrl+O** o **arrastrándolas a la ventana**. Formato: pcap clásico (en
Wireshark, *Guardar como → pcap*; un pcapng da un aviso con la forma de
convertirlo).

## Qué hay en la ventana

| Zona | Qué muestra |
|---|---|
| **Resumen** (arriba a la izquierda) | Cuántas conversaciones son peligro 🔴, raras 🟠 y normales 🟢, y cuánto tráfico hay |
| **Lo que ha pasado** | Las alertas contadas como *historias*: un escaneo de 12 puertos es **una** historia, no 12 líneas. Cada una dice qué pasó y **qué hacer**, con su técnica MITRE ATT&CK enlazada |
| **Conversaciones** | Una línea por conversación. En modo **Simple**, una frase («El equipo 192.168.1.10 abrió una conexión segura con store.ejemplo-corporativo.com»); en modo **Experto**, las columnas técnicas de siempre (protocolo, origen, destino, paquetes, bytes, riesgo, alertas) |
| **Explicación** | La frase completa, si es normal, cada alerta explicada con su «qué hacer» y los datos de la conversación (cuándo, volumen, dominio, SNI, huella JA4, archivos extraídos…) |
| **Paquetes** | La vista de Wireshark, explicada: la lista de paquetes con lo que hace cada uno («Pide abrir una conexión (SYN)», «Saludo TLS del cliente…», «Pregunta DNS: ¿dónde está example.com?»), las **capas** con cada campo y su significado, y los **bytes** en hexadecimal. Al pasar el ratón por una capa se iluminan sus bytes; al pasarlo por un byte, se ilumina su capa |
| **Técnico** | El `EnrichedFlow` completo en JSON, igual que `socshark capture --json` |

![Vista de paquetes: capas explicadas y bytes resaltados](img/gui-paquetes.png)

Las palabras técnicas (DNS, TCP, puerto, SYN, JA4…) aparecen subrayadas:
al pasar el ratón por encima se explican. El glosario completo y ejemplos
de filtros están en la ayuda (**F1** o el botón **?**).

### Filtros

- **Todo** / **Solo lo importante** (oculta lo normal).
- **Mostrar tráfico de fondo**: NTP, mDNS y similares están ocultos por
  defecto (*Smart Noise Dimming*).
- **Filtro avanzado**: el mismo DSL que `socshark capture -f`
  ([filter-dsl.md](filter-dsl.md)). Si tiene un error, se señala la
  posición exacta.

### Atajos

| Tecla | Acción |
|---|---|
| `/` | Escribir un filtro |
| `↑` / `↓` | Moverse por las conversaciones |
| `Ctrl`+`O` | Abrir captura |
| `F1` | Ayuda y glosario |

Las preferencias de modo (Simple/Experto) y tema (claro/oscuro) se
recuerdan entre sesiones.

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
| `GET /api/packets/{n}` | Capas explicadas, rangos de bytes y volcado hexadecimal |
| `POST /api/open?name=…` | Analiza la captura enviada en el cuerpo (máx. 512 MiB) |

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
  texto. Verificado con una captura cuyo nombre DNS es
  `<img src=x onerror=alert(1)>`: se muestra literal y no se ejecuta nada.
- Cabeceras estrictas: CSP `default-src 'none'` (solo los tres archivos
  propios), `X-Frame-Options: DENY`, `nosniff`, `no-store`, `no-referrer`.
- Límites: cabeceras 16 KiB, captura subida 512 MiB, tiempo de lectura 30 s.

## Próximos pasos

- Empaquetado como aplicación de escritorio (Tauri) reutilizando el mismo
  frontend.
- Tabla virtualizada para capturas con cientos de miles de conversaciones
  (hoy se muestran las 10.000 primeras; el resto, con un filtro).
- Vista en vivo alimentada por el daemon.
- Nombres de equipo (DHCP, mDNS, NetBIOS) en lugar de direcciones IP.
