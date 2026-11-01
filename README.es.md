<div align="center">

<img src="docs/img/logo.svg" width="112" alt="Logo de SOC SHARK: una aleta de tiburón cortando una ola">

# SOC SHARK

**Tu red, explicada en lenguaje claro.**<br>
Una alternativa moderna y amable a Wireshark para analistas de SOC / Blue Team… y para todos los demás.

[English](README.md) · **Español**

[![CI](https://github.com/Ruby570bocadito/soc-shark/actions/workflows/ci.yml/badge.svg)](https://github.com/Ruby570bocadito/soc-shark/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Ruby570bocadito/soc-shark?color=0e7490&label=versi%C3%B3n)](https://github.com/Ruby570bocadito/soc-shark/releases/latest)
![Plataformas](https://img.shields.io/badge/plataformas-Windows%20%7C%20Linux%20%7C%20macOS-1fb5cc)
![Rust](https://img.shields.io/badge/rust-1.88%2B-orange)
![Licencia](https://img.shields.io/badge/licencia-MIT-green)

<a href="docs/media/demo.mp4"><img src="docs/media/demo.webp" width="900" alt="Recorrido de 35 segundos: abrir una captura, leer qué pasó, ver los paquetes, las estadísticas, el mapa de la red y el tema oscuro"></a>

<sub>▶ Recorrido de 35 segundos por la aplicación · <a href="docs/media/demo.mp4">verlo en MP4</a></sub>

</div>

---

## ⚡ Instalación en una línea

> Descarga el binario listo para usar de tu sistema desde el
> [último release](https://github.com/Ruby570bocadito/soc-shark/releases/latest),
> comprueba su SHA-256, deja `socshark` en tu `PATH` y lo prueba con una
> captura de demostración. **No hace falta compilar: tarda unos segundos.**
> Para actualizar, vuelve a ejecutarlo.

### Windows · PowerShell

```powershell
irm https://raw.githubusercontent.com/Ruby570bocadito/soc-shark/main/install.ps1 | iex
```

### Linux / macOS · bash

```bash
curl -fsSL https://raw.githubusercontent.com/Ruby570bocadito/soc-shark/main/install.sh | bash
```

Y abre la aplicación:

```bash
socshark gui
```

<details>
<summary>Qué hace cada instalador, los permisos de captura en vivo y las opciones</summary>

- **Windows** ([`install.ps1`](install.ps1)): instala `socshark.exe` en
  `%USERPROFILE%\.socshark\bin` y lo añade a tu `PATH` de usuario. Para ver la
  red **en vivo** instala [Npcap](https://npcap.com) (ya lo tienes si usas
  Wireshark) con *WinPcap API-compatible Mode* marcado.
- **Linux** ([`install.sh`](install.sh)): instala en `~/.local/bin`, añade
  `libpcap` si falta y da al binario las capacidades de captura
  (`setcap cap_net_raw,cap_net_admin=ep`): **la red en vivo funciona sin
  sudo**. Ojo: a diferencia de Wireshark (donde solo las tiene el pequeño
  ayudante `dumpcap`), aquí se aplican a **todo el binario `socshark`**,
  parsers y ventana incluidos; separar un ayudante de captura con privilegios
  está planificado (ver [docs/security.md](docs/security.md)). Si no lo
  quieres, usa `SOCSHARK_NO_SETCAP=1` y captura con `sudo` o abre ficheros
  `.pcap`. El binario funciona en cualquier distribución con glibc 2.17 o más
  nueva (x86_64 y ARM64).
- **macOS**: el mismo script, con un binario universal (Apple Silicon e
  Intel); ver la red en vivo necesita `sudo` (o ChmodBPF, de Wireshark).
- **¿No hay binario para tu sistema, o no arranca?** El instalador lo compila
  desde el código, instalando lo necesario (Git, Rust, un enlazador de C; en
  Windows, las Build Tools de C++ de Visual Studio).
- Opciones (variables de entorno): `SOCSHARK_VERSION` (p. ej. `0.9.0`; por
  defecto, la última), `SOCSHARK_FROM_SOURCE=1` (compilar en vez de
  descargar), `SOCSHARK_BIN` (carpeta de instalación en Linux/macOS),
  `SOCSHARK_NO_SETCAP=1`.

</details>

**¿Prefieres descargarlo tú?** Cada
[release](https://github.com/Ruby570bocadito/soc-shark/releases/latest) trae
`socshark` para Windows (`.zip`), Linux x86_64 y ARM64, y macOS (`.tar.gz`),
además de `SHA256SUMS` para comprobarlos: descomprímelo y ejecuta
`socshark gui`.

## Por qué SOC SHARK

Wireshark responde a *«¿qué hay en este paquete?»*. **SOC SHARK responde a
*«¿qué está pasando en mi red y qué me debería preocupar?»*** Conversaciones en
lugar de paquetes, significado en lugar de hexadecimal, alertas en lugar de
desplazarse sin fin:

- cada conversación es **una frase** —*«El equipo «DESKTOP-AB12» usó Telnet
  con el router»*— con su estado ✓ / ! / ✕;
- las alertas se agrupan en **historias** con **qué hacer** y su técnica de
  MITRE ATT&CK;
- y cuando hace falta el detalle, está todo, como en Wireshark: cada paquete,
  sus capas explicadas campo a campo y sus bytes.

## Funciones

| Función | Qué hace |
|---|---|
| 🪟 **Ventana (GUI)** | Conversaciones en lenguaje claro, historias con *qué hacer*, lista de paquetes con capas y bytes resaltados, *Contenido* (seguir la conversación), estadísticas, filtros con clic derecho, lenguaje de filtros, tema claro y oscuro. Abre **pcap y pcapng** y guarda `.pcap`. |
| 🔴 **En vivo** | Tu red en tiempo real: eliges Wi-Fi o cable (con su IP y estado), la ventana se actualiza cada segundo y *Detener* es inmediato. Windows (Npcap), Linux y macOS. |
| 🏷️ **Quién es quién** | Cada equipo por su nombre (*iPhone-de-Ana*, *HP OfficeJet*, *el router*) aprendido de DHCP, mDNS, LLMNR y NetBIOS; fabricante por la MAC; tus propios apodos; en vivo, **qué programa** de tu ordenador abrió cada conexión. |
| 🗺️ **Mapa de la red** | Tus equipos, el router e Internet, y quién habla con quién; lo peligroso en rojo; clic para filtrar. |
| 🔔 **Avisos e informe** | Notificación del sistema cuando aparece algo peligroso o raro; un informe HTML en lenguaje claro para guardar, imprimir o enviar. |
| 💻 **TUI** | Interfaz de terminal Flow-First (Ratatui): una línea por conversación, panel de alertas y filtro DSL en vivo. |
| 🛡️ **Motor SOC** | Mini-IDS: túnel DNS, escaneo de puertos y de red, beaconing (T1071), archivos disfrazados (T1036), tráfico que no es DNS en el puerto 53 (T1571), servicios inseguros; huellas JA4 y SNI; extracción de archivos HTTP con SHA-256; inteligencia de amenazas sin conexión (Feodo, Tor); reensamblado de TCP; IPv6 completo. |
| 📤 **Exportar a SIEM** | JSONL, **Elastic ECS 8.x** y **Wazuh**, con MITRE ATT&CK. |

<table>
  <tr>
    <td width="50%"><img src="docs/img/gui-explicacion.png" alt="Historias y conversaciones explicadas en lenguaje claro"><br><sub><b>Lo que ha pasado</b>: historias, conversaciones y qué hacer</sub></td>
    <td width="50%"><img src="docs/img/gui-mapa.png" alt="Mapa de una red de casa"><br><sub><b>Mapa de la red</b>: equipos por su nombre, el router e Internet</sub></td>
  </tr>
  <tr>
    <td><img src="docs/img/gui-paquetes.png" alt="Lista de paquetes con capas y bytes"><br><sub><b>Paquetes</b>: todos, con sus capas explicadas y los bytes resaltados</sub></td>
    <td><img src="docs/img/gui-estadisticas.png" alt="Estadísticas"><br><sub><b>Estadísticas</b>: actividad en el tiempo, protocolos y servicios</sub></td>
  </tr>
  <tr>
    <td colspan="2"><img src="docs/img/tui.png" alt="La interfaz de terminal (TUI)"><br><sub><b>TUI</b>: el mismo análisis en la terminal — <code>socshark tui -r captura.pcap</code></sub></td>
  </tr>
</table>

## Uso

```bash
# Ventana: ver la red en vivo, o abrir/arrastrar una captura (pcap o pcapng)
socshark gui
socshark gui -r captura.pcapng

# Interfaz de terminal
socshark tui -r captura.pcap

# Informe en lenguaje claro (un HTML para guardar, imprimir o enviar)
socshark report -r captura.pcap -o informe.html

# Tabla resumen, JSONL y el lenguaje de filtros (docs/filter-dsl.md)
socshark capture -r captura.pcap
socshark capture -r captura.pcap --json - | jq '.risk_score'
socshark capture -r captura.pcap -f "tcp.port == 443 || flow.risk >= 50"

# Extraer archivos HTTP y detectar los disfrazados (T1036); inteligencia sin conexión
socshark capture -r captura.pcap --carve-files
socshark capture -r captura.pcap --intel-feodo feodo.txt --intel-tor tor-exits.txt

# Seguir una conversación TCP reensamblada
socshark follow -r captura.pcap --flow "93.184.216.34:443"

# Exportar a un SIEM
socshark export -r captura.pcap -F ecs -o ecs.jsonl
socshark export -r captura.pcap -F wazuh -o wazuh.jsonl

# Captura en vivo desde la consola (filtro BPF aplicado en el kernel)
socshark daemon --list
socshark daemon -i eth0 --bpf "tcp port 443" --json flujos.jsonl

# ¿Sin captura a mano? Genera una: un ataque de demostración o una red de casa
socshark dev sample-pcap -o demo.pcap
socshark dev sample-pcap --escenario casa -o casa.pcap
```

## Compilar desde el código

Requisitos: [Rust 1.88+](https://rustup.rs) y un enlazador de C. Para ver la
red en vivo hace falta además libpcap (Linux; macOS ya la trae) o
[Npcap](https://npcap.com) (Windows) al ejecutar: se carga al vuelo, no se
enlaza al compilar.

```bash
git clone https://github.com/Ruby570bocadito/soc-shark.git
cd soc-shark
./install.sh                     # compila esta copia y la instala; o: cargo build --release
./target/release/socshark gui -r examples/demo.pcap
```

Ver la red en vivo en Linux sin el instalador: da el permiso una vez con
`sudo setcap cap_net_raw,cap_net_admin=ep "$(command -v socshark)"`, o
ejecútalo con `sudo`.

## Estado del proyecto

| Área | Estado |
|---|---|
| Captura (archivos y en vivo), disectores, agregación de flujos, lenguaje de filtros | ✅ Hecho |
| Motor SOC: mini-IDS, JA4, beaconing, extracción de archivos, inteligencia, exportación SIEM | ✅ Hecho |
| Ventana (en vivo, quién es quién, mapa, avisos, informe) y TUI | ✅ Hecho |
| Atribución de procesos con eBPF (hoy: tabla de sockets del sistema, Linux/Windows) | 🟡 Diseñado — [ebpf-design.md](docs/ebpf-design.md) |
| Descifrado transparente de TLS 1.3 (uprobes en `SSL_read/SSL_write`) | 🔵 Previsto |
| Plugins WASM aislados · decodificador tipo CyberChef · GeoIP/ASN · TheHive | 🔵 Previsto — [roadmap.md](docs/roadmap.md) |

Calidad: más de 300 tests unitarios y de integración, un corpus de capturas
reales con su resultado esperado, fuzzing determinista y guiado por cobertura
en CI, `clippy -D warnings` y `rustfmt` sin excepciones, disectores sin `panic`
(un paquete malformado u hostil produce `None`, nunca un cierre) y las
dependencias justas.

<details>
<summary>Estructura del repositorio</summary>

```text
soc-shark/
├── crates/
│   ├── socshark-core/         # EnrichedFlow, paquetes crudos, configuración
│   ├── socshark-capture/      # Lector pcap/pcapng + captura en vivo (FFI libpcap/Npcap, dlopen)
│   ├── socshark-dissectors/   # Ethernet, IPv4/6, TCP, UDP, DNS, TLS, DHCP… + pool concurrente
│   ├── socshark-flow/         # Agregador de flujos bidireccionales
│   ├── socshark-filter/       # Lenguaje de filtros (lexer, parser, evaluador)
│   ├── socshark-soc/          # Ruido, DNS pasivo, riesgo, lenguaje claro, carving, intel, export SIEM
│   ├── socshark-ebpf-common/  # Tipos compartidos entre sondas eBPF y espacio de usuario
│   ├── socshark-testgen/      # Constructores de tramas, escenarios de demo, fuzzing
│   └── socshark-cli/          # El binario `socshark`: gui, tui, capture, report, daemon…
├── docs/                      # Documentación — empieza por docs/index.md
├── examples/demo.pcap         # Captura de demostración
├── install.ps1 · install.sh   # Instaladores de una línea
└── .github/workflows/
    ├── ci.yml                 # fmt + clippy + tests (Linux/Windows/macOS) + MSRV + fuzzing
    └── release.yml            # Binarios de cada versión (Windows, Linux, macOS) + SHA256SUMS
```

</details>

**Documentación**: [índice](docs/index.md) · [ventana (GUI)](docs/gui.md) ·
[TUI](docs/tui.md) · [arquitectura](docs/architecture.md) ·
[lenguaje de filtros](docs/filter-dsl.md) · [MITRE ATT&CK](docs/soc-mitre-mapping.md) ·
[exportación SIEM](docs/siem-export.md) · [modelo de seguridad](docs/security.md) ·
[cambios](CHANGELOG.md)

## Uso responsable

SOC SHARK es una herramienta **defensiva** para analistas de SOC y Blue Team,
investigadores y cualquiera que quiera entender su propia red. Capturar tráfico
de redes que no administras puede ser ilegal donde vives: úsala solo en redes
propias o con permiso explícito y, en el trabajo, según tu política de
monitorización.

## Licencia

MIT — ver [LICENSE](LICENSE).
