# Security policy

**English** · [Español](#política-de-seguridad)

SOC SHARK parses packets written by attackers, so security bugs matter.
Thank you for helping keep it safe.

## Supported versions

| Version | Supported |
|---|---|
| Latest release | ✅ security fixes |
| `main` | ✅ fixed first, released as soon as possible |
| Older releases | ❌ please update (re-run the installer) |

## Reporting a vulnerability

**Do not open a public issue.** Report it privately through GitHub:
[Security → Report a vulnerability](https://github.com/Ruby570bocadito/soc-shark/security/advisories/new).

Please include:

- the version (`socshark --version`) and your operating system;
- what happens (crash, hang, memory exhaustion, wrong privileges, code
  execution, data leak…) and what you expected;
- a way to reproduce it, ideally a small capture (`.pcap`/`.pcapng`), a
  filter expression or an HTTP request to the local GUI. Strip personal data
  from captures, or build a synthetic one.

## What to expect

| Step | Target time |
|---|---|
| Acknowledgement | 3 days |
| First assessment (confirmed or not, severity) | 7 days |
| Fix released for High/Critical | 30 days |
| Fix released for Low/Medium | next regular release |

This is a small project maintained in spare time; these are targets, not a
contract. You will be credited in the CHANGELOG and the advisory unless you
prefer otherwise. Please give us the chance to release a fix before
disclosing.

## Scope

In scope:

- a capture file, live traffic, filter expression or GUI request that
  crashes, hangs or exhausts the memory of `socshark`;
- anything that lets another local process or a web page drive the local
  GUI (it binds to `127.0.0.1` and requires a per-session token);
- the installers (`install.sh`, `install.ps1`) and release artifacts;
- privilege issues with the Linux capture capabilities (see
  [docs/security.md](docs/security.md));
- detection evasions that make the mini-IDS miss what it documents it
  detects (lower severity, but welcome).

Out of scope: findings that need an attacker who already runs code as your
user or as root, and denial of service by sheer traffic volume on live
capture.

---

# Política de seguridad

SOC SHARK interpreta paquetes escritos por atacantes: los fallos de seguridad
importan.

- **Versiones con soporte:** el último release y `main`. Para las
  anteriores, actualiza (vuelve a ejecutar el instalador).
- **Cómo reportar:** **no abras un issue público.** Usa
  [Security → Report a vulnerability](https://github.com/Ruby570bocadito/soc-shark/security/advisories/new)
  con la versión, el sistema, qué ocurre y cómo reproducirlo (idealmente una
  captura pequeña sin datos personales, un filtro o una petición a la GUI).
- **Plazos objetivo:** acuse en 3 días, valoración en 7, arreglo publicado en
  30 días para High/Critical y en el siguiente release para el resto. Se te
  reconocerá en el CHANGELOG salvo que prefieras lo contrario.
- **Alcance:** caídas, cuelgues o agotamiento de memoria con capturas,
  tráfico, filtros o peticiones a la GUI; control de la GUI local desde otro
  proceso o una web; instaladores y binarios publicados; privilegios de
  captura en Linux; evasiones de las detecciones documentadas.
