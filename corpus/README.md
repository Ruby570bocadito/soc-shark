# Corpus de verificación

Este directorio responde a una pregunta: **¿lo que dice soc-shark es
verdad?** Cada captura declara qué debe detectarse y qué no, y guarda el
resultado esperado en un *golden file*. El test
[`crates/socshark-cli/tests/corpus.rs`](../crates/socshark-cli/tests/corpus.rs)
corre en cada `cargo test` y en CI.

```bash
cargo test -p socshark-cli --test corpus                     # comprobar
SOCSHARK_BLESS=1 cargo test -p socshark-cli --test corpus    # regenerar golden/
python3 scripts/fetch_corpus.py                              # bajar capturas reales
SOCSHARK_CORPUS_STRICT=1 cargo test -p socshark-cli --test corpus  # fallar si falta alguna
```

## Estructura

| Ruta | Contenido |
|---|---|
| `manifest.json` | una entrada por captura con su verdad de campo |
| `golden/<name>.json` | resultado esperado: nº de flujos, alertas por regla y flujos alertados con su riesgo |
| `captures/` | capturas reales descargadas (**no se versionan**, ver `.gitignore`) |

## Campos de una entrada

| Campo | Significado |
|---|---|
| `name` | identificador; da nombre al golden |
| `synthetic` | escenario de `socshark-testgen` (`sample`, `home`, `dns_benign`, …) |
| `file` | o bien una captura real, relativa a `corpus/` (p. ej. `captures/x.pcap`) |
| `url`, `sha256` | de dónde bajarla (solo `https://`) y su huella; el test comprueba la huella |
| `gunzip` | `true` si la descarga es un `.gz` (se guarda descomprimida) |
| `zip_member`, `zip_password` | si la descarga es un .zip |
| `source` | procedencia y licencia, en una frase |
| `carve_files` | activar el *carving* HTTP (necesario para `FILE-MASQUERADING`) |
| `must` | reglas que **tienen** que saltar al menos una vez (verdaderos positivos) |
| `must_not` | reglas que **no pueden** saltar (falsos positivos conocidos) |
| `max_severity` | severidad máxima aceptable en toda la captura |
| `known_miss` | lo que la fuente dice que hay y soc-shark **no** detecta todavía (texto); el test lo lista en su resumen para que no se olvide |
| `note` | observación sin verificar (p. ej. una alerta que la fuente no explica); no la comprueba el test |

## Añadir una captura real

1. Elige una captura **pública y sin datos personales**, con licencia que
   permita usarla para pruebas. Buenas fuentes:
   - [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
     (tráfico legítimo variado: el mejor sitio para cazar falsos positivos);
   - [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/)
     (infecciones reales con C2, beacons y descargas; los zip llevan
     contraseña y contienen malware: **no los subas al repo**);
   - [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
     (escaneos, fuerza bruta y exfiltración etiquetados por día).
2. Añade la entrada a `manifest.json` con `file`, `url`, `source` y lo que
   *sabes* que contiene (por el informe de la fuente, no por lo que diga
   soc-shark): eso es `must` y `must_not`.
3. `python3 scripts/fetch_corpus.py` la baja y te da el `sha256` que copiar.
4. `SOCSHARK_BLESS=1 cargo test -p socshark-cli --test corpus` genera el
   golden. **Revísalo**: cada flujo alertado es un verdadero o un falso
   positivo; si es falso, añade la regla a `must_not` y arregla la regla,
   no el manifiesto.

## Criterio de la 0.8

El corpus real no produce falsos positivos de severidad High y cada regla
del mini-IDS tiene al menos un verdadero positivo **real** (no sintético).
La tabla que imprime el test (`VP reales` / `VP sintéticos` /
`FP prohibidos` por regla) y la lista de fallos conocidos muestran qué falta.

**Estado (noviembre de 2026).** 23 capturas reales (≈ 13,4 MB) con la verdad
de campo escrita *antes* de pasarlas por soc-shark:

- 14 del wiki de Wireshark (tráfico legítimo, Telnet, shells remotas y dos
  sesiones de bases de datos del propio equipo);
- 3 de Chris Sanders: un escaneo SYN real de nmap (1000 puertos contra un
  equipo) y DNS legítimo sobre TCP (consulta de 35 KB y transferencia de
  zona), verificadas con un lector propio antes de usarlas;
- 6 de Active Countermeasures: túnel DNS con dnscat2 y cinco C2 con el ritmo
  del beacon documentado (EvilOSX 30 s, Octopus 5 s, Backoff 30 s ± 10 %,
  Asprox 30 s ± 20 %, AsyncRAT 6,5 s ± 1,5 s). Según la fuente, sin malware
  real.

| Regla | VP reales | FP reales |
|---|---|---|
| `BEACONING` | 5 (los cinco C2) | 0 |
| `INSECURE-PORT` | 3 | 0 |
| `DNS-TUNNELING` | 1 (dnscat2) | 0 |
| `PORT-SCAN` | 1 (nmap) | 0 |
| `NON-DNS-ON-53` | 1 (shell en TCP/53) | 0 |
| `NON-HTTP-ON-80` | 1 (shell en TCP/80) | 0 |

**Lo que encontró y se corrigió** (todo con test de regresión):

- falso positivo alto de `DNS-TUNNELING` con el localizador de Active
  Directory (`dns.cap`);
- falso positivo alto de `FILE-MASQUERADING` con HTML comprimido (`http.cap`);
- el parser DNS descartaba las búsquedas inversas IPv6 (34 etiquetas, el
  límite era 32), y con `NON-DNS-ON-53` eso daba un falso positivo alto
  («no es DNS») en cualquier red con IPv6 (dnscat2);
- `BEACONING` medio sobre la Optimización de distribución de Windows
  (TCP/7680 entre equipos de la red, cada ~40 s): ahora es ruido de fondo
  solo si los dos extremos son de la red local;
- `EXPOSED-DB` medio con bases de datos usadas desde el propio equipo
  (MySQL de 192.168.0.254 consigo mismo, PostgreSQL por loopback): no están
  expuestas a la red. Se habían registrado como verdaderos positivos; el
  lector propio mostró que eran locales y la verdad de campo se corrigió
  antes de pasarlas por soc-shark.

**Fallos conocidos**: ninguno. La shell en TCP/80 de `dns-remoteshell.pcap`
la caza `NON-HTTP-ON-80`.

**Sin verdadero positivo real todavía**: `FILE-MASQUERADING` (hay
candidata, pero con malware vivo), `NETWORK-SWEEP`, `REPEATED-ATTEMPTS` y
`EXPOSED-DB` (las dos sesiones del wiki resultaron ser locales); no se
encontraron capturas públicas pequeñas de las tres últimas. Las de threat intel necesitan además
las listas.
