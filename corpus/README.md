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

**Estado (noviembre de 2026).** 12 capturas del wiki de Wireshark (≈ 685 KB)
con la verdad de campo escrita *antes* de pasarlas por soc-shark:

- **2 falsos positivos High encontrados y corregidos**: `DNS-TUNNELING` con
  una consulta del localizador de Active Directory (`dns.cap`) y
  `FILE-MASQUERADING` con una página HTML comprimida con gzip (`http.cap`).
  Ver `docs/soc-features.md`.
- **Verdaderos positivos reales**: `INSECURE-PORT` en 3 capturas (dos
  sesiones Telnet y una shell en el 23) y `NON-DNS-ON-53` en 1 (la shell de
  `cmd.exe` en TCP/53 de `dns-remoteshell.pcap`, regla añadida a raíz de
  este corpus; ningún falso positivo en las otras 17 capturas).
- **Fallo conocido**: la shell en TCP/80 de esa misma captura no se detecta
  (no hay regla de «tráfico que no es HTTP en el puerto 80»).
- **Sin verdadero positivo real todavía**: escaneo, barrido, intentos
  repetidos, túnel DNS, beacon y T1036. Hacen falta capturas de ataques
  reales (Malware-Traffic-Analysis, CIC-IDS2017).
