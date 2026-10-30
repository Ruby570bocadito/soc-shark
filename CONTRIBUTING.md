# Contribuir a soc-shark

Gracias por tu interés. Reglas rápidas para que el motor siga siendo
confiable, auditable y fácil de mantener. Para el contexto completo de cada
regla, ver [docs/decisions.md](docs/decisions.md) (ADRs) y
[docs/architecture.md](docs/architecture.md).

## Principios no negociables

1. **Cero panics con entrada de red** (ADR-006). Los parsers usan slicing
   comprobado (`get`, comparaciones de longitud, `try_into`) y devuelven
   `Option`/`Result`. Si añades o tocas un disector, incluye el test de
   truncado masivo (corta la trama en todas las longitudes y verifica que
   no hay panic) y el de entrada aleatoria.
2. **Flow-First** (ADR-002). Toda característica —UI, filtros, alertas,
   exportación— consume `EnrichedFlow`; los paquetes crudos nunca son
   producto de salida por defecto.
3. **Dependencias externas mínimas** (ADR-003). Las actuales (`serde`,
   `serde_json`, `thiserror`, `clap`, `anyhow` y, tras la feature `tui`,
   `ratatui` + `crossterm`) están congeladas; cualquier dependencia nueva
   exige un ADR que justifique superficie de auditoría, tamaño de build y
   alternativa propia.
4. **DAG estricto de crates.** `socshark-core` no depende de nadie;
   `socshark-testgen` solo de `std`; la CLI lo junta todo. No introduzcas
   ciclos ni dependencias transversales "por comodidad".
5. **Español en docs, comentarios y mensajes de la CLI; identificadores y
   términos técnicos en inglés** (ADR-007).
6. **Privilegio mínimo** (ADR-004). Ningún código nuevo puede requerir
   privilegios de captura salvo la captura en vivo (`socshark daemon` y el
   botón *En vivo* de la GUI), y solo en la frontera de captura
   (`socshark-capture`).

## Flujo de trabajo

```bash
cargo fmt --all                                   # formato antes de commit
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                            # verde obligatorio

# Regenera y verifica el escenario demo si tocas dissectors/flow/soc:
./target/release/socshark dev sample-pcap -o demo.pcap
./target/release/socshark capture -r demo.pcap
```

La CI (`.github/workflows/ci.yml`) ejecuta exactamente `fmt --check`,
`clippy -D warnings`, `test`, `build --release` y el fuzzing determinista
(Linux), `build` + `test` en Windows y macOS, `cargo check --locked` con la
MSRV (Rust 1.88, la que exige el `Cargo.lock`), y revisa los instaladores: `shellcheck install.sh` y que `install.ps1` se
analice sin errores y siga en **ASCII puro, sin BOM** (con BOM, `irm | iex`
deja de funcionar). Un PR no se revisa si la CI falla.

## Publicar una versión

1. Sube la versión en `[workspace.package]` de `Cargo.toml` y pasa lo de
   `## [Sin publicar]` del CHANGELOG a una sección `## [X.Y.Z] — fecha`.
2. Fusiona en `main` con la CI en verde.
3. En GitHub: **Actions → Release → Run workflow** (rama `main`).

El workflow (`.github/workflows/release.yml`) comprueba que la etiqueta
`vX.Y.Z` no exista y que el CHANGELOG tenga su sección, pasa los tests,
compila `socshark` para Windows x86_64, Linux x86_64 y ARM64 (con
`cargo zigbuild` contra glibc 2.17) y macOS universal, y publica el release
con los binarios, `SHA256SUMS` y las notas de esa sección. Los archivos
tienen nombre fijo (`socshark-<plataforma>.zip|tar.gz`): los instaladores
descargan siempre de `releases/latest/download/`, así que no renombres
ninguno sin cambiar también `install.sh` e `install.ps1`.

## Añadir un disector nuevo

1. Implementa el parser en `crates/socshark-dissectors/src/`
   (por ejemplo `ntp.rs`) con la firma `pub fn parse(data: &[u8]) ->
   Option<...>` y sus tests de truncado (tomar `dns.rs` como plantilla).
2. Engánchalo en la heurística L7 de `crates/socshark-dissectors/src/lib.rs`
   (puerto conocido + sniffing de contenido).
3. Si produce campos filtrables, añádelos al registro del DSL
   (`crates/socshark-filter/src/eval.rs`) y documenta la gramática nueva en
   [docs/filter-dsl.md](docs/filter-dsl.md).
4. Si es relevante para SOC, añade reglas o ruido de fondo en
   `crates/socshark-soc/` y mapea la detección a MITRE en
   [docs/soc-mitre-mapping.md](docs/soc-mitre-mapping.md).
5. Añade tramas de prueba a `socshark-testgen` (sin dependencias del
   workspace: los fixtures no deben heredar los bugs del código bajo prueba).

## Decisiones de arquitectura

Cambio que afecte al modelo de datos, al DSL, a los privilegios o a las
dependencias requiere un ADR nuevo en [docs/decisions.md](docs/decisions.md)
antes del código: contexto, decisión y consecuencias. Los ADRs aceptados no
se editan; se superseden.

## Commits

Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`) con la
descripción en español. Los cambios de motor incluyen en el cuerpo qué tests
cubren el cambio y por qué.

## Fuzzing

Cada build de CI ejecuta el fuzzer determinista en proceso: el corpus
derivado del escenario demo se muta (bits, truncados, empalmes, longitudes
mentirosas) y se pasa por el pipeline completo; cualquier panic rompe el
build y se reproduce con la semilla impresa:

```bash
cargo build --release
./target/release/socshark dev fuzz --seed 42 --iterations 50000
# Un fallo imprime:
# [!] FUZZ FALLÓ — reproducible con: socshark dev fuzz --seed <S> --iterations <N+1>
```

Reglas para el contribuidor:

- Un panic nuevo en parsers/agregador/SOC/DSL debe reproducirse con `dev
  fuzz` (añade o ajusta el caso si la mutación lo dispara solo a veces) y
  corregirse acotando el acceso, no capturando el panic.
- Antes de proponer un disector nuevo, corre una sesión larga local
  (`--iterations 500000`) con tu disector en el camino: es la puerta de
  entrada de tramas hostiles.

### Fuzzing guiado por cobertura (cargo-fuzz)

El fuzzer determinista muta a ciega; libFuzzer guía por cobertura. Los
objetivos viven en `fuzz/` (fuera del workspace, necesitan nightly): `dns`,
`ipv4`, `ipv6`, `tcp`, `udp`, `tls` (ClientHello + JA4 + captura por
segmentos), `dissect` (trama completa), `pcap` (pcap/pcapng desde memoria),
`carve` (carving HTTP sobre un stream reensamblado) y `filter` (parser y
evaluador del DSL). La tabla completa está en `fuzz/README.md`.

```bash
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked --version 0.13.2

# Corpus inicial desde los escenarios de socshark-testgen (Rust estable)
cargo run --manifest-path fuzz/seeds/Cargo.toml -- fuzz/corpus

cargo +nightly fuzz run dns -- -max_total_time=300
# Un fallo deja la entrada en fuzz/artifacts/dns/; se reproduce con:
cargo +nightly fuzz run dns fuzz/artifacts/dns/<archivo>
```

El workflow `.github/workflows/fuzz.yml` ejecuta cada objetivo 5 minutos
cada noche (y a demanda con `workflow_dispatch`), conserva el corpus
minimizado en la caché de Actions y sube como artefacto las entradas que
fallan. No es un gate de PR: el fuzzer determinista sigue siendo el gate
obligatorio. Al añadir un parser nuevo, añade su objetivo en
`fuzz/fuzz_targets/`, su `[[bin]]` en `fuzz/Cargo.toml`, sus semillas en
`fuzz/seeds/src/main.rs` y su nombre en la matriz del workflow.

En Windows (MSVC) el binario instrumentado necesita
`clang_rt.asan_dynamic-x86_64.dll` (de Visual Studio) en el `PATH`.
