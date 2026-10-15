# Contribuir a soc-shark

Gracias por tu interés. Reglas rápidas para que el motor siga siendo
confiable y auditable:

## Principios no negociables

1. **std-only en los crates del motor** (ver `docs/adr/ADR-0001-std-only.md`).
   Cualquier dependencia nueva requiere un ADR que justifique: superficie de
   auditoría, tamaño de build y alternativa propia.
2. **Cero panics con entrada de red.** Los parsers usan slicing comprobado
   (`get`, comparaciones de longitud) y devuelven `Option`/`Result`. Si
   añades un disector, incluye el test de truncado masivo (corta la trama
   en todas las longitudes y verifica que no hay panic) y el de entrada
   aleatoria.
3. **Zero-copy**: los dissectors devuelven vistas `&[u8]`; copiar payload
   solo está permitido en el carving (y documentado).
4. **Flow-First**: toda característica de UI consume `EnrichedFlow`; no se
   exponen paquetes sueltos sin contexto.
5. **Español en comentarios y docs** (coincide con la audiencia del
   proyecto); identificadores y términos técnicos en inglés.

## Flujo de trabajo

```bash
cargo fmt --all                    # formato antes de commit
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace             # verde obligatorio
python3 tools/gen_demo_pcap.py     # regenera el demo si tocas dissectors/SOC
./target/release/soc-shark read examples/demo_soc_incident.pcap --no-color
```

La CI (`.github/workflows/ci.yml`) ejecuta exactamente eso más el smoke
E2E que exige la detección de beaconing en el demo.

## Añadir un disector nuevo

1. Implementa `parse_x(data: &[u8]) -> Option<X<'_>>` con tests de
   truncado (ver `crates/dissectors/src/layer4/tcp.rs` como plantilla).
2. Engánchalo en `detect_l7` (`crates/dissectors/src/view.rs`) por puerto
   + sniffing de contenido.
3. Añade sus campos al `bridge.rs` del daemon y al `registry.rs` del DSL.
4. Añade resumen humano en `human_summary.rs` y, si procede, reglas en
   `soc-engine`.

## Commits

Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`) en
cualquier idioma, descripción clara en el cuerpo para cambios de motor.
