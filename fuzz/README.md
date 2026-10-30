# Fuzzing guiado por cobertura

Objetivos de [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
(libFuzzer). Este directorio **no** forma parte del workspace: necesita
nightly. El procedimiento completo está en
[CONTRIBUTING.md](../CONTRIBUTING.md#fuzzing).

```bash
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked --version 0.13.2

# Corpus inicial a partir de los escenarios de socshark-testgen (Rust estable)
cargo run --manifest-path fuzz/seeds/Cargo.toml -- fuzz/corpus

cargo +nightly fuzz list
cargo +nightly fuzz run dns -- -max_total_time=300
```

| Objetivo  | Qué ejercita |
|-----------|--------------|
| `dns`     | `parse_dns` |
| `ipv4`    | `parse_ipv4` (+ TCP/UDP del resto) |
| `ipv6`    | `parse_ipv6` (+ TCP/UDP del resto) |
| `tcp`     | `parse_tcp` |
| `udp`     | `parse_udp` (+ DNS del payload) |
| `tls`     | `parse_client_hello`, JA4 y `ClientHelloCapture` por segmentos |
| `dissect` | `DissectorPipeline::dissect` con Ethernet, IP crudo, SLL/SLL2 y loopback |
| `pcap`    | `PcapFileReader` (pcap y pcapng) desde memoria + disección |
| `carve`   | `carve_http` sobre un stream reensamblado sintético (`u16 LE` longitud cliente, cliente, servidor) |
| `filter`  | `lex` + `parse` del DSL y `eval` contra un flujo completo |

Un fallo deja la entrada en `fuzz/artifacts/<objetivo>/`; se reproduce con
`cargo +nightly fuzz run <objetivo> fuzz/artifacts/<objetivo>/<archivo>`.

En Windows (MSVC) el binario con AddressSanitizer necesita
`clang_rt.asan_dynamic-x86_64.dll` en el `PATH` (está en
`VC\Tools\MSVC\<versión>\bin\Hostx64\x64` de Visual Studio).
