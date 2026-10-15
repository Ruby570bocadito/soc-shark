# custom_protocol — plantilla de disector Wasm (fase 5)

Ejemplo de referencia para el SDK de plugins. En la fase 5 este crate se
compila a `wasm32-unknown-unknown` y se carga con `wasmtime` en el
`wasm_host` del motor (`docs/adr` + `plugins-sdk/README.md`).

## Protocolo ficticio "ACME-C2"

Header de 8 bytes:

```text
0..2  magic        0xAC 0x1E
2     version      u8 (1)
3     msg_type     u8 (0x01 beacon, 0x02 task, 0x03 result)
4..8  length       u32 BE del payload que sigue
```

## Esqueleto que implementará (Rust → Wasm)

```rust
#![no_std]
use socshark_plugin_abi::{prelude::*, L7Event, FlowContext};

#[export_name = "dissect"]
pub extern "C" fn dissect(payload: &[u8], ctx: &FlowContext) -> EventStream {
    let mut out = EventStream::new();
    if payload.len() < 8 || payload[0] != 0xAC || payload[1] != 0x1E {
        return out; // no es nuestro protocolo
    }
    let msg_type = payload[3];
    match msg_type {
        0x01 => out.push(L7Event::field("acme.msg", "beacon")),
        0x02 => out.push(L7Event::field("acme.msg", "task")),
        0x03 => out.push(L7Event::field("acme.msg", "result")),
        _ => out.push(L7Event::summary("ACME-C2 desconocido")),
    }
    out.push(L7Event::summary(&format!("ACME-C2 v{} ({})", payload[2], ctx.flow_key())));
    out
}
```

## Checklist de la fase 5 (criterio de aceptación)

- [ ] Compila a Wasm con `--target wasm32-unknown-unknown` (no_std, sin deps).
- [ ] El host impone límites: 32 MiB de memoria y fuel máximo por paquete.
- [ ] Un payload malicioso diseñado para colgar el plugin solo agota su fuel:
      el motor sigue funcionando y registra el plugin como "degradado".
- [ ] Sus `field` aparecen en el DSL (`acme.msg == beacon`) y sus `alert`
      pasan por el risk-score estándar.
