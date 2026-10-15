# plugins-sdk — Dissectors externos en WebAssembly (fase 5)

Estado: **diseño**. El problema histórico de Wireshark son sus dissectors en
C: un paquete malicioso puede explotarlos con privilegios del analizador.
soc-shark moverá los dissectors de terceros a un **sandbox Wasm**.

## Contrato (WIT, borrador)

```wit
package socshark:plugin@1.0.0;

interface dissector {
    /// ¿Reclama este payload? (puerto candidato + contenido)
    record claim {
        ports: list<u16>,           // puertos típicos (orientativo)
        protocol-name: string,
    }

    /// Resultado de la disección; el host presta los bytes (zero-copy Wasm).
    variant l7-event {
        summary(string),                       // resumen humano
        field(tuple<string, string>),          // campo DSL extra
        alert(tuple<string, u8, string>),      // (id, severidad 0-3, detalle)
    }

    dissect: func(payload: borrow<stream<u8>>, ctx: flow-context) -> stream<l7-event>;
}
```

## Reglas del sandbox

- El host (**wasmtime**) ejecuta cada plugin con:
  - **memoria lineal acotada** (p. ej. 32 MiB) y **fuel limitado**
    (disección acotada en tiempo de cómputo),
  - **sin filesystem, sin red, sin reloj** — solo los bytes prestados y el
    contexto declarado,
  - un hilo propio: un plugin colgado no congela el motor.
- El plugin **no puede** marcar riesgo alto directamente: sus `alert` pasan
  por las mismas reglas/risk-score que el resto del motor.
- Distribución: `.wasm` firmados por el operador (ed25519), cargados desde
  un directorio local auditado; nada de auto-actualización.

## Plantilla (fase 5)

```
plugins-sdk/examples/custom_protocol/
├── Cargo.toml            # crate cdylib, wasm32-unknown-unknown
├── src/lib.rs            # implementación del contrato WIT
└── README.md             # cómo compilar (cargo build --target wasm32) y registrar
```

`src/lib.rs` mostrará un parser de un protocolo C2 ficticio ("ACME-C2")
que emite `field` + `alert` — el ejemplo de integración que probará el
criterio de aceptación de la fase 5: *un disector externo no puede corromper
el motor ni elevar privilegios*.

## Integración con el motor

- `dissectors::wasm_host` (fase 5) implementa el mismo patrón que los
  dissectors nativos: `parse(payload) -> Option<AppInfo::Wasm(...)>`, con
  los eventos traducidos a digests flat de `EnrichedFlow`.
- Los plugins se registran por `claim.ports` y se prueban **después** de la
  detección nativa (los nativos tienen prioridad).
