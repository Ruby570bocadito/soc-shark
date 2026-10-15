# Diseño de plugins WASM (Fase 4)

El ecosistema Wireshark demuestra el valor de dissectors de terceros y,
a la vez, su riesgo: un dissector escrito en C se enlaza al proceso y un bug
(o un plugin malicioso) es ejecución de código con los privilegios del
analizador. La respuesta de soc-shark: **dissectors como módulos
WebAssembly dentro de un sandbox**, con privilegios de módulo de kernel pero
seguridad de módulo de navegador. Estado: diseño completo, implementación en
Fase 4 sobre `wasmtime`.

## Por qué WASM y no C/Lua/Python

| Opción | Seguridad | Rendimiento | Distribución |
|---|---|---|---|
| C nativo (modelo Wireshark) | nula: el plugin es el proceso | máxima | recompilar por plataforma |
| Lua/Python embebidos | media: sandbox débil, GIL, supply-chain | baja | fácil |
| **WASM (wasmtime)** | **memoria aislada + sin syscalls + fuel limit** | ~native tras JIT (los parsers son bucles simples) | **un .wasm portable** |

Los parsers son exactamente el workload donde WASM rinde: bucles sobre bytes
sin syscalls. Y el riesgo se elimina por construcción: el módulo no puede
tocar memoria fuera de su linear memory ni llamar a nada que el host no
exporte.

## API del plugin (WIT)

La interfaz se define en WIT (WebAssembly Interface Types), lo que da ABI
estable y bindings automáticos para cualquier lenguaje con soporte
(Rust→wasm32-wasi, Go, TinyGo, C, AssemblyScript):

```wit
package socshark:plugin@1.0.0;

interface dissector {
  /// Metadatos del plugin, se registran al cargar.
  record plugin-info {
    name: string,
    /// Identificadores que reclama: puertos, ethertypes, magic bytes.
    interests: list<interest>,
  }

  variant interest {
    udp-port(u16),
    tcp-port(u16),
    ethertype(u16),
    /// Último recurso: inspectores generales (con coste de rendimiento).
    any,
  }

  /// Resultado de diseccionar un payload.
  record dissector-output {
    /// Protocolo detectado (aparece en l7_protocol).
    protocol: string,
    /// Campos estructurados que el host añade al flujo (p. ej. "http.host").
    fields: list<tuple<string, string>>,
    /// Línea para human_summary del analista.
    summary: string,
    /// Puntos de riesgo sugeridos 0-100 y alertas id+detalle.
    risk: u8,
    alerts: list<tuple<string, string>>,
  }

  /// El host entrega el payload como copia acotada (nunca el buffer original).
  dissect: func(ts-micros: u64, direction: direction, payload: list<u8>) -> option<dissector-output>;
}
```

## Funciones host exportadas al sandbox

El plugin solo ve lo que el host le da. La lista completa (nada más existe
en su mundo):

| Host function | Propósito | Límite |
|---|---|---|
| `read_payload(offset, len)` | Lee del payload que el host copió a la memoria del módulo | acotado al payload |
| `emit_field(k, v)` | Publica un campo del flujo | cuota por plugin (p. ej. 64 campos) |
| `emit_alert(id, detail, risk)` | Sugiere alerta; el motor SOC la valida y deduplica | cuota por paquete |
| `log(level, msg)` | Log con prefijo del plugin | cuota de líneas |
| `get_flow_meta()` | Lee campos ya existentes del flujo (IPs, puertos, dominio) | solo lectura |

**Lo que NO existe**: red, sistema de archivos, reloj, aleatoriedad, hilos,
`env`. Un plugin no puede exfiltrar porque no tiene cómo abrir un canal.

## Ejecución y límites

- **Fuel metering** (`wasmtime` `Store::set_fuel`): cada plugin tiene un
  presupuesto de instrucciones por paquete; un bucle infinito agota el fuel
  y el plugin se suspende con alerta, sin colgar el pipeline.
- **Memory cap**: linear memory limitada por plugin (p. ej. 16 MiB); una
  explosión de memoria mata al módulo, no al proceso.
- **Epímeros por paquete**: cada llamada `dissect` es stateless por diseño;
  el estado entre paquetes (p. ej. reensamblado de un protocolo) se modela
  con `record stream-state` gestionado por el host con TTL, nunca con
  globales del módulo.
- **Aislamiento por instancia**: cada plugin corre en su propio `Engine`
  ligero; la caída o corrupción de uno no afecta a otros ni al host.

## Distribución, firma y confianza

1. Los plugins se distribuyen como `.wasm` (o `.crowd` empaquetado con
   metadatos: nombre, versión, autores, intereses).
2. **Firma Ed25519** del autor verificada al cargar; el banner de la TUI
   muestra siempre qué plugins están activos y de quién son.
3. Política configurable: `deny-all` (por defecto en modo daemon privilegiado),
   `allow-signed`, `allow-all` (solo para laboratorio). En ningún modo un
   plugin obtiene más capacidades que las host functions anteriores: la
   firma confía en *quién*, no amplía *qué*.
4. El registro de plugins del proyecto (Fase 4+) revisará y firmará los que
   pasen un corpus de tests (`socshark-testgen` genera los casos).

## Ejemplo de flujo completo

```text
1. Arranque: socshark-engine carga http-flow.wasm (firmado por "community").
2. El plugin registra intereses: tcp-port(8080), tcp-port(8000).
3. Un paquete TCP 192.168.1.20:40111 → 93.184.216.34:8080 llega al pool.
4. El host copia el payload a la memoria del plugin y llama dissect().
5. El plugin parsea "GET /index.html HTTP/1.1\r\nHost: example.com" y emite:
   fields=[("http.method","GET"),("http.host","example.com")],
   summary="HTTP GET /index.html a example.com", risk=0.
6. El host añade los campos al EnrichedFlow y compone el human_summary.
```

## Fase de implementación

Fase 4 (ver [roadmap.md](roadmap.md)): primero el runtime con los plugins
oficiales HTTP/QUIC-initial, después la API pública WIT y el registro firmado.
El `DissectorPipeline` de Fase 1 ya define el punto de registro: los plugins
se enchufan como dissectors más detrás de la heurística de intereses.
