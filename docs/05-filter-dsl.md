# 05 · Filter DSL

Motor de consultas estilo Wireshark implementado desde cero
(`crates/filter-dsl`): lexer → Pratt parser → VM de evaluación sobre una
abstracción de "hechos" (`FactSource`), lo que permite usar **la misma
expresión sobre paquetes y sobre flujos**.

## Gramática (EBNF informal)

```ebnf
expr        = or_expr ;
or_expr     = and_expr { ("or" | "||") and_expr } ;
and_expr    = unary { ("and" | "&&") unary } ;
unary       = [ "not" | "!" ] unary | cmp ;
cmp         = "(" expr ")"
            | field [ cmp_op value ] ;   (* sin cmp_op → campo booleano *)
cmp_op      = "==" | "!=" | ">=" | "<=" | ">" | "<" | "contains" ;
value       = number | string | ip_literal | "true" | "false" | palabra ;
field       = ident { "." ident } ;
```

Precedencias: `or` (1) < `and` (2) < `not` (3) < comparación (4).

## Semántica

- **Campo ausente** → la comparación es `false` (como Wireshark). `not`
  invierte el resultado de la comparación ya evaluada.
- **Campo a secas** (`flow.has_alert and not flow.noise`): verdadero si el
  campo existe y (si es booleano) vale `true`.
- **IPs literales**: `192.168.1.50` con exactamente 4 segmentos numéricos;
  cualquier secuencia numérica punteada inválida es un error de sintaxis
  (evita filtrar por IPs mal escritas sin querer).
- **`contains`**: case-sensitive sobre strings; `==` sobre strings es
  case-insensitive.
- **Comparaciones numéricas** con coerción int/float; strings comparan
  lexicográficamente con `< >`.

## Catálogo de campos (fase 1)

`soc-shark fields` imprime la lista canónica (`filter-dsl/src/registry.rs`).
Destacados:

| Campo | Nivel | Nota |
|-------|-------|------|
| `ip.src`, `ip.dst`, `ip.proto`, `ip.frag` | P/F | |
| `tcp.port`, `tcp.srcport`, `tcp.dstport`, `tcp.flags.{syn,ack,fin,rst,psh}` | P/F | |
| `udp.port` | P/F | |
| `dns.qname`, `dns.qtype`, `dns.is_response` | P/F | |
| `http.method`, `http.target`, `http.host`, `http.status`, `http.user_agent` | P/F | `user_agent` a nivel flujo llega con reensamblado (fase 4) |
| `tls.sni`, `tls.alpn`, `tls.ja4` | P/F | |
| `proto` / `flow.proto` | P/F | L7 detectado |
| `flow.risk`, `flow.noise`, `flow.domain`, `flow.state`, `flow.duration_ms`, `flow.packets`, `flow.bytes`, `flow.has_alert`, `alert.count`, `alert.max_severity` | F | |
| `artifact.magic`, `artifact.masquerade` | F | carving |
| `proc.name`, `proc.pid`, `geo.dst` | F | **vacíos en fase 1** (eBPF/MMDB fase 3) |

## Ejemplos

```text
# Triaje básico
flow.risk >= 30 and not flow.noise
flow.has_alert and not flow.noise
alert.max_severity == CRITICAL

# Beaconing y C2
flow.proto == HTTP and tcp.dstport == 4444
flow.domain contains evil
dns.qname contains tunnel and dns.qtype == 16

# Exfiltración / artefactos
artifact.masquerade
artifact.magic == MZ
flow.bytes > 1000000 and ip.src == 192.168.1.50

# Contexto de proceso (se activan solos en fase 3)
proc.name == powershell.exe
proc.name == curl and ip.dst != 10.0.0.0/8
geo.dst == RU and flow.has_alert

# A nivel de paquete (modo --events)
tcp.flags.syn == true and tcp.flags.ack == false
http.method == POST and tcp.dstport != 80
dns.qname contains update
ip.src == 192.168.1.50 and udp.port == 123
```

## Uso en el CLI

```bash
# A nivel de flujos (por defecto)
soc-shark read captura.pcap --filter 'flow.risk >= 60 and not flow.noise'

# A nivel de paquetes
soc-shark read captura.pcap --events --filter 'tcp.dstport == 4444 and http.method == POST'

# Errores amigables (posición y causa)
$ soc-shark read c.pcap --filter 'flow.risk >'
soc-shark: error: se esperaba un valor, encontrado None
```

## Implementación

- `lexer.rs`: tokens con strings con comillas simples/dobles y escapes,
  números int/float, palabras punteadas (campos e IPs); los operadores de
  2 bytes se reconocen antes que los de 1.
- `parser.rs`: Pratt con precedencias explícitas; campos a secas se
  resuelven mirando el token siguiente.
- `vm.rs`: `eval(&Expr, &dyn FactSource)` — el daemon implementa
  `PacketFacts` y `FlowFacts` (puente en `daemon/src/bridge.rs`), por lo que
  las UIs futuras pueden evaluar filtros del lado del motor sin duplicar
  gramáticas.
- `registry.rs`: catálogo con tipo, nivel (P/F) y descripción — la base del
  autocompletado de la fase 4.
