# DSL de filtrado

El DSL permite seleccionar flujos con expresiones tipo tcpdump pero sobre
campos enriquecidos, no solo cabeceras. Está implementado como crate
independiente (`socshark-filter`) con lexer, parser por precedencia y
evaluador puro, testeado con su propia suite.

```bash
socshark capture -r captura.pcap -f "tcp.port == 443"
socshark capture -r captura.pcap -f "dns.qname contains evil || flow.risk >= 50"
socshark capture -r captura.pcap -f "!(flow.noise) && ip.dst == 8.8.8.8"
```

## Gramática (EBNF)

```ebnf
expr     = or ;
or       = and , { ("||" | "or") , and } ;
and      = not , { ("&&" | "and") , not } ;
not      = ("!" | "not") , not
         | "(" , or , ")"
         | cmp ;
cmp      = field , op , value        (* forma normal *)
         | field ;                   (* campo booleano: flow.noise *)
op       = "==" | "!=" | "<" | "<=" | ">" | ">=" | "contains" ;
value    = ip | number | boolean | string ;
ip       = octet , "." , octet , "." , octet , "." , octet ;
number   = digit , { digit } ;
string   = '"' , { char } , '"' | "'" , { char } , "'" ;
field    = ident , { "." , ident } ;
```

- Precedencias (de menor a mayor): `||` < `&&` < `!` prefijo < comparaciones.
  El parser es un *precedence climbing* simplificado (familiar de Pratt):
  ver `crates/socshark-filter/src/parser.rs`.
- Comentarios de línea con `#`.
- Palabras clave (`and`, `or`, `not`, `contains`) solo en minúsculas;
  `true`/`false` como booleanos.
- Las cadenas admiten escapes `\n`, `\t`, `\\`, `\'`, `\"`.
- Solo se acepta `campo op valor` (no `valor op campo`): es la convención de
  tcpdump/Wireshark y mantiene la inferencia de tipos trivial.

## Campos soportados (Fase 1 + 3)

| Campo | Tipo | Descripción |
|---|---|---|
| `ip.src`, `ip.dst` | IP | Extremos según primer paquete |
| `ip.addr` (`host`) | IP (multi) | Cualquiera de los dos extremos, como en Wireshark. Para excluir un equipo usa `!(ip.addr == X)`: `ip.addr != X` es cierto si *algún* extremo es distinto |
| `ip.version` | num | Familia del flujo: `4` o `6` (Fase 2) |
| `sport`, `dport` (`src.port`, `dst.port`) | num | Puertos individuales |
| `tcp.port`, `udp.port`, `port` | num (multi) | Ambos puertos; `tcp.port` solo aplica a flujos TCP y `udp.port` a UDP (igual que tcpdump) |
| `tcp.flags.syn/ack/fin/rst/psh` | bool | True si el flujo vio el flag (en cualquier dirección) |
| `dns.qname` | cadena (multi) | Todos los nombres consultados en el flujo |
| `dns.qtype` | cadena | Tipo del primer registro (`A`, `AAAA`, `TXT`, `CNAME`, `TYPE66`...) |
| `dns.rcode` | cadena | `NOERROR`, `NXDOMAIN`, ... (solo respuestas) |
| `dns.answer` | IP/cadena (multi) | Direcciones o targets de las respuestas |
| `net.l7` (`l7`, `proto`) | cadena | `DNS`, `TLS`, `HTTP`, `SSH`, `NTP`, `DHCP`, `?` |
| `net.transport` (`transport`) | cadena | `TCP`, `UDP`, `ICMP`, `OTRO` |
| `net.domain` (`domain`) | cadena | Dominio resuelto (DNS pasivo, y desde F3 también el SNI del ClientHello si no hubo DNS) |
| `tls.ja4` | cadena | Huella JA4 del ClientHello (Fase 3; vacío en flujos sin TLS) |
| `tls.sni` | cadena | Nombre de servidor declarado por el cliente (Fase 3) |
| `flow.packets`, `flow.bytes` | num | Totales de ambas direcciones |
| `flow.risk` (`flow.risk_score`) | num | Riesgo 0-100 |
| `flow.noise` | bool | Ruido de fondo |
| `flow.alerts` | num | Número de alertas |
| `flow.state` | cadena | `activo`, `inactivo`, `cerrado` |
| `flow.interval_mean_secs` | num | Intervalo medio entre paquetes del iniciador en segundos (Fase 3; vacío con < 3 paquetes) |
| `flow.interval_cv` | num | Coeficiente de variación de los intervalos: 0 = reloj perfecto (Fase 3) |
| `process.name`, `process.pid` | cadena/num | Atribución eBPF (siempre vacíos hasta Fase 3; ya cableados) |
| `file.count` | num | Archivos tallados en el flujo con `--carve-files` (Fase 4) |
| `file.name` | cadena (multi) | Nombres declarados de los archivos tallados (Fase 4) |
| `file.magic` | cadena (multi) | Firmas magic de los archivos tallados: `PE32`, `ELF`, `PDF`, ... (Fase 4) |
| `file.masquerading` | bool | True si algún archivo tallado tiene identidad falseada (T1036, Fase 4) |
| `intel.tag` | cadena (multi) | Etiquetas de threat intel offline del destino: `FEODO-C2`, `TOR-EXIT` (Fase 4) |

## Semántica de operadores

**Campos multi-valor.** `tcp.port` expone los dos puertos del flujo. Para
evitar sorpresas, las reglas son exactas y documentadas:

- `==` coincide si **alguno** de los valores cumple: `tcp.port == 443`
  selecciona el flujo si el origen o el destino es 443.
- `!=` es la **negación global**: coincide solo si **ninguno** cumple.
  `tcp.port != 80` excluye cualquier flujo que toque el 80. Esta elección
  replica la intuición de tcpdump y evita el falso positivo del `!=`
  ingenuo (que devolvería "verdadero" para un flujo 80↔443 solo porque el
  puerto origen no es 80).
- `>` `>=` `<` `<=` comparan numéricamente si ambos lados son numéricos
  (incluidas cadenas numéricas); IPs no se ordenan.
- `contains` es insensible a mayúsculas y funciona sobre cadenas (ideal para
  `dns.qname contains evil`) y sobre la representación textual de otros tipos.

**Campos desconocidos o no aplicables.** Un campo que no existe o no aplica
al flujo (p. ej. `dns.qname` en un flujo TCP) devuelve *sin coincidencia*
(`false`) en lugar de error. Esto permite compartir filtros entre
subconjuntos heterogéneos de flujos sin guardas defensivas.

**Coerciones tolerantes.** `ip.src == "10.0.0.5"` (cadena) funciona igual que
con literal IP; `flow.noise == 1` equivale a `true`. El objetivo es que los
filtros pegados desde SIEMs u otros textos sobrevivan a pequeñas variaciones
de tipo.

## Errores

El parser devuelve errores con **posición byte** para señalar el fallo en la
línea de comandos: `error de sintaxis en la posición 12: se esperaba un
valor, encontrado ')'`. Los errores comunes:

| Entrada | Error |
|---|---|
| `ip.src ==` | fin de la expresión inesperado |
| `(a == 1` | se esperaba ')' |
| `443 == tcp.port` | el lado izquierdo debe ser un campo |
| `443` | el valor 443 no es una expresión válida por sí sola |
| `a == 1 basura` | token inesperado tras el final de la expresión |

## Ejemplos prácticos para el SOC

```bash
# Solo exfiltración potencial y C2
-f "flow.risk >= 45"

# Reconocimiento: sondas que nunca establecieron conexión
# (sin respuesta, RST/ACK de puerto cerrado o half-open con RST)
-f "tcp.flags.syn && !tcp.flags.psh && !tcp.flags.fin && (!tcp.flags.ack || tcp.flags.rst)"

# Todo lo que hable con el DNS externo salvo consultas normales
-f "ip.dst == 8.8.8.8 && !(dns.qtype == \"A\")"

# Dominios raros (etiqueta larga de alta entropía)
-f "dns.qname contains .tun. || dns.qname contains .xyz"

# Sesiones cerradas limpiamente hacia SMB
-f "tcp.port == 445 && flow.state == cerrado"

# Negación compuesta: ni ruido ni DNS interno
-f "!(flow.noise) && !(net.l7 == \"DNS\")"
```

## Límites actuales y evolución

- Literales IPv6 nativos desde Fase 2 (`ip.dst == 2001:db8::1`, sin
  comillas); el lexer incluye `:` en las palabras. Las cadenas entre
  comillas siguen funcionando por coerción.
- Sin funciones (`len()`, `entropy()`): llegarán como predicados registrados
  cuando el mini-IDS los exponga.
- La TUI reutiliza este parser para su línea de filtro interactiva
  (generando los mismos errores con posición que la CLI).
