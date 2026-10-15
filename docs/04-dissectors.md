# 04 · Dissectors

## Principios

1. **Zero-copy**: cada parser toma `&[u8]` y devuelve estructuras que
   contienen rebanadas del buffer original. Solo se copian escalares y
   strings cortos (nombres DNS, URI HTTP). El carving es la única excepción
   y está documentado.
2. **Inviolabilidad ante paquetes hostiles**: ningún parser hace
   `unwrap()` de índices ni slicing sin comprobar. Firmas:
   `parse_x(data: &[u8]) -> Option<X<'_>>`. La suite incluye:
   - *truncado masivo*: cada trama de test se corta en TODAS las longitudes
     y no debe haber panic;
   - *entrada aleatoria*: 2.000 paquetes pseudoaleatorios (PRNG LCG
     determinista) a través de `dissect()` (`view.rs::tests`).
3. **Salida normalizada**: todo se ensambla en `DissectedPacket` con
   5-tupla y protocolo L7; el resto del motor no ve bytes crudos.
4. **Detección por puerto + sniffing**: el L7 se identifica probando
   contenido (métodos HTTP, byte 0x16 de TLS, prefijo DNS), no solo el
   puerto — así se encuentra HTTP en 4444 o DNS por 8080, que es la base
   del detector de port mismatch.

## Protocolos implementados (fase 1)

| Capa | Protocolo | Detalles |
|------|-----------|----------|
| L2 | Ethernet II | + VLAN 802.1Q y QinQ (hasta 2 etiquetas), ARP, Linux SLL |
| L3 | IPv4 | opciones, checksum, flags/fragmentación (los fragmentos no primeros se saltan) |
| L3 | IPv6 | extensión headers saltables (hop-by-hop, routing, fragment, dstopts); fragmentos no primeros marcados |
| L4 | TCP | flags, seq/ack, ventana; payload prestado |
| L4 | UDP | longitud declarada acotada al buffer |
| L4 | ICMP | tipos echo/dest-unreachable con resumen |
| L7 | DNS | preguntas + respuestas con **descompresión de nombres segura** (punteros solo hacia atrás, máx 64 saltos, máx 255 bytes), A/AAAA/CNAME/NS/PTR/MX/TXT; soporta TCP con prefijo de 2 bytes y mDNS |
| L7 | HTTP/1.1 | request/response, cabeceras (nombres normalizados), `content-length`, `transfer-encoding: chunked` con `dechunk()`, extensión de URI |
| L7 | TLS | capa de registros + ClientHello: SNI, ALPN, cipher suites, `supported_versions`, **fingerprint JA4-like** `t13d0201h2_<hash12>_<hash12>` |

QUIC: detección por nibble largo-header (`0xC0-0xCF`) sin disección (roadmap).

## Cómo añadir un disector nuevo

1. **Módulo** en `layerN/` con la firma estándar y tests de truncado:

```rust
pub struct MiProtocolo<'a> { pub campo: u16, pub payload: &'a [u8] }

pub fn parse_mi_protocolo(data: &[u8]) -> Option<MiProtocolo<'_>> {
    if data.len() < 4 { return None; }              // siempre comprobado
    let campo = u16::from_be_bytes([data[0], data[1]]);
    Some(MiProtocolo { campo, payload: &data[4..] }) // vista, sin copiar
}
```

2. **Detección** en `view.rs::detect_l7` (puerto candidato + prueba de
   contenido; el orden importa: DNS → QUIC → TLS → HTTP).

3. **Digest flat** en `session_table::feed` si aporta al resumen (como
   `http_method`, `tls_sni`...).

4. **Campos DSL**: añade el mapeo en `daemon/src/bridge.rs` y la entrada en
   `filter-dsl/src/registry.rs`.

5. **Resumen humano** en `human_summary.rs` y, si procede, detectores en
   `soc-engine` (p. ej. SMB: carving + auth anómala).

## Estándar de calidad (en CI)

```bash
cargo test -p socshark-dissectors   # truncado masivo + aleatorio + unitarios
cargo clippy -- -D warnings
```

Un disector sin tests de truncado no se acepta (ver `CONTRIBUTING.md`).
