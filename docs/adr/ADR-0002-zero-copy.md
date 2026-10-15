# ADR-0002: Zero-copy por slicing, no por ownership

- Estado: **aceptado** (fase 1)
- Contexto: los analizadores clásicos copian bytes entre etapas (memcpy por
  paquete) o usan punteros crudos inseguros. Rust ofrece una tercera vía.
- Decisión: el archivo de captura se materializa una vez (`Vec<u8>` en fase
  1, `mmap` en fase 2) y **todo** el pipeline trabaja con referencias
  (`PacketRecord<'a>`, `DissectedPacket<'a>`, payloads `&[u8]`). Las copias
  están restringidas a: strings cortos (nombres, URIs), escalares y el
  carving (explícito y documentado).
- Consecuencias:
  - (+) Memoria O(captura), sin memcpy por paquete; lifetimes del compilador
    garantizan que ninguna vista sobrevive al buffer.
  - (+) El paso a mmap no cambia APIs (mismo `&[u8]`).
  - (−) Los lifetimes obligan a que las etapas asíncronas de la fase 2
    clonen solo lo que cruza hilos (o usen offsets — ya diseñado en
    `storage-index`).
