# ADR-0006: Formatos de captura soportados y estrategia de normalización

- Estado: **aceptado** (fase 1)
- Contexto: el motor debe abrir cualquier evidencia que el SOC traiga:
  tcpdump (pcap), capture-service modernos (pcapng), capturas de loopback.
- Decisión: lectores propios zero-copy para:
  - **pcap** clásico: ambos endianness, resolución μs y ns (magics
    `0xa1b2c3d4`, `0xd4c3b2a1`, `0xa1b23c4d`, `0x4d3cb2a1`).
  - **pcapng**: SHB (detección de endianness por BOM), IDB (linktype +
    `if_tsresol` decimal/binario), EPB y SPB; bloques desconocidos (NRB,
    ISB, custom) se saltan de forma segura.
  - Linktypes: Ethernet (1), Null/loopback (0), Raw IP (12/101/228), Linux
    SLL (113). Otros se marcan `Unknown` y no se diseccionan (nada de
    heurísticas peligrosas).
- Normalización interna: **todo timestamp se convierte a μs epoch u64**
  (fase 1). La resolución ns se preservará truncando; si un caso real la
  exige, se migrará el campo a ns u64 (coste conocido y localizado).
- Consecuencias:
  - (+) Evidencias de cualquier origen con un único modelo interno.
  - (+) Escritura de pcapng queda para fase 2 (recorte de evidencias por
    flujo).
  - (−) Los linktypes exóticos (USB, NFLOG...) quedan fuera del MVP; el
    fallback es convertir con `tcpdump -r -w` o `editcap` antes del análisis.
