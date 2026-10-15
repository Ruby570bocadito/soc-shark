# 07 · Seguridad (diseño y modelo de amenazas)

La seguridad de la herramienta es un requisito de producto: el analista
apunta el motor a tráfico hostil **a propósito**.

## 1. Superficie de amenazas

| Amenaza | Vector | Mitigación en la base |
|---------|--------|----------------------|
| Explotación de un parser | paquete malformado que corrompe memoria (el caso clásico de Wireshark en C) | Rust seguro; **cero `unsafe` salvo el ring buffer SPSC** (aislado, con test multihilo); slicing comprobado; suite anti-panic (truncado masivo + entrada aleatoria) |
| DoS por recurso | capturas enormes, compresión de nombres DNS perversa, headers HTTP infinitos | límites explícitos en cada parser: máx 64 saltos/255 bytes en DNS, 128 cabeceras/64 KiB línea en HTTP, máx 8 extension headers, cadenas con guard |
| Cadena de suministro | dependencia comprometida | **std-only en fase 1** (ADR-0001): nada que auditar fuera del repo; cada dependencia futura necesita ADR |
| Compromiso del analizador completo | bug en la disección con privilegios de captura | **separación de privilegios** (§3): la disección nunca corre como root |
| Fuga de evidencias | el analizador "telefona a casa" (VT, GeoIP online) | offline-first por diseño; consultas externas solo bajo demanda explícita del analista |
| Plugins maliciosos | disector de terceros en C con bug/voluntario | Wasm sandbox desde el diseño (ADR + plugins-sdk); el host define el contrato WIT y limita memoria |

## 2. Reglas de código (en CI)

- Sin `panic!`/`unwrap`/`expect` en rutas de datos de red (los tests lo
  barren; `expect` solo en setup de tests).
- `unsafe` prohibido salvo `ring_buffer.rs` (documentado con invariantes y
  test de productor/consumidor en hilos).
- Errores como `Result`/`Option`; sin `abort`.

## 3. Separación de privilegios (diseño fase 2-3)

```text
┌───────────────────────────┐        ┌───────────────────────────────┐
│ soc-shark-daemon          │  gRPC  │ soc-shark-engine + UI         │
│ (CAP_NET_RAW, CAP_BPF)    │◄═══════│ (usuario sin privilegios)     │
│                           │ unix   │                               │
│ · abre NIC / AF_XDP       │ socket │ · disección completa          │
│ · inyecta programas eBPF  │        │ · flow-first, SOC, carving    │
│ · vuelca bytes crudos a   │        │ · filtros, UI, exportación    │
│   shm/mmap (sin interpretar)       │                               │
└───────────────────────────┘        └───────────────────────────────┘
```

- El daemon **no interpreta protocolos**: solo captura y escribe bytes a
  memoria compartida con timestamps. Su superficie de ataque es mínima y
  auditable (unos cientos de líneas).
- Si un paquete explota un bug lógico del parser de SMB/HTTP, el atacante
  cuelga un hilo de usuario sin privilegios — no el proceso root.
- La TUI/GUI se conectan al mismo socket; el modo por SSH funciona igual
  (socket UNIX remitido o gRPC sobre TCP local en laboratorio).

Preparación actual (`soc-shark live` imprime esta guía):

```bash
sudo setcap cap_net_raw,cap_bpf+eip target/release/soc-shark
sudo ip link set eth0 promisc on
```

## 4. Integridad de la evidencia

- Timestamps normalizados a **UTC en microsegundos** (pcap μs/ns y pcapng
  `if_tsresol` preservan la resolución original).
- Los artefactos carved llevan **SHA-256 completo**; el informe JSON es la
  pieza de evidencia exportable (y a su vez exportable a ECS JSONL).
- Nada se sobreescribe: la captura se lee; los offsets quedan indexados para
  relecturas bit-exactas.

## 5. Privacidad del analista

- GeoIP/ASN con base local (fase 3); IOCs con listas locales.
- VirusTotal u otros enriquecimientos externos: **opt-in por flujo**,
  jamás automáticos.
- Sin telemetría, sin update-check, sin IDs.
