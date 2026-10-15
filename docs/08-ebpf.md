# 08 · eBPF (fase 3): atribución de procesos y TLS plaintext

Estado: **diseño**. La fase 1 ya reserva los campos (`EnrichedFlow.process_*`,
campos DSL `proc.*`) y la etapa del pipeline donde se inyecta.

## Objetivo 1: atribución de procesos

Wireshark ve IPs; soc-shark mostrará `[PID: 4812 | binario: /usr/bin/python3
| usuario: www-data]` en el flujo.

### Programas kernel (C compilado con aya-bpf, CO-RE)

1. `sock_tracker.bpf.c`
   - `tracepoint/inet/inet_sock_set_state`: transiciones TCP → mapa
     `sock_ops` por 5-tupla con PID (`bpf_get_current_pid_tgid`).
   - `kprobe/tcp_v4_connect` + `kprobe/__inet_connect`: captura la intención
     de conexión (UDP incluido vía `udp_sendmsg`).
   - Mapa eBPF: `hash(5-tupla) → { pid, tgid, uid, comm }` con TTL corto.
2. Proceso user (Rust, `aya`):
   - Carga los programas (sin libbpf-sys), lee los mapas y los sirve al
     enricher por un canal MPMC.
   - Resolución rica: `/proc/<pid>/exe`, `/proc/<pid>/cmdline`, cgroup →
     **nombre de contenedor Docker/K8s** si existe.
   - Fallback sin eBPF (macOS/contenedores sin privilegios): correlación
     temporal `ss`/`lsof` — degradación elegante, campos vacíos.

### Inyección en el pipeline

```text
[mapas eBPF] ── canales ──▶ EbpfAttributor (etapa del enricher)
                                │
SessionTable.feed ──────────────┴──▶ EnrichedFlow.process_name/pid
```

Los flujos ya cerrados antes del arranque del daemon quedan sin proceso
(evidencia honesta: `null`, no inventado).

## Objetivo 2: TLS 1.3 transparente (sin SSLKEYLOGFILE)

### Uprobes

- `SSL_write`/`SSL_read` de **OpenSSL/BoringSSL** (offsets por versión vía
  `target_file` + symbol), `SSL_write_ex`, y equivalentes de **GnuTLS**
  (`gnutls_record_send`/`recv`).
- Go runtime: uprobes sobre `crypto/tls.(*Conn).Write` (requiere resolver
  argumentos con el ABI de Go — plan documentado, riesgo medio).
- Lectura del buffer de texto plano **antes de cifrar** y su asociación al
  FD → 5-tupla (`SSL_write(ssl, buf, num)` con el registro del socket).
- Claves TLS (para decrypt completo de capture files): uprobe a
  `SSL_new`/`SSL_set_fd` + `SSL_SESSION` → exporter del formato
  `SSLKEYLOGFILE` a petición (la lectura de plaintext por uprobe cubre la
  mayoría de casos SOC sin tocar claves).

### Ética y límites

- Requiere CAP_BPF + CAP_PERFMON en la máquina analizada; es vigilancia de
  la propia red del analista — se documenta en `docs/07-seguridad.md` y se
  marca el flujo con `plaintext_source: uprobe` para trazabilidad.

## Sketch del loader (aya)

```rust
let mut bpf = AyaBpf::load_file("/usr/lib/socshark/sock_tracker.bpf.o")?;
bpf.attach_tracepoint("inet", "inet_sock_set_state")?;
let mut events = EventRing::new(SpscRing::new(4096));
// mapa → canal → EbpfAttributor
```

## Requisitos y fallbacks

| Entorno | Atribución | TLS plaintext |
|---------|-----------|---------------|
| Linux ≥ 5.10 + CAP_BPF | eBPF completa | uprobes |
| Linux sin CAP_BPF | `/proc` + correlación temporal | — (SSLKEYLOGFILE manual) |
| macOS (fase cliente) | lsof correlación | SSLKEYLOGFILE manual |

## Pruebas de la fase 3

- Con `curl https://...` en un host de laboratorio, el flujo muestra
  `proc.name == curl` y el filtro `proc.name == curl` funciona en vivo.
- El ejemplo C2 del demo ejecutado por `python3` queda atribuido a python3.
- Los mapas no crecen sin límite (TTL + capacidad + estadísticas de drop).
