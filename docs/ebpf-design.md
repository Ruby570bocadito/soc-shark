# Diseño del módulo eBPF (Fase 3)

La característica que ningún analizador clásico tiene: **saber qué proceso,
binario y usuario originó cada conexión**, directamente en la tabla de
flujos, sin instrumentar la aplicación. Este documento es el diseño completo
de la Fase 3: qué probes, cómo se correlaciona, y con qué límites. Estado
actual: **no implementado**; el modelo de datos ya reserva los campos
(`process_name`, `pid`, `user`) para que la integración sea rellenar datos.

## Objetivo

Dado un `EnrichedFlow`, responder al instante: *¿qué binario de qué usuario
abrió este socket, y qué ha estado haciendo desde entonces?* Esto convierte
`udp/8.8.8.8:53-192.168.1.30:53002` en:

```json
{"flow_id":"udp/8.8.8.8:53-192.168.1.30:53002",
 "process_name":"/tmp/.hidden/beacon", "pid":24312, "user":"svc_backup",
 "risk_score":45, "alerts":[{"id":"DNS-TUNNELING", ...}]}
```

La diferencia entre "alguien en 192.168.1.30 habla raro" y "el binario
`/tmp/.hidden/beacon` del usuario `svc_backup` habla raro" es la diferencia
entre un ticket y una contención de incidente.

## Probes previstos

### 1. `kprobe/tcp_v4_connect` — atribución en el origen

Se dispara en cada `connect()` IPv4. En el contexto del probe están
disponibles el `struct sock` (con IP/puerto origen y destino **antes** de que
el kernel asigne el puerto efímero definitivo), el `current` task (PID, Tgid,
comm, credenciales). Capturamos el evento de *intención de conexión*.

### 2. `tracepoint/inet_sock_set_state` — ciclo de vida exacto

Se dispara en cada cambio de estado del socket TCP (y cubre el hueco del
puerto efímero: el tracepoint incluye la 5-tupla ya definitiva). Sirve para
confirmar la atribución (match exacto de 5-tupla + cookie del socket) y para
saber cuándo un socket muere (limpieza del mapa de correlación).

### 3. `kprobe/udp_sendmsg` — UDP

`connect()` es opcional para UDP (datagramas no conectados). El probe en
`udp_sendmsg`/`__udp4_lib_send_skb` atribuye el envío por socket. Para DNS
que usa sockets conectados no hace falta; para flows UDP anónimos sí.

### 4. `uprobe/SSL_read` + `SSL_write` — TLS transparente (Fase 3+)

Con `SSLKEYLOGFILE` los navegadores ya permiten descifrar, pero los binarios
que no respetan la variable (la mayoría del malware y bastantes herramientas
corporativas) no. El uprobe engancha las funciones de la librería TLS
(OpenSSL/BoringSSL) en el proceso objetivo y captura el plaintext de entrada
y salida **antes de cifrarse**, sin tocar el código de la aplicación.

Límites y ética: opt-in explícito por PID, banner legal, no persistencia por
defecto y auditoría de cada activación (detallado en
[security.md](security.md)). Esta función es la más potente del proyecto y
la que exige el marco de uso más claro.

## Correlación de eventos con flujos

El problema central: los eventos eBPF llegan por socket, los flujos existen
por 5-tupla; hay que unirlos con coste O(1) por paquete y sin fugas de
memoria.

```text
kernel space                          user space (daemon)
┌──────────────────────────┐          ┌─────────────────────────────┐
│ eBPF:                    │ ring buf │ daemon eBPF:                │
│  connect() ─►            │─────────►│  tupla+cookie ─► pid,exe,uid│
│    map: cookie → {pid,   │  (LRU)   │  en un HashMap hashbrown    │
│          comm, exe, uid, │          │  con TTL por estado socket  │
│          ts}  (LRU cap)  │          │                             │
│  set_state(ESTABLISHED)─►│          │ el Enricher busca la 5-tupla│
│    evento con 5-tupla    │          │ de cada flujo nuevo y copia │
└──────────────────────────┘          │ la atribución a los campos  │
                                      └─────────────────────────────┘
```

Decisiones clave:

- **Clave por cookie de socket** (`bpf_get_socket_cookie`): estable aunque
  la tupla cambie (NAT del propio host) y único por socket, evita colisiones
  de puertos reutilizados.
- **Mapas LRU con capacidad fija** (`BPF_MAP_TYPE_LRU_HASH`): un host ruidoso
  no puede agotar la memoria del kernel; los mapas reciclan entradas viejas
  por sí mismos.
- **TTL en userspace**: si el evento de cierre no llega (probe perdido), la
  entrada del HashMap userspace caduca junto con el flujo del agregador.
- **Sin PIE del ring**: si el daemon se retrasa, eBPF descarta eventos
  antiguos en lugar de bloquear el kernel; el flujo queda sin atribución
  (degradación elegante, no parada).

## Stack técnico: aya

Se usará **aya** (Rust puro, no BCC): el probe se compila a objeto eBPF en
el build del workspace y se carga con libbpf/aya sin clang ni BCC en el host
del analista. Ventajas para este proyecto concreto: mismo lenguaje y
toolchain que el resto del workspace, tipos compartidos entre probe y
userspace (un solo `struct ConnectEvent` en un crate `socshark-ebpf-common`),
y el verifier del kernel como red de seguridad adicional.

Requisitos operativos: Linux ≥ 5.15 recomendado (ring buffer v2, CO-RE
maduro), CAP_BPF+CAP_PERFMON (o root en kernels antiguos), BTF presente
(`/sys/kernel/btf/vmlinux`) para CO-RE.

## Formato del evento

```rust
/// Evento compartido entre probe y userspace (crate socshark-ebpf-common).
#[repr(C)]
pub struct ConnectEvent {
    pub cookie: u64,
    pub saddr: [u8; 4],   // o [u8; 16] para v6 en el evento v2
    pub daddr: [u8; 4],
    pub sport: u16,
    pub dport: u16,
    pub pid_tgid: u32,
    pub uid: u32,
    pub ts_ns: u64,
    pub comm: [u8; 16],   // task->comm (truncado por el kernel)
}
```

El daemon resuelve `comm → ruta completa del binario` leyendo
`/proc/<pid>/exe` **en el momento del evento** (antes de que el proceso
muera y el path se pierda), y cachea con el PID como clave.

## Casos límite documentados

- **Procesos de vida corta**: malware que ejecuta `connect()` y muere. La
  lectura inmediata de `/proc/<pid>/exe` en el evento mitiga el caso.
- **Fork/threads**: se atribuye al Tgid (proceso) y se guarda también el
  Tid; el `comm` del hilo suele ser más revelador en binarios multihilo.
- **Contenedores**: el PID es del namespace del host (el probe ve el kernel
  compartido); en Fase 4 se añadirá resolución de namespace para mostrar
  `container/k8s-pod` vía cgroup id (`bpf_get_current_cgroup_id`).
- **NAT saliente del host**: la cookie resuelve la correlación aunque la
  tupla observada en el cable difiera de la del socket.
- **Kernels sin BTF**: se degradará a probes sin CO-RE compilados para el
  kernel exacto (opción avanzada), o se desactiva el módulo con un aviso
  claro: el resto del producto funciona igual.
