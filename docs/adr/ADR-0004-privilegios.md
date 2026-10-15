# ADR-0004: Separación de privilegios captura/disección

- Estado: **aceptado** (diseño; implementación en fase 2)
- Contexto: los analizadores suelen correr como root y procesan bytes
  hostiles en el mismo proceso: un bug del parser es privesc.
- Decisión: dos procesos con superficies distintas:
  - `soc-shark-daemon` (CAP_NET_RAW + CAP_BPF): abre la NIC, inyecta eBPF,
    escribe bytes crudos + timestamps a shm/mmap. **No interpreta
    protocolos**.
  - `soc-shark-engine` + UI (usuario sin privilegios): lee la shm y ejecuta
    disección, flow-first, SOC y exportación.
- Comunicación: gRPC sobre UNIX domain socket (mismo motor en GUI, TUI o
  SSH).
- Consecuencias:
  - (+) Un exploit de disector cuelga un hilo de usuario, no el root.
  - (+) El daemon es pequeño y auditable de forma independiente.
  - (−) Coste de IPC y de despliegue (setcap/systemd); en fase 1 la CLI
    mantiene el pipeline monoproceso como modo de análisis offline.
