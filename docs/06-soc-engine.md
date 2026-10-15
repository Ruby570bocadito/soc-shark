# 06 · Motor SOC (Blue Team)

`crates/soc-engine` — detección pasiva integrada en el pipeline. Todos los
detectores son **heurísticas puras y documentadas** (sin ML, sin red): el
analista puede entender cada alerta leyendo este documento.

## Ciclo de trabajo

```text
observe_packet(dp):            # por cada paquete, O(1)
    passive_dns.observe(dp)    # pares IP→dominio de respuestas A/AAAA/CNAME
    registrar evento DNS       # qname, qtype, entropía, etiqueta máx.
    file_carver.observe(dp)    # carving HTTP + magic bytes

enrich(table, threat_intel):   # al agotar la captura
    beacon_detect::detect      # agrupa flujos por destino y mide CV temporal
    anomaly_detector::dns_tunneling
    por flujo:
        passive DNS → dominio (o alerta de conexión directa)
        port mismatch, TLS sin SNI
        IOCs offline (IP/CIDR)
        artefactos → alertas EXE-TRANSFER / MASQUERADE
        risk_score = Σ pesos (cap 100)
        human_summary
```

## Detectores y umbrales

### 1. C2 Beaconing — `beacon_detect.rs` · id `C2-BEACON` · T1071

- Eventos: **paquetes con datos del cliente** (c2s) agrupados por
  `(src, dst, dport, proto)` — las respuestas del servidor ensuciarían la
  métrica.
- Condiciones: ≥ 4 eventos, intervalo medio entre 1 s y 600 s, y
  **CV = σ/μ ≤ 0.35**.
- Severidad: CRITICAL si el intervalo medio < 60 s; HIGH en caso contrario.
- Evidencia: primeros 8 intervalos (`intervalos_s=10.0,10.0,...`).

Demo: `POST /gate.php` cada 10.0 s → `CV 0.00, n=6`.

### 2. Live File Carving + Masquerading — `file_carver.rs` · T1105 / T1036

- Fase 1: cuerpos HTTP completos en un paquete (chunked soportado vía
  `dechunk`); ≥ 64 bytes para evitar favicon noise.
- Calcula **SHA-256** (implementación propia, vectores FIPS en tests) y
  **magic bytes** (MZ, ELF, PDF, PNG, JPEG, ZIP, GZIP, WASM, RAR, 7Z).
- `MASQUERADE` (T1036): la extensión del nombre espera un magic distinto —
  `factura.pdf` que empieza por `MZ`.
- `EXE-TRANSFER` (T1105): magic `MZ`/`ELF` transferido.
- Nombres inferidos de la URI de la petición previa del mismo flujo.

### 3. Port Mismatch — `anomaly_detector.rs` · T1071

Protocolo L7 identificado por el disector ≠ puerto estándar:

| L7 | Puertos considerados estándar | Severidad |
|----|-------------------------------|-----------|
| HTTP | 80, 8080, 8000, 8888, 8081 | HIGH |
| TLS | 443, 8443, 993, 995, 465, 636 | MEDIUM |
| DNS | 53 | MEDIUM |

Se respeta el ruido de fondo (mDNS en 5353 no es anomalía). Patrón típico:
HTTP en 4444/8081 (C2).

### 4. DNS Tunneling — `anomaly_detector.rs` · T1071.004

Por `(src, dominio base)`: ≥ 3 consultas con **etiqueta ≥ 30 chars** o
**entropía de Shannon del qname ≥ 3.8 bits/byte** o **qtype TXT/NULL/ANY**.
Evidencia = dominio base, y la alerta se adjunta **solo a los flujos DNS
cuyas consultas caen bajo ese dominio** (nada de ruido cruzado).

### 5. Conexión directa por IP — `anomaly_detector.rs` · T1095

Flujo hacia IP **global** (no RFC1918/multicast/loopback) sin ninguna
resolución en el passive DNS en el instante del primer paquete, y sin
Host/SNI. Típico de malware con C2 hardcodeado. MEDIUM.

### 6. TLS sin SNI — `rules_eval.rs` · T1071

ClientHello hacia IP externa sin Server Name Indication: escaneos,
malware o bibliotecas no estándar. LOW (apilable con otras).

### 7. Threat Intel offline — `threat_intel.rs` · `IOC-MATCH`

Lista local (`--iocs`): una entrada por línea, `#` comentarios, IP, CIDR
v4/v6 o dominio (dominios correlacionan con passive DNS en fase 3).

```text
185.220.101.0/24      # Tor exit nodes
185.22.1.9            # C2 demo
2001:db8:bad::/48
```

Coincidencia → **CRITICAL**. Cero consultas externas: las evidencias nunca
salen de la máquina.

## Risk score

`risk = min(100, Σ peso(severity))` con pesos `LOW=5, MEDIUM=15, HIGH=30,
CRITICAL=45`. La paleta semántica: ≥ 60 rojo, ≥ 30 ámbar, > 0 amarillo
tenue, ruido gris.

## Mapeo MITRE ATT&CK (indicativo)

| Alerta | Técnica | Nota |
|--------|---------|------|
| C2-BEACON | T1071 (Application Layer Protocol) | el canal concreto refina en fase 3 con proc.* |
| PORT-MISMATCH | T1071 | |
| DNS-TUNNEL | T1071.004 (DNS) | |
| DIRECT-IP | T1095 (Non-Application Layer Protocol) | |
| EXE-TRANSFER | T1105 (Ingress Tool Transfer) | |
| MASQUERADE | T1036 (Masquerading) | |
| TLS-NO-SNI | T1071 | |

## Roadmap de detección (fases 3-5)

- **Reglas Sigma/Suricata simplificadas** evaluadas sobre el mismo DSL del
  flujo (`rules_eval` ya centraliza la composición).
- **JA4+ y HASSH** con las métricas del ClientHello y de la KEXINIT SSH.
- **Jitter profundo**: distribución de intervalos (no solo CV) y
  detección de sleep-dithering.
- **GeoIP/ASN MMDB offline** + feeds Feodo/Tor/AbuseIPDB con actualización
  programada; lookup VirusTotal **bajo demanda explícita** del analista.
