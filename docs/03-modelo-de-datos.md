# 03 · Modelo de datos

Los tres tipos que definen el contrato motor ↔ UI.

## `PacketRecord<'a>` — el paquete crudo

```rust
pub struct PacketRecord<'a> {
    pub index: u64,      // número secuencial en la captura
    pub ts_us: u64,      // timestamp epoch en microsegundos (normalizado)
    pub orig_len: u32,   // longitud original en el cable (snaplen puede cortar)
    pub data: &'a [u8],  // bytes capturados: VISTA sobre el buffer, cero copias
}
```

## `DissectedPacket<'a>` — el paquete diseccionado

Producido por `dissectors::view::dissect`. Contiene capas opcionales
(`NetInfo`, `TransInfo`, `AppInfo`), la **5-tupla** canónica, el protocolo
L7 detectado (`"DNS"`, `"HTTP"`, `"TLS"`, `"QUIC"`, `"TCP"`...) y el payload
de aplicación prestado. Los `AppInfo` exponen helpers tipados:
`as_dns()`, `as_http_request()`, `as_http_response()`, `as_tls()`.

## `EnrichedFlow` — la fila legible (Flow-First)

Definido en `flow-aggregator/src/model.rs`; es la estructura que envía el
backend a cualquier interfaz. Campos clave (resumen; el código es la
referencia):

```rust
pub struct EnrichedFlow {
    pub flow_id: u64,
    pub key: FlowKey,                     // 5-tupla direccional (cliente→servidor)
    pub state: FlowState,                 // Active | Closed | Reset | Timeout
    pub first_seen_us: u64,
    pub duration_ms: u64,

    // 1. Identidad enriquecida
    pub process_name: Option<String>,     // eBPF fase 3: "powershell.exe"
    pub process_pid: Option<u32>,         // eBPF fase 3
    pub resolved_domain: Option<String>,  // passive DNS / Host / SNI
    pub domain_source: DomainSource,      // passive_dns | http_host | tls_sni | none
    pub dst_geo_asn: Option<String>,      // MMDB fase 3

    // 2. Clasificación y legibilidad
    pub l7_protocol: &'static str,
    pub is_background_noise: bool,        // ARP/mDNS/SSDP/NTP... → atenuar
    pub human_summary: String,            // "POST /gate.php (Host: c2.evil-domain.ru)"

    // 3. Contexto SOC
    pub risk_score: u8,                   // 0-100, color de la fila
    pub alerts: Vec<SocAlert>,            // severidad + MITRE + evidencia
    pub extracted_files: Vec<Artifact>,   // carving con SHA-256 y magic bytes
    pub ja4_fingerprint: Option<String>,  // huella JA4-like del ClientHello

    // 4. Estadísticas y punteros
    pub packets_c2s: u64, pub packets_s2c: u64,
    pub bytes_c2s: u64,   pub bytes_s2c: u64,
    pub packet_count: usize,
    pub packet_offsets: Vec<u64>,         // lectura instantánea vía mmap (fase 2)
    pub packet_ts: Vec<u64>,              // base del detector de beaconing
    pub packet_data: Vec<u8>,             // 0 nada · 1 datos c2s · 2 datos s2c
}
```

### `SocAlert` y `Artifact` (en `common::soc_types`)

```rust
pub struct SocAlert {
    pub id: &'static str,          // "C2-BEACON", "MASQUERADE", "IOC-MATCH"...
    pub severity: Severity,        // Low < Medium < High < Critical
    pub title: String,             // "Beaconing hacia 185.22.1.9:4444 (CV 0.00, n=6)"
    pub detail: String,            // explicación para el analista
    pub mitre: Option<&'static str>, // "T1071", "T1036", "T1105"...
    pub evidence: Option<String>,  // hash, dominio base, intervalos...
}

pub struct Artifact {
    pub name: String,              // "update.exe" (inferido de la URI)
    pub size: u64,
    pub sha256: String,            // completo, 64 hex
    pub magic: &'static str,       // "MZ", "ELF", "PDF"...
    pub masquerade: bool,          // extensión ≠ magic → T1036
    pub source: &'static str,      // "HTTP" (SMB/FTP en fases siguientes)
}
```

## JSON del informe (`soc-shark read --json`)

```json
{
  "tool": "soc-shark",
  "capture": { "packets": 54, "bytes": 5915, "link": "Ethernet",
               "first_ts": "2025-06-10T08:14:00.000000Z" },
  "summary": { "flows": 15, "alerts": 11, "artifacts": 2, "beacon_flows": 1 },
  "protocols": { "DNS": 8, "HTTP": 3, "UDP": 4 },
  "flows": [
    {
      "flow_id": 10,
      "state": "active",
      "first_seen": "2025-06-10T08:15:00.500000Z",
      "src": { "ip": "192.168.1.50", "port": 49820, "process": null },
      "dst": { "ip": "185.22.1.9", "port": 4444,
               "domain": "c2.evil-domain.ru", "geo_asn": null },
      "domain_source": "passive_dns",
      "l7_protocol": "HTTP",
      "is_background_noise": false,
      "human_summary": "POST /gate.php (Host: c2.evil-domain.ru)",
      "risk_score": 100,
      "alerts": [ { "id": "C2-BEACON", "severity": "CRITICAL",
                    "mitre": "T1071", "evidence": "intervalos_s=10.0,10.0,..." } ],
      "extracted_files": [],
      "ja4_fingerprint": null,
      "packets": 18, "bytes_c2s": 780, "bytes_s2c": 96,
      "http": { "method": "POST", "target": "/gate.php",
                "host": "c2.evil-domain.ru" }
    }
  ]
}
```

## Reglas de versión

- `EnrichedFlow` solo **añade campos** (la UI debe tolerar extras).
- Los campos `process_*`, `dst_geo_asn` y `geo.*` del DSL existen desde
  fase 1 y devuelven `null`/vacío hasta que eBPF/MMDB los llenen — así la
  UI y las reglas SOC se escriben ya con su forma final.
