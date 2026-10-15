//! Catálogo de campos del DSL (para autocompletado y `soc-shark fields`).
//!
//! Los campos `proc.*` y `geo.*` existen desde la fase 1 pero devuelven
//! vacío hasta que eBPF (fase 3) y MMDB (fase 3) los alimenten — así las
//! reglas SOC se escriben ya con la forma final.

/// Definición de un campo del DSL.
#[derive(Debug, Clone, Copy)]
pub struct FieldDef {
    /// Ruta punteada completa (`tcp.flags.syn`).
    pub path: &'static str,
    /// Tipo esperado: num, str, bool, ip.
    pub kind: &'static str,
    /// Descripción breve en español.
    pub desc: &'static str,
    /// Nivel: P=paquete, F=flujo, ambos.
    pub level: &'static str,
}

/// Catálogo completo de campos.
pub const FIELDS: &[FieldDef] = &[
    // Frame
    FieldDef {
        path: "frame.number",
        kind: "num",
        desc: "Número de paquete en la captura",
        level: "P",
    },
    FieldDef {
        path: "frame.len",
        kind: "num",
        desc: "Longitud capturada (bytes)",
        level: "P",
    },
    FieldDef {
        path: "frame.ts",
        kind: "num",
        desc: "Timestamp epoch en microsegundos",
        level: "P",
    },
    // IP
    FieldDef {
        path: "ip.src",
        kind: "ip",
        desc: "IP origen (v4 o v6)",
        level: "PF",
    },
    FieldDef {
        path: "ip.dst",
        kind: "ip",
        desc: "IP destino",
        level: "PF",
    },
    FieldDef {
        path: "ip.proto",
        kind: "num",
        desc: "Protocolo IP (6=TCP, 17=UDP, 1=ICMP)",
        level: "PF",
    },
    FieldDef {
        path: "ip.frag",
        kind: "bool",
        desc: "Paquete IP fragmentado",
        level: "P",
    },
    // TCP
    FieldDef {
        path: "tcp.port",
        kind: "num",
        desc: "Puerto origen o destino",
        level: "PF",
    },
    FieldDef {
        path: "tcp.srcport",
        kind: "num",
        desc: "Puerto origen",
        level: "PF",
    },
    FieldDef {
        path: "tcp.dstport",
        kind: "num",
        desc: "Puerto destino",
        level: "PF",
    },
    FieldDef {
        path: "tcp.flags.syn",
        kind: "bool",
        desc: "Flag SYN",
        level: "P",
    },
    FieldDef {
        path: "tcp.flags.ack",
        kind: "bool",
        desc: "Flag ACK",
        level: "P",
    },
    FieldDef {
        path: "tcp.flags.fin",
        kind: "bool",
        desc: "Flag FIN",
        level: "P",
    },
    FieldDef {
        path: "tcp.flags.rst",
        kind: "bool",
        desc: "Flag RST",
        level: "P",
    },
    FieldDef {
        path: "tcp.flags.psh",
        kind: "bool",
        desc: "Flag PSH",
        level: "P",
    },
    // UDP
    FieldDef {
        path: "udp.port",
        kind: "num",
        desc: "Puerto UDP origen o destino",
        level: "PF",
    },
    // ARP
    FieldDef {
        path: "arp.op",
        kind: "num",
        desc: "Operación ARP (1=request, 2=reply)",
        level: "P",
    },
    // ICMP
    FieldDef {
        path: "icmp.type",
        kind: "num",
        desc: "Tipo ICMP (8=echo request)",
        level: "P",
    },
    // DNS
    FieldDef {
        path: "dns.qname",
        kind: "str",
        desc: "Dominio consultado",
        level: "PF",
    },
    FieldDef {
        path: "dns.qtype",
        kind: "num",
        desc: "Tipo de registro (1=A, 16=TXT, 28=AAAA)",
        level: "P",
    },
    FieldDef {
        path: "dns.is_response",
        kind: "bool",
        desc: "Es respuesta DNS",
        level: "P",
    },
    // HTTP
    FieldDef {
        path: "http.method",
        kind: "str",
        desc: "Método HTTP (GET/POST...)",
        level: "PF",
    },
    FieldDef {
        path: "http.target",
        kind: "str",
        desc: "URI objetivo",
        level: "PF",
    },
    FieldDef {
        path: "http.host",
        kind: "str",
        desc: "Cabecera Host",
        level: "PF",
    },
    FieldDef {
        path: "http.status",
        kind: "num",
        desc: "Código de estado de la respuesta",
        level: "PF",
    },
    FieldDef {
        path: "http.user_agent",
        kind: "str",
        desc: "User-Agent de la petición",
        level: "PF",
    },
    // TLS
    FieldDef {
        path: "tls.sni",
        kind: "str",
        desc: "Server Name Indication",
        level: "PF",
    },
    FieldDef {
        path: "tls.alpn",
        kind: "str",
        desc: "Protocolo negociado (h2, http/1.1)",
        level: "PF",
    },
    FieldDef {
        path: "tls.ja4",
        kind: "str",
        desc: "Fingerprint JA4-like del ClientHello",
        level: "PF",
    },
    // L7 genérico
    FieldDef {
        path: "proto",
        kind: "str",
        desc: "Protocolo L7 detectado (DNS/HTTP/TLS/TCP...)",
        level: "PF",
    },
    // Procesos (eBPF, fase 3 — presentes pero vacíos en fase 1)
    FieldDef {
        path: "proc.name",
        kind: "str",
        desc: "Proceso local responsable (eBPF, fase 3)",
        level: "PF",
    },
    FieldDef {
        path: "proc.pid",
        kind: "num",
        desc: "PID del proceso local (eBPF, fase 3)",
        level: "PF",
    },
    // Geo/ASN (MMDB, fase 3)
    FieldDef {
        path: "geo.dst",
        kind: "str",
        desc: "País/ASN del destino (fase 3)",
        level: "F",
    },
    // Flujo
    FieldDef {
        path: "flow.risk",
        kind: "num",
        desc: "Puntuación de riesgo 0-100",
        level: "F",
    },
    FieldDef {
        path: "flow.noise",
        kind: "bool",
        desc: "Es ruido de fondo (ARP/mDNS/NTP...)",
        level: "F",
    },
    FieldDef {
        path: "flow.proto",
        kind: "str",
        desc: "Protocolo L7 del flujo",
        level: "F",
    },
    FieldDef {
        path: "flow.domain",
        kind: "str",
        desc: "Dominio resuelto (passive DNS/Host/SNI)",
        level: "F",
    },
    FieldDef {
        path: "flow.duration_ms",
        kind: "num",
        desc: "Duración del flujo en ms",
        level: "F",
    },
    FieldDef {
        path: "flow.packets",
        kind: "num",
        desc: "Número de paquetes",
        level: "F",
    },
    FieldDef {
        path: "flow.bytes",
        kind: "num",
        desc: "Bytes totales (ambos sentidos)",
        level: "F",
    },
    FieldDef {
        path: "flow.state",
        kind: "str",
        desc: "Estado TCP (active/closed/reset)",
        level: "F",
    },
    FieldDef {
        path: "flow.has_alert",
        kind: "bool",
        desc: "El flujo tiene al menos una alerta",
        level: "F",
    },
    FieldDef {
        path: "alert.count",
        kind: "num",
        desc: "Número de alertas del flujo",
        level: "F",
    },
    FieldDef {
        path: "alert.max_severity",
        kind: "str",
        desc: "Severidad máxima (LOW/MEDIUM/HIGH/CRITICAL)",
        level: "F",
    },
    // Artefactos
    FieldDef {
        path: "artifact.magic",
        kind: "str",
        desc: "Magic bytes de un archivo extraído (MZ/ELF/PDF...)",
        level: "F",
    },
    FieldDef {
        path: "artifact.masquerade",
        kind: "bool",
        desc: "Hay un archivo disfrazado (T1036)",
        level: "F",
    },
];

/// Busca un campo por su ruta.
pub fn find(path: &str) -> Option<&'static FieldDef> {
    FIELDS.iter().find(|f| f.path.eq_ignore_ascii_case(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogo_consistente() {
        assert!(!FIELDS.is_empty());
        // Sin rutas duplicadas.
        let mut paths: Vec<&str> = FIELDS.iter().map(|f| f.path).collect();
        paths.sort_unstable();
        let n = paths.len();
        paths.dedup();
        assert_eq!(paths.len(), n, "hay campos duplicados");
        assert!(find("IP.SRC").is_some(), "búsqueda case-insensitive");
        assert!(find("nope.nope").is_none());
    }
}
