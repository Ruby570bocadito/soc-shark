//! Dissectors de protocolos para **soc-shark**.
//!
//! Principios (ver `docs/04-dissectors.md`):
//! - **Zero-copy**: cada parser toma `&[u8]` y devuelve vistas (`&[u8]`) sobre
//!   los mismos bytes; solo se copian campos escalares y strings pequeños.
//! - **Memoria segura por construcción**: ningún parser hace `unwrap()` sobre
//!   índices; todos usan slicing comprobado y devuelven `Option`/`Result`.
//!   Un paquete malformado nunca debe tumbar el motor (objetivo del test
//!   de truncado masivo en `lib.rs`).
//! - **Salida normalizada**: [`view::dissect`] produce un
//!   [`view::DissectedPacket`] uniforme con tupla de 5, capa L7 detectada y
//!   payload de aplicación, listo para el `flow-aggregator`.

pub mod layer2;
pub mod layer3;
pub mod layer4;
pub mod layer7;
pub mod mac;
pub mod view;

pub use layer2::ethernet::{parse_ethernet, EthernetFrame};
pub use layer2::sll::parse_sll;
pub use layer3::ipv4::{parse_ipv4, Ipv4Packet, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
pub use layer3::ipv6::{parse_ipv6, Ipv6Packet};
pub use layer4::tcp::{parse_tcp, TcpSegment};
pub use layer4::udp::{parse_udp, UdpDatagram};
pub use layer7::dns::{parse_dns, DnsPacket};
pub use layer7::http::{parse_http, HttpMessage};
pub use layer7::tls::{parse_tls, ClientHello, TlsRecord};
pub use mac::MacAddr;
pub use view::{dissect, AppInfo, DissectedPacket, FiveTuple, NetInfo, TransInfo};
