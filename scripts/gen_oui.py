#!/usr/bin/env python3
"""Genera crates/socshark-soc/src/oui_data.rs a partir del registro público
del IEEE (MA-L, prefijos de 24 bits): https://standards-oui.ieee.org/oui/oui.csv

Solo se incluyen marcas que una persona reconoce en casa o en la oficina
(móviles, ordenadores, routers de operadoras, impresoras, NAS, domótica…):
así la tabla es pequeña y el fabricante se dice con el nombre de la marca,
no con la razón social («Apple», no «Apple, Inc.»).

Uso:  python3 scripts/gen_oui.py oui.csv > crates/socshark-soc/src/oui_data.rs
"""
import csv
import re
import sys

# (patrón sobre la razón social, marca, a qué suele corresponder)
BRANDS = [
    (r"^Apple,? Inc", "Apple", None),
    (r"^Samsung Electronics|^SAMSUNG ELECTRO", "Samsung", None),
    (r"^Google,? (Inc|LLC)", "Google", None),
    (r"^Nest Labs", "Google Nest", "domótica"),
    (r"^Amazon Technologies|^Amazon\.com", "Amazon", None),
    (r"^Microsoft", "Microsoft", None),
    (r"^Intel Corporat", "Intel", "tarjeta de red de ordenador"),
    (r"^Realtek", "Realtek", "tarjeta de red de ordenador"),
    (r"^HUAWEI TECHNOLOGIES|^Huawei Device", "Huawei", None),
    (r"^Honor Device", "Honor", "móvil"),
    (r"Xiaomi", "Xiaomi", None),
    (r"OPPO", "OPPO", "móvil"),
    (r"^vivo Mobile", "vivo", "móvil"),
    (r"^Realme", "realme", "móvil"),
    (r"^OnePlus", "OnePlus", "móvil"),
    (r"^Motorola Mobility", "Motorola", "móvil"),
    (r"^LG Electronics|^LG Innotek", "LG", None),
    (r"^Sony Interactive", "Sony PlayStation", "videoconsola"),
    (r"^Sony (Corporation|Mobile)", "Sony", None),
    (r"^Nintendo", "Nintendo", "videoconsola"),
    (r"^Hewlett Packard|^HP Inc", "HP", None),
    (r"^Dell (Inc|Technologies)", "Dell", "ordenador"),
    (r"^Lenovo|^LCFC", "Lenovo", "ordenador"),
    (r"^ASUSTek", "ASUS", None),
    (r"^Acer Incorporated", "Acer", "ordenador"),
    (r"^Raspberry Pi", "Raspberry Pi", "miniordenador"),
    (r"^Espressif", "Espressif", "dispositivo inteligente (enchufe, bombilla, sensor…)"),
    (r"^Tuya", "Tuya", "dispositivo inteligente"),
    (r"^Shelly|^Allterco", "Shelly", "domótica"),
    (r"^Signify|^Philips Lighting", "Philips Hue", "iluminación inteligente"),
    (r"^Sonos", "Sonos", "altavoz"),
    (r"^Bose Corporation", "Bose", "altavoz"),
    (r"^Roku", "Roku", "televisión"),
    (r"^Hisense", "Hisense", "televisión"),
    (r"^Panasonic", "Panasonic", None),
    (r"^TP-LINK|^TP-Link", "TP-Link", "router o Wi-Fi"),
    (r"^NETGEAR", "Netgear", "router o Wi-Fi"),
    (r"^Ubiquiti", "Ubiquiti", "router o Wi-Fi"),
    (r"^Cisco", "Cisco", "equipo de red"),
    (r"^Routerboard|^MikroTik", "MikroTik", "router"),
    (r"^AVM ", "AVM FRITZ!Box", "router"),
    (r"^Arcadyan", "Arcadyan", "router de operadora"),
    (r"^Sagemcom", "Sagemcom", "router de operadora"),
    (r"^zte corporation", "ZTE", "router de operadora"),
    (r"^Technicolor", "Technicolor", "router de operadora"),
    (r"^Askey", "Askey", "router de operadora"),
    (r"^MitraStar", "MitraStar", "router de operadora"),
    (r"^Zyxel", "Zyxel", "router"),
    (r"^D-Link", "D-Link", "router o Wi-Fi"),
    (r"^Belkin", "Belkin", None),
    (r"^Shenzhen Tenda|^Tenda", "Tenda", "router o Wi-Fi"),
    (r"^Fortinet", "Fortinet", "cortafuegos"),
    (r"^Palo Alto Networks", "Palo Alto Networks", "cortafuegos"),
    (r"^Aruba", "Aruba", "Wi-Fi de empresa"),
    (r"^Ruckus", "Ruckus", "Wi-Fi de empresa"),
    (r"^Synology", "Synology", "disco en red (NAS)"),
    (r"^QNAP", "QNAP", "disco en red (NAS)"),
    (r"^Canon Inc", "Canon", "impresora o cámara"),
    (r"^Seiko Epson", "Epson", "impresora"),
    (r"^Brother Industries", "Brother", "impresora"),
    (r"^Xerox", "Xerox", "impresora"),
    (r"^Lexmark", "Lexmark", "impresora"),
    (r"^KYOCERA", "Kyocera", "impresora"),
    (r"^Ricoh", "Ricoh", "impresora"),
    (r"^Hangzhou Hikvision", "Hikvision", "cámara de vigilancia"),
    (r"^Zhejiang Dahua", "Dahua", "cámara de vigilancia"),
    (r"^Garmin", "Garmin", None),
    (r"^Fitbit", "Fitbit", "pulsera"),
    (r"^Tesla", "Tesla", "coche"),
    (r"^VMware", "VMware", "máquina virtual"),
    (r"^PCS Systemtechnik", "VirtualBox", "máquina virtual"),
    (r"^Parallels", "Parallels", "máquina virtual"),
]


def main(path):
    compiled = [(re.compile(p, re.I), b, k) for p, b, k in BRANDS]
    names = []
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["Registry"] != "MA-L":
                continue
            org = row["Organization Name"].strip()
            for rx, brand, kind in compiled:
                if rx.search(org):
                    key = (brand, kind)
                    if key not in names:
                        names.append(key)
                    rows.append((int(row["Assignment"], 16), names.index(key)))
                    break
    rows.sort()
    out = sys.stdout
    out.write("//! Fabricantes por prefijo de MAC (OUI). GENERADO por\n")
    out.write("//! `scripts/gen_oui.py` desde el registro público del IEEE (MA-L):\n")
    out.write("//! no editar a mano. Solo marcas reconocibles en casa u oficina.\n\n")
    out.write("/// (marca, a qué suele corresponder).\n")
    out.write("pub(crate) static BRANDS: &[(&str, Option<&str>)] = &[\n")
    for brand, kind in names:
        k = f'Some("{kind}")' if kind else "None"
        out.write(f'    ("{brand}", {k}),\n')
    out.write("];\n\n")
    out.write("/// (prefijo de 24 bits, índice en `BRANDS`), ordenado por prefijo.\n")
    out.write("pub(crate) static OUI: &[(u32, u8)] = &[\n")
    for i in range(0, len(rows), 6):
        chunk = rows[i : i + 6]
        out.write("    " + " ".join(f"(0x{p:06X}, {b})," for p, b in chunk) + "\n")
    out.write("];\n")
    print(f"{len(rows)} prefijos, {len(names)} marcas", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1])
