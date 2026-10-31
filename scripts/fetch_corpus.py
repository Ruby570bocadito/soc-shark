#!/usr/bin/env python3
"""Descarga las capturas reales del corpus (corpus/manifest.json).

Para cada entrada con `file` y `url` que no esté ya en disco: la descarga
por HTTPS, comprueba su `sha256` y la deja en `corpus/<file>`. Las capturas
reales no se versionan (`corpus/captures/` está en .gitignore): pueden pesar
mucho, tener licencias que no permiten redistribuirlas o, en el caso de
Malware-Traffic-Analysis, contener malware que los antivirus marcan.

Uso:
    python3 scripts/fetch_corpus.py            # descarga lo que falte
    python3 scripts/fetch_corpus.py --check    # solo comprueba sha256

Si la captura viene en un .zip, indica `"zip_member"` (el archivo de dentro)
y, si tiene contraseña ZipCrypto, `"zip_password"`. Los zip cifrados con AES
(o los .7z) no los abre la biblioteca estándar: descárgalos a mano.
"""

import argparse
import hashlib
import io
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(entry: dict) -> bytes:
    url = entry["url"]
    if not url.startswith("https://"):
        raise SystemExit(f"{entry['name']}: solo se admiten URLs https:// ({url})")
    with urllib.request.urlopen(url, timeout=60) as r:
        data = r.read()
    member = entry.get("zip_member")
    if member:
        pwd = entry.get("zip_password")
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            data = z.read(member, pwd=pwd.encode() if pwd else None)
    return data


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="no descargar, solo comprobar")
    args = ap.parse_args()

    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    errors = 0
    for entry in manifest["captures"]:
        if "file" not in entry:
            continue  # escenario sintético
        dest = CORPUS / entry["file"]
        expected = entry.get("sha256")
        if not dest.exists():
            if args.check or "url" not in entry:
                print(f"falta   {entry['file']}")
                errors += 1
                continue
            print(f"bajando {entry['file']} ← {entry['url']}")
            data = fetch(entry)
            if expected and sha256(data) != expected:
                print(f"ERROR   {entry['file']}: sha256 {sha256(data)} ≠ {expected}")
                errors += 1
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        got = sha256(dest.read_bytes())
        if expected and got != expected:
            print(f"ERROR   {entry['file']}: sha256 {got} ≠ {expected}")
            errors += 1
        else:
            print(f"ok      {entry['file']}" + ("" if expected else f"  (añade \"sha256\": \"{got}\")"))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
