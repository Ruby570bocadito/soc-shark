#!/usr/bin/env python3
"""Descarga las capturas reales del corpus (corpus/manifest.json).

Para cada entrada con `file` y `url` que no esté ya en disco: la descarga
por HTTPS, comprueba su `sha256` y la deja en `corpus/<file>`. Las capturas
reales no se versionan (`corpus/captures/` está en .gitignore): pueden pesar
mucho, tener licencias que no permiten redistribuirlas o, en el caso de
Malware-Traffic-Analysis, contener malware que los antivirus marcan.

Uso:
    python3 -I scripts/fetch_corpus.py            # descarga lo que falte
    python3 -I scripts/fetch_corpus.py --check    # solo comprueba sha256

Si la captura viene comprimida con gzip, indica `"gunzip": true`; si viene
en un .zip, `"zip_member"` (el archivo de dentro) y, si tiene contraseña
ZipCrypto, `"zip_password"`. Los zip cifrados con AES (o los .7z) no los
abre la biblioteca estándar: descárgalos a mano. El `sha256` es siempre el
del archivo final (ya descomprimido), que es lo que comprueba el test.

Límites: como mucho MAX_DOWNLOAD bytes por descarga y MAX_EXPANDED tras
descomprimir. Un servidor que responde 429/503 se respeta (Retry-After) y
entre descargas se hace una pausa (--pause).
"""

import argparse
import gzip
import hashlib
import io
import json
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"

MAX_DOWNLOAD = 5 * 1024 * 1024
MAX_EXPANDED = 50 * 1024 * 1024
RETRIES = 5
USER_AGENT = "soc-shark-corpus-fetch (+https://github.com/Ruby570bocadito/soc-shark)"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download(url: str) -> bytes:
    """GET con tope de tamaño y reintentos educados ante 429/503."""
    for attempt in range(1, RETRIES + 1):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                declared = r.headers.get("Content-Length")
                if declared and int(declared) > MAX_DOWNLOAD:
                    raise SystemExit(f"{url}: {declared} bytes, más que el tope de {MAX_DOWNLOAD}")
                data = r.read(MAX_DOWNLOAD + 1)
                if len(data) > MAX_DOWNLOAD:
                    raise SystemExit(f"{url}: supera el tope de {MAX_DOWNLOAD} bytes")
                return data
        except urllib.error.HTTPError as e:
            if e.code not in (429, 503) or attempt == RETRIES:
                raise
            wait = e.headers.get("Retry-After")
            wait = min(int(wait), 120) if wait and wait.isdigit() else 15 * attempt
            print(f"        el servidor pide esperar ({e.code}); reintento en {wait} s")
            time.sleep(wait)
    raise SystemExit(f"{url}: sin respuesta tras {RETRIES} intentos")


def fetch(entry: dict) -> bytes:
    url = entry["url"]
    if not url.startswith("https://"):
        raise SystemExit(f"{entry['name']}: solo se admiten URLs https:// ({url})")
    data = download(url)
    if entry.get("gunzip"):
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
            data = g.read(MAX_EXPANDED + 1)
        if len(data) > MAX_EXPANDED:
            raise SystemExit(f"{entry['name']}: descomprimido supera {MAX_EXPANDED} bytes")
    member = entry.get("zip_member")
    if member:
        pwd = entry.get("zip_password")
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if z.getinfo(member).file_size > MAX_EXPANDED:
                raise SystemExit(f"{entry['name']}: {member} supera {MAX_EXPANDED} bytes")
            data = z.read(member, pwd=pwd.encode() if pwd else None)
    return data


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="no descargar, solo comprobar")
    ap.add_argument("--pause", type=float, default=5.0, help="segundos entre descargas")
    args = ap.parse_args()

    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    errors = 0
    downloaded = 0
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
            if downloaded:
                time.sleep(args.pause)
            print(f"bajando {entry['file']} <- {entry['url']}")
            data = fetch(entry)
            downloaded += 1
            if expected and sha256(data) != expected:
                print(f"ERROR   {entry['file']}: sha256 {sha256(data)} != {expected}")
                errors += 1
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        content = dest.read_bytes()
        got = sha256(content)
        if expected and got != expected:
            print(f"ERROR   {entry['file']}: sha256 {got} != {expected}")
            errors += 1
        else:
            note = "" if expected else f'  (añade "sha256": "{got}")'
            print(f"ok      {entry['file']} ({len(content)} bytes){note}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
