"""Firma digital de ejecutables e instaladores con signtool.exe.

Requiere:
- Windows SDK Build Tools
- Certificado de code signing (.pfx) y su password

Uso:
    python installer/sign.py path\\to\\file.exe --pfx archivo.pfx --password *****
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def _find_signtool() -> str:
    candidates = [
        r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
        r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
        r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    found = shutil.which("signtool")
    if found:
        return found
    raise FileNotFoundError("signtool.exe no encontrado.")


def sign(target: Path, pfx: Path, password: str, timestamp_url: str) -> int:
    signtool = _find_signtool()
    cmd = [
        signtool, "sign",
        "/fd", "SHA256",
        "/td", "SHA256",
        "/tr", timestamp_url,
        "/f", str(pfx),
        "/p", password,
        str(target),
    ]
    print(">>", " ".join(cmd))
    return subprocess.call(cmd)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("target", type=Path)
    p.add_argument("--pfx", required=True, type=Path)
    p.add_argument("--password", required=True)
    p.add_argument("--timestamp-url", default="http://timestamp.digicert.com")
    args = p.parse_args()
    return sign(args.target, args.pfx, args.password, args.timestamp_url)


if __name__ == "__main__":
    sys.exit(main())
