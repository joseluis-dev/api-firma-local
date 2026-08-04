"""Firma digital de ejecutables e instaladores con signtool.exe.

Modos:
  --thumbprint <hash>   : Usa certificado del Windows Certificate Store.
  --pfx <archivo>       : Usa archivo PFX. La password se lee de la variable
                          de entorno CODESIGN_PASSWORD o de stdin.

Uso:
    python installer/sign.py path\\to\\file.exe --thumbprint ABC123
    python installer/sign.py path\\to\\file.exe --pfx archivo.pfx
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional


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


def _masked_cmd(cmd: list[str]) -> str:
    masked = list(cmd)
    for i, arg in enumerate(masked):
        if arg == "/p" and i + 1 < len(masked):
            masked[i + 1] = "***"
    return " ".join(masked)


def sign(
    target: Path,
    timestamp_url: str,
    thumbprint: Optional[str] = None,
    pfx: Optional[Path] = None,
    password: Optional[str] = None,
) -> int:
    signtool = _find_signtool()
    cmd = [
        signtool, "sign",
        "/fd", "SHA256",
        "/td", "SHA256",
        "/tr", timestamp_url,
    ]
    if thumbprint:
        cmd += ["/sha1", thumbprint]
    elif pfx:
        cmd += ["/f", str(pfx)]
        if password:
            cmd += ["/p", password]

    cmd.append(str(target))
    print(">>", _masked_cmd(cmd))
    return subprocess.call(cmd)


def verify(target: Path) -> bool:
    signtool = _find_signtool()
    rc = subprocess.call([signtool, "verify", "/pa", "/all", str(target)])
    return rc == 0


def main() -> int:
    p = argparse.ArgumentParser(description="Firma digital con signtool.exe")
    p.add_argument("target", type=Path, help="Archivo a firmar")
    p.add_argument("--thumbprint", help="SHA1 thumbprint del certificado en el store de Windows")
    p.add_argument("--pfx", type=Path, help="Archivo PFX con clave privada")
    p.add_argument("--timestamp-url", default="http://timestamp.digicert.com")
    p.add_argument("--verify", action="store_true", help="Verificar firma despues de firmar")
    args = p.parse_args()

    if not args.thumbprint and not args.pfx:
        p.error("Debe especificar --thumbprint o --pfx")
    if args.thumbprint and args.pfx:
        p.error("Use --thumbprint o --pfx, no ambos")

    password: Optional[str] = None
    if args.pfx:
        password = os.environ.get("CODESIGN_PASSWORD")
        if not password:
            password = input("Password del PFX: ").strip()
            if not password:
                print("ERROR: Password requerida.", file=sys.stderr)
                return 1

    rc = sign(args.target, args.timestamp_url, args.thumbprint, args.pfx, password)
    if rc != 0:
        return rc

    if args.verify:
        if verify(args.target):
            print("Firma verificada OK.")
        else:
            print("ERROR: Verificacion de firma fallo.", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
