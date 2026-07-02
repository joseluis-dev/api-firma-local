"""Build script: produce a one-folder bundle using PyInstaller.

Uso:
    python installer/build.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "installer" / "build"
DIST = ROOT / "installer" / "dist"
SPEC = ROOT / "installer" / "gadsign_localapi.spec"
ICON = ROOT / "resources" / "gadsign.ico"


def ensure_icon() -> None:
    if ICON.exists():
        return
    from make_icon import make_ico

    ICON.parent.mkdir(parents=True, exist_ok=True)
    make_ico(ICON)
    print(f"Icono generado: {ICON}")


def main() -> int:
    if not SPEC.exists():
        print(f"No se encuentra {SPEC}")
        return 1
    ensure_icon()
    if BUILD.exists():
        shutil.rmtree(BUILD)
    if DIST.exists():
        shutil.rmtree(DIST)
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        str(SPEC),
    ]
    print(">>", " ".join(cmd))
    rc = subprocess.call(cmd, cwd=str(ROOT / "installer"))
    if rc != 0:
        return rc
    bundle = DIST / "GadSignLocalAPI"
    if not bundle.exists():
        print(f"No se genero {bundle}")
        return 1
    # Copiar .env.example al bundle para referencia.
    target_env = bundle / ".env.example"
    if not target_env.exists():
        shutil.copy2(ROOT / ".env.example", target_env)
    # Copiar icono.
    resources_src = ROOT / "resources"
    if resources_src.exists():
        for f in resources_src.iterdir():
            shutil.copy2(f, bundle / f.name)
    print(f"Bundle generado: {bundle}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
