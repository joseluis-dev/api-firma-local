"""Script de instalacion Windows (PowerShell).

Pasos:
1. Crear entorno virtual en .venv
2. Instalar dependencias
3. Crear acceso directo en Startup (autostart)
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
VENV = BASE_DIR / ".venv"
REQUIREMENTS = BASE_DIR / "requirements.txt"


def run(cmd: list[str], **kwargs) -> None:
    print(">>", " ".join(cmd))
    subprocess.run(cmd, check=True, **kwargs)


def ensure_venv() -> None:
    if VENV.exists():
        print(f"venv ya existe: {VENV}")
        return
    run([sys.executable, "-m", "venv", str(VENV)])


def install_deps() -> None:
    pip = VENV / "Scripts" / "pip.exe"
    if not pip.exists():
        pip = VENV / "bin" / "pip"
    run([str(pip), "install", "--upgrade", "pip"])
    run([str(pip), "install", "-r", str(REQUIREMENTS)])


def create_startup_shortcut() -> None:
    if os.name != "nt":
        print("Startup shortcut solo Windows.")
        return
    startup = Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    startup.mkdir(parents=True, exist_ok=True)
    bat = startup / "localapi.bat"
    python_exe = VENV / "Scripts" / "python.exe"
    bat.write_text(
        f'@echo off\r\n'
        f'cd /d "{BASE_DIR}"\r\n'
        f'"{python_exe}" -m localapi.main\r\n',
        encoding="utf-8",
    )
    print(f"Acceso directo creado: {bat}")


def main() -> int:
    ensure_venv()
    install_deps()
    create_startup_shortcut()
    print("Instalacion completada.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
