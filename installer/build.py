"""Build script: produce a one-folder bundle using PyInstaller.

Uso:
    python installer/build.py
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "installer" / "build"
DIST = ROOT / "installer" / "dist"
SPEC = ROOT / "installer" / "gadsign_localapi.spec"
ICON = ROOT / "resources" / "gadsign.ico"
VERSION_FILE = ROOT / "installer" / "version_info.txt"


def _read_canonical_version() -> str:
    init = ROOT / "__init__.py"
    ns: dict = {}
    exec(init.read_text(encoding="utf-8"), ns)
    return ns["__version__"]


def _validate_x64() -> None:
    if struct.calcsize("P") != 8:
        print("ERROR: El build debe ejecutarse con Python x64.", file=sys.stderr)
        sys.exit(1)


def ensure_icon() -> None:
    if ICON.exists():
        return
    from make_icon import make_ico

    ICON.parent.mkdir(parents=True, exist_ok=True)
    make_ico(ICON)
    print(f"Icono generado: {ICON}")


def _generate_version_file(version: str, target: Path) -> None:
    parts = version.split(".")
    major, minor, patch = (int(p) if p.isdigit() else 0 for p in parts[:3])
    build = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0

    content = f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({major}, {minor}, {patch}, {build}),
    prodvers=({major}, {minor}, {patch}, {build}),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0),
  ),
  kids=[
    StringFileInfo([
      StringTable(
        u'040904B0',
        [
          StringStruct(u'CompanyName', u'GadSign / Salcedo'),
          StringStruct(u'FileDescription', u'GadSign Local API'),
          StringStruct(u'FileVersion', u'{version}'),
          StringStruct(u'InternalName', u'GadSignLocalAPI'),
          StringStruct(u'LegalCopyright', u'(c) 2026'),
          StringStruct(u'OriginalFilename', u'GadSignLocalAPI.exe'),
          StringStruct(u'ProductName', u'GadSign Local API'),
          StringStruct(u'ProductVersion', u'{version}'),
        ]),
    ]),
    VarFileInfo([VarStruct(u'Translation', [0x0409, 0x04B0])]),
  ],
)
"""
    target.write_text(content, encoding="utf-8")
    print(f"Version file generado: {target}")


def main() -> int:
    _validate_x64()
    if not SPEC.exists():
        print(f"No se encuentra {SPEC}")
        return 1
    version = _read_canonical_version()
    print(f"Version canonica: {version}")
    ensure_icon()
    _generate_version_file(version, VERSION_FILE)

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
    target_env = bundle / ".env.example"
    if not target_env.exists():
        shutil.copy2(ROOT / ".env.example", target_env)
    resources_src = ROOT / "resources"
    if resources_src.exists():
        for f in resources_src.iterdir():
            shutil.copy2(f, bundle / f.name)
    print(f"Bundle generado: {bundle}")
    print("")
    print(f"Para compilar el instalador ejecuta:")
    print(f'  & "$env:LOCALAPPDATA\\Programs\\Inno Setup 6\\ISCC.exe" /DMyAppVersion={version} installer\\inno_setup.iss')
    return 0


if __name__ == "__main__":
    _validate_x64()
    sys.exit(main())
