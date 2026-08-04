"""PyInstaller spec for GadSign Local API.

Genera un bundle one-folder con tray + uvicorn embebido.

Uso:
    pyinstaller --noconfirm installer/gadsign_localapi.spec
"""
# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None
SPEC_DIR = Path(SPEC).resolve().parent
ROOT = SPEC_DIR.parent
PROJECT_PARENT = ROOT.parent


def collect_optional(package):
    try:
        return collect_submodules(package)
    except Exception:
        return []

datas = [
    (str(ROOT / '.env.example'), '.'),
]

hiddenimports = [
    'PIL._tkinter_finder',
    'tkinter',
]

for package in (
    'uvicorn',
    'pystray',
    'PIL',
    'pyhanko',
    'asn1crypto',
    'cryptography',
    'pkcs11',
    'smartcard',
):
    hiddenimports += collect_optional(package)

a = Analysis(
    [str(ROOT / 'installer' / 'windows_launcher.py')],
    pathex=[str(PROJECT_PARENT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'pytest',
        'tests',
        'unittest',
        'test',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

version_file = str(SPEC_DIR / 'version_info.txt')
version_version = str(ROOT / 'installer' / 'version_info.txt')

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='GadSignLocalAPI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / 'resources' / 'gadsign.ico'),
    version=str(ROOT / 'installer' / 'version_info.txt'),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='GadSignLocalAPI',
)
