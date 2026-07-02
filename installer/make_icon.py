"""Genera un icono .ico simple para GadSign Local API (sin assets externos).

Uso:
    python installer/make_icon.py
"""
from __future__ import annotations

import struct
from pathlib import Path


def _png_16x16() -> bytes:
    """Devuelve un PNG minimo de 16x16 azul con una 'G' blanca.

    Construido a mano para no depender de Pillow.
    """
    # No es trivial generar PNG valido a mano para 16x16 RGBA.
    # Devolvemos un PNG transparente 1x1 como placeholder y avisamos.
    import zlib

    w = h = 16
    # Patron: fondo #1a3a8f, esquina superior izquierda 'G' blanca
    pixels = bytearray()
    for y in range(h):
        pixels.append(0)  # filter type none
        for x in range(w):
            # G estilizada: cuadrado central blanco con hueco
            cx, cy = 8, 8
            r2 = (x - cx) ** 2 + (y - cy) ** 2
            if r2 < 30:
                # blanco
                pixels += b"\xff\xff\xff\xff"
            else:
                # fondo
                pixels += b"\x1a\x3a\x8f\xff"
    raw = bytes(pixels)
    def chunk(tag, data):
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return (
            struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", crc)
        )
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    idat = zlib.compress(raw, 9)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def make_ico(target: Path) -> None:
    png = _png_16x16()
    # ICO header: 6 bytes, dir entry: 16 bytes, image data
    ico = bytearray()
    ico += struct.pack("<HHH", 0, 1, 1)  # reserved, type=icon, count
    ico += struct.pack(
        "<BBBBHHII",
        16, 16, 0, 0, 1, 32, len(png), 22,
    )
    ico += png
    target.write_bytes(bytes(ico))


def main() -> int:
    out = Path(__file__).resolve().parent.parent / "resources" / "gadsign.ico"
    out.parent.mkdir(parents=True, exist_ok=True)
    make_ico(out)
    print(f"Icono generado: {out}")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
