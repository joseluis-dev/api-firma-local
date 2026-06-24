"""Lanzador con icono en system tray (Windows).

Si ``pystray`` no esta instalado, simplemente arranca la API
en una ventana de consola.
"""
from __future__ import annotations

import sys
import threading

from .app import app
from .config import settings


def _run_uvicorn() -> None:
    import uvicorn

    uvicorn.run(
        "localapi.app:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        access_log=False,
        server_header=False,
    )


def main() -> int:
    try:
        import pystray  # type: ignore
        from PIL import Image, ImageDraw  # type: ignore
    except Exception:
        print("pystray/Pillow no disponible; arrancando en consola.")
        _run_uvicorn()
        return 0

    def on_quit(icon, item):  # type: ignore[no-untyped-def]
        icon.stop()
        sys.exit(0)

    def on_show_docs(icon, item):  # type: ignore[no-untyped-def]
        import webbrowser

        webbrowser.open(f"http://{settings.host}:{settings.port}/api/v1/docs")

    img = Image.new("RGB", (64, 64), color="navy")
    ImageDraw.Draw(img).rectangle((8, 8, 56, 56), fill="white")
    ImageDraw.Draw(img).text((20, 24), "LAPI", fill="navy")

    icon = pystray.Icon(
        "localapi",
        img,
        "Local API Firma Token",
        menu=pystray.Menu(
            pystray.MenuItem("Abrir docs", on_show_docs),
            pystray.MenuItem("Salir", on_quit),
        ),
    )

    t = threading.Thread(target=_run_uvicorn, daemon=True)
    t.start()
    icon.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
