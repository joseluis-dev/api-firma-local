"""Tray icon app for GadSign Local API.

Menus disponibles:
- Iniciar / Detener API
- Estado del token
- Ver puerto
- Ver origenes autorizados
- Revocar emparejamiento de un origen
- Limpiar PIN cacheado
- Abrir carpeta de logs
- Salir

Si pystray/Pillow no estan disponibles, cae a un bucle por consola
con los mismos comandos.
"""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
import webbrowser
from typing import Optional

from .. import __version__
from ..app import app
from ..config import settings
from ..core.config_store import config_store
from ..core.drivers.factory import has_real_driver, list_available_providers
from ..core.security.pairing import pairing_manager
from ..core.token_service import _pin_cache
from ..core.user_paths import logs_dir


log = logging.getLogger(__name__)
_server_thread: threading.Thread | None = None


def _run_uvicorn() -> None:
    import uvicorn

    cfg = config_store.get()
    uvicorn.run(
        app,
        host=cfg.host,
        port=cfg.port,
        log_level=cfg.log_level.lower(),
        access_log=False,
        server_header=False,
    )


def _start_server_thread() -> None:
    global _server_thread
    if _server_thread and _server_thread.is_alive():
        return
    _server_thread = threading.Thread(target=_run_uvicorn, daemon=True)
    _server_thread.start()


def _status_text() -> str:
    cfg = config_store.get()
    providers = list_available_providers()
    real = has_real_driver()
    tok_count = sum(1 for t in pairing_manager.list_tokens() if not t.revoked)
    return (
        f"GadSign Local API\n"
        f"Version: v{__version__}\n"
        f"Endpoint: http://{cfg.host}:{cfg.port}\n"
        f"Driver real: {'si' if real else 'no'}\n"
        f"Providers: {', '.join(p['id'] for p in providers) or '-'}\n"
        f"PIN cache: {len(_pin_cache._data)} tokens\n"  # type: ignore[attr-defined]
        f"Tokens activos: {tok_count}\n"
        f"Origenes: {', '.join(cfg.effective_allowed_origins()) or '-'}\n"
        f"DevMode: {cfg.dev_mode}\n"
        f"Pairing: {'activo' if cfg.require_pairing else 'desactivado'}\n"
        f"Confirmacion firma: {'si' if cfg.require_user_confirmation else 'no'}\n"
    )


def _revoke_origin_interactive() -> Optional[str]:
    """Simple prompt por consola; en tray se reemplaza por submenu."""
    tokens = [t for t in pairing_manager.list_tokens() if not t.revoked]
    if not tokens:
        return None
    print("Origenes emparejados:")
    for i, t in enumerate(tokens, 1):
        print(f"  {i}. {t.origin}")
    try:
        sel = int(input("Numero a revocar (0=cancelar): ").strip())
    except ValueError:
        return None
    if sel <= 0 or sel > len(tokens):
        return None
    target = tokens[sel - 1]
    n = pairing_manager.revoke_origin(target.origin)
    return target.origin if n else None


def _console_loop() -> None:
    _start_server_thread()
    print(_status_text())
    print("Comandos: status | revoke | clear-pin | logs | open-docs | quit")
    while True:
        try:
            cmd = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if cmd in {"q", "quit", "exit"}:
            break
        if cmd == "status":
            print(_status_text())
        elif cmd == "revoke":
            origin = _revoke_origin_interactive()
            print(f"Revocado: {origin}" if origin else "Sin cambios.")
        elif cmd in {"clear-pin", "clear_pin"}:
            with _pin_cache._lock:  # type: ignore[attr-defined]
                _pin_cache._data.clear()  # type: ignore[attr-defined]
            print("PIN cache limpiado.")
        elif cmd == "logs":
            print(f"Logs: {logs_dir()}")
        elif cmd == "open-docs":
            webbrowser.open(f"http://{cfg.host}:{cfg.port}/api/v1/docs")
        else:
            print("Comando no reconocido.")


# ---------------------------------------------------------------------------
# pystray UI
# ---------------------------------------------------------------------------


def _tray_loop() -> None:
    import pystray  # type: ignore
    from PIL import Image, ImageDraw  # type: ignore

    def make_image() -> "Image.Image":
        img = Image.new("RGB", (64, 64), color="navy")
        d = ImageDraw.Draw(img)
        d.rectangle((8, 8, 56, 56), fill="white")
        d.text((18, 24), "G", fill="navy")
        return img

    def on_status(icon, item):
        try:
            import tkinter as tk
            from tkinter import scrolledtext

            win = tk.Tk()
            win.title("GadSign Local API - Estado")
            win.geometry("520x360")
            text = scrolledtext.ScrolledText(win, font=("Consolas", 10))
            text.insert("1.0", _status_text())
            text.configure(state="disabled")
            text.pack(fill="both", expand=True)
            win.attributes("-topmost", True)
            win.mainloop()
        except Exception as exc:
            log.warning("No se pudo abrir ventana de estado: %s", exc)

    def on_open_docs(icon, item):
        webbrowser.open(f"http://{settings.host}:{settings.port}/api/v1/docs")

    def on_open_logs(icon, item):
        try:
            os.startfile(str(logs_dir()))  # type: ignore[attr-defined]
        except Exception:
            print(f"Logs: {logs_dir()}")

    def on_clear_pin(icon, item):
        with _pin_cache._lock:  # type: ignore[attr-defined]
            _pin_cache._data.clear()  # type: ignore[attr-defined]
        log.info("PIN cache limpiado desde tray.")

    def on_revoke(icon, item):
        # Muestra un submenu con los origenes para revocar.
        tokens = [t for t in pairing_manager.list_tokens() if not t.revoked]
        return pystray.Menu(*[
            pystray.MenuItem(
                t.origin,
                lambda i, it, o=t.origin: pairing_manager.revoke_origin(o),
            )
            for t in tokens
        ]) if tokens else pystray.MenuItem("(sin origenes)", None, enabled=False)

    def on_quit(icon, item):
        icon.stop()
        os._exit(0)

    _start_server_thread()

    icon = pystray.Icon(
        "gadsign-localapi",
        make_image(),
        "GadSign Local API",
        menu=pystray.Menu(
            pystray.MenuItem("Estado", on_status),
            pystray.MenuItem("Abrir docs", on_open_docs),
            pystray.MenuItem("Abrir logs", on_open_logs),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Limpiar PIN cacheado", on_clear_pin),
            pystray.MenuItem("Revocar origen", on_revoke),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Salir", on_quit),
        ),
    )
    icon.run()


def main() -> int:
    try:
        import pystray  # type: ignore
        from PIL import Image  # type: ignore
        _tray_loop()
    except Exception as exc:
        log.info("Tray no disponible (%s), arrancando en consola.", exc)
        _console_loop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
