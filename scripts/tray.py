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
import queue
import sys
import threading
import webbrowser
from typing import Optional

from .. import __version__
from ..app import app
from ..core.config_store import config_store
from ..core.drivers.factory import has_real_driver, list_available_providers
from ..core.security.pairing import pairing_manager
from ..core.token_service import _pin_cache
from ..core.user_paths import logs_dir
from ..core.update_service import UpdateService, UpdateResult
from ..installer.update_check import CheckResult

log = logging.getLogger(__name__)
_server_thread: threading.Thread | None = None
_shutdown_requested = False
_update_service: UpdateService | None = None

# Acciones que los callbacks de pystray (hilo propio de pystray) envian al
# hilo principal de Tkinter. Nunca se toca Tkinter desde otro hilo.
_action_queue: "queue.Queue[str]" = queue.Queue()


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
    tok_count = len(pairing_manager.list_active_tokens())
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
            c = config_store.get()
            webbrowser.open(f"http://{c.host}:{c.port}/api/v1/docs")
        else:
            print("Comando no reconocido.")


# ---------------------------------------------------------------------------
# pystray UI
# ---------------------------------------------------------------------------


def _tray_loop() -> None:
    import pystray  # type: ignore
    import tkinter as tk
    from tkinter import scrolledtext  # noqa: F401  (valida la dependencia)
    from PIL import Image, ImageDraw  # type: ignore

    def make_image() -> "Image.Image":
        img = Image.new("RGB", (64, 64), color="navy")
        d = ImageDraw.Draw(img)
        d.rectangle((8, 8, 56, 56), fill="white")
        d.text((18, 24), "G", fill="navy")
        return img

    # ------------------------------------------------------------------
    # Tkinter: hilo principal (mainloop propietario de la ventana)
    # ------------------------------------------------------------------

    root = tk.Tk()
    root.withdraw()
    holder: dict = {"win": None}

    def _refresh_status(win) -> None:
        text = getattr(win, "_gadsign_text", None)
        if text is None:
            return
        text.configure(state="normal")
        text.delete("1.0", "end")
        text.insert("1.0", _status_text())
        text.configure(state="disabled")

    def _show_status() -> None:
        win = holder["win"]
        if win is not None and win.winfo_exists():
            win.deiconify()
            win.lift()
            win.focus_force()
            _refresh_status(win)
            return
        win = tk.Toplevel(root)
        holder["win"] = win
        win.title("GadSign Local API - Estado")
        win.geometry("520x360")
        # Ventana de tamano fijo: el boton de maximizar queda deshabilitado.
        win.resizable(False, False)
        text = scrolledtext.ScrolledText(win, font=("Consolas", 10))
        text.insert("1.0", _status_text())
        text.configure(state="disabled")
        text.pack(fill="both", expand=True)
        win._gadsign_text = text  # type: ignore[attr-defined]
        win.attributes("-topmost", True)
        # Cerrar SOLO la ventana: la API y el icono siguen corriendo.
        win.protocol("WM_DELETE_WINDOW", win.destroy)
        win.bind("<Escape>", lambda _e: win.destroy())

    def _quit_app() -> None:
        try:
            win = holder["win"]
            if win is not None and win.winfo_exists():
                win.destroy()
        except Exception:
            pass
        root.quit()

    def _poll_actions() -> None:
        try:
            while True:
                action = _action_queue.get_nowait()
                if action == "status":
                    _show_status()
                elif action == "quit":
                    _quit_app()
                    return
        except queue.Empty:
            pass
        except Exception:
            log.exception("Error procesando accion del menu bandeja.")
        root.after(100, _poll_actions)

    # ------------------------------------------------------------------
    # pystray: hilo detached; callbacks SOLO encolan acciones
    # ------------------------------------------------------------------

    def on_status(icon, item) -> None:
        _action_queue.put("status")

    def on_open_docs(icon, item) -> None:
        c = config_store.get()
        webbrowser.open(f"http://{c.host}:{c.port}/api/v1/docs")

    def on_open_logs(icon, item) -> None:
        try:
            os.startfile(str(logs_dir()))  # type: ignore[attr-defined]
        except Exception:
            log.info("Logs: %s", logs_dir())

    def on_clear_pin(icon, item) -> None:
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

    def on_quit(icon, item) -> None:
        global _shutdown_requested
        _shutdown_requested = True
        if _update_service:
            _update_service.stop()
        with _pin_cache._lock:
            _pin_cache._data.clear()
        icon.stop()
        _action_queue.put("quit")

    def on_check_updates(icon, item) -> None:
        if _update_service:
            _update_service.check_now()
            result = _update_service.last_result
            if result:
                if result.result == UpdateResult.UPDATE_AVAILABLE:
                    _show_update_available(result)
                elif result.result == UpdateResult.NO_UPDATE:
                    _show_update_none()
                else:
                    _show_update_error(result)
        else:
            log.warning("UpdateService not available")

    def _update_callback(result: CheckResult) -> None:
        if result.result == UpdateResult.UPDATE_AVAILABLE:
            _show_update_available(result)

    def _show_update_available(result: CheckResult) -> None:
        ver = result.manifest.get("version", "?") if result.manifest else "?"
        log.info("Update available: v%s", ver)

    def _show_update_none() -> None:
        log.info("No updates available")

    def _show_update_error(result: CheckResult) -> None:
        log.warning("Update check failed: %s", result.detail)

    _update_service = UpdateService()
    _update_service.set_callbacks(on_update_available=_update_callback)
    _update_service.start()

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
            pystray.MenuItem("Buscar actualizaciones", on_check_updates),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Limpiar PIN cacheado", on_clear_pin),
            pystray.MenuItem("Revocar origen", on_revoke),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Salir", on_quit),
        ),
    )
    # El icono vive en su propio hilo; Tkinter conserva el hilo principal.
    icon.run_detached()

    root.after(100, _poll_actions)
    try:
        root.mainloop()
    finally:
        # Apagado ordenado si se sale por otra via (p.ej. consola de errores).
        _shutdown_requested = True
        if _update_service:
            _update_service.stop()
        try:
            icon.stop()
        except Exception:
            pass
    return 0


def main() -> int:
    try:
        import pystray  # type: ignore  # noqa: F401
        from PIL import Image  # type: ignore  # noqa: F401
        import tkinter  # noqa: F401
        return _tray_loop()
    except Exception as exc:
        log.info("Tray no disponible (%s), arrancando en consola.", exc)
        _console_loop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
