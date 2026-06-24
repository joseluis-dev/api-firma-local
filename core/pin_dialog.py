"""Dialogo nativo de PIN multiplataforma.

Nunca envia el PIN al navegador. Se muestra en una ventana propia
del sistema operativo. Si la GUI no esta disponible (servicio sin
display) cae a entrada por consola.
"""
from __future__ import annotations

import logging
import threading
from typing import Optional

from .errors import UserCancelledError


log = logging.getLogger(__name__)


def _tkinter_dialog(title: str, prompt: str) -> Optional[str]:
    import tkinter as tk
    from tkinter import simpledialog

    result: dict = {"value": None}

    def worker() -> None:
        try:
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            value = simpledialog.askstring(title, prompt, show="*", parent=root)
            result["value"] = value
            root.destroy()
        except Exception as exc:  # pragma: no cover - entorno sin GUI
            log.warning("PIN dialog tkinter no disponible: %s", exc)
            result["value"] = None

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join()
    return result["value"]


def _console_dialog(prompt: str) -> Optional[str]:
    try:
        import getpass

        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        return None


def ask_pin(token_label: str = "Token") -> str:
    """Muestra dialogo nativo y devuelve el PIN.

    Lanza ``UserCancelledError`` si el usuario cancela.
    """
    title = "Firma digital - Token"
    prompt = f"Ingrese el PIN del {token_label}:"

    try:
        value = _tkinter_dialog(title, prompt)
        if value is None:
            value = _console_dialog(prompt)
    except Exception as exc:  # pragma: no cover
        log.warning("PIN dialog fallo, usando consola: %s", exc)
        value = _console_dialog(prompt)

    if value is None or value == "":
        raise UserCancelledError("El usuario cancelo la captura de PIN.")
    return value
