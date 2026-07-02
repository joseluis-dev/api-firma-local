"""Limpia el cache de PIN cuando Windows bloquea o suspende la sesion.

Usa ``WTSRegisterSessionNotification`` para recibir mensajes
``WM_WTSSESSION_CHANGE`` con ``WTS_SESSION_LOCK`` y
``WTS_SESSION_REMOTE_DISCONNECT``.

Si no estamos en Windows, no hace nada.

Se arranca en un hilo daemon al iniciar la API.
"""
from __future__ import annotations

import logging
import threading
from typing import Optional

from ..token_service import _pin_cache


log = logging.getLogger(__name__)


def _is_windows() -> bool:
    import sys
    return sys.platform == "win32"


def start_session_lock_watcher(window_title: str = "GadSignLocalAPISessionWatcher") -> Optional[threading.Thread]:
    """Inicia un watcher que limpia el cache de PIN al bloquear la sesion."""
    if not _is_windows():
        return None

    try:
        import ctypes
        from ctypes import wintypes
    except Exception as exc:
        log.debug("ctypes no disponible: %s", exc)
        return None

    try:
        import tkinter as tk
    except Exception as exc:
        log.debug("tkinter no disponible: %s", exc)
        return None

    WM_WTSSESSION_CHANGE = 0x02B1
    WTS_SESSION_LOCK = 0x7
    WTS_SESSION_UNLOCK = 0x8

    NOTIFY_FOR_THIS_SESSION = 0x0
    WM_DESTROY = 0x0002

    user32 = ctypes.windll.user32  # type: ignore[attr-defined]
    user32.RegisterClassW.restype = wintypes.ATOM
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.DefWindowProcW.restype = ctypes.c_long

    def wnd_proc(hwnd, msg, wparam, lparam):
        if msg == WM_WTSSESSION_CHANGE:
            if wparam in (WTS_SESSION_LOCK, WTS_SESSION_REMOTE_DISCONNECT := 4):
                with _pin_cache._lock:  # type: ignore[attr-defined]
                    _pin_cache._data.clear()  # type: ignore[attr-defined]
                log.info("PIN cache limpiado por bloqueo/desconexion de sesion.")
        elif msg == WM_DESTROY:
            user32.PostQuitMessage(0)
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_long, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
    wnd_proc_ref = WNDPROC(wnd_proc)

    hInst = ctypes.windll.kernel32.GetModuleHandleW(None)  # type: ignore[attr-defined]

    class WNDCLASS(ctypes.Structure):
        _fields_ = [
            ("style", ctypes.c_uint),
            ("lpfnWndProc", WNDPROC),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", wintypes.HINSTANCE),
            ("hIcon", wintypes.HICON),
            ("hCursor", wintypes.HANDLE),
            ("hbrBackground", wintypes.HBRUSH),
            ("lpszMenuName", wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
        ]

    wc = WNDCLASS()
    wc.lpfnWndProc = wnd_proc_ref
    wc.hInstance = hInst
    wc.lpszClassName = window_title
    if not user32.RegisterClassW(ctypes.byref(wc)):
        log.debug("RegisterClass fallo, ya registrada o no disponible.")
        return None

    HWND_MESSAGE = -3
    hwnd = user32.CreateWindowExW(
        0, window_title, window_title, 0,
        0, 0, 0, 0, HWND_MESSAGE, None, hInst, None,
    )
    if not hwnd:
        log.debug("CreateWindowExW fallo.")
        return None

    if not user32.WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION):
        log.debug("WTSRegisterSessionNotification fallo.")

    def loop():
        msg = ctypes.wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        user32.WTSUnRegisterSessionNotification(hwnd)
        user32.DestroyWindow(hwnd)

    t = threading.Thread(target=loop, daemon=True, name="session-lock-watcher")
    t.start()
    log.info("Watcher de bloqueo de sesion iniciado.")
    return t
