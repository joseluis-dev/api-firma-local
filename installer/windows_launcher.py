"""Windows entrypoint for the packaged GadSign Local API application."""
from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import IO


_ERROR_ALREADY_EXISTS = 183
_MUTEX_NAME = "Local\\GadSignLocalAPI"
_mutex_handle: int | None = None
_log_stream: IO[str] | None = None


def _data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "GadSign" / "LocalAPI"


def _redirect_stdio_for_windowed() -> None:
    """Ensure windowed PyInstaller builds still have a log sink."""
    global _log_stream
    if sys.stdout is not None and sys.stderr is not None:
        return
    log_dir = _data_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    _log_stream = (log_dir / "GadSignLocalAPI.log").open(
        "a", encoding="utf-8", buffering=1
    )
    sys.stdout = _log_stream
    sys.stderr = _log_stream


def _acquire_single_instance() -> bool:
    """Prevent duplicate tray/API processes in the same Windows session."""
    global _mutex_handle
    if os.name != "nt":
        return True
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.CreateMutexW(None, False, _MUTEX_NAME)
    if not handle:
        return True
    _mutex_handle = handle
    return ctypes.get_last_error() != _ERROR_ALREADY_EXISTS


def main() -> int:
    _redirect_stdio_for_windowed()
    if not _acquire_single_instance():
        return 0

    from localapi.scripts.tray import main as tray_main

    return tray_main()


if __name__ == "__main__":
    sys.exit(main())
