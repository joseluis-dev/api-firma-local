"""User data dir + paths for runtime config, pairing and logs.

Windows: %LOCALAPPDATA%\\GadSign\\LocalAPI\\
Linux:   $XDG_DATA_HOME/gadsign/localapi or ~/.local/share/gadsign/localapi
macOS:   ~/Library/Application Support/GadSign/LocalAPI

Config y pairing se almacenan en archivos JSON. El estado sensible
(PIN) NUNCA se persiste: vive solo en memoria y se borra al cerrar.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional


APP_DIR_NAME = "GadSign"
APP_NAME = "LocalAPI"


def _platform_data_root() -> Path:
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_DIR_NAME / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_DIR_NAME / APP_NAME
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / APP_DIR_NAME / APP_NAME


def user_data_dir(override: Optional[str] = None) -> Path:
    """Returns user data dir, creating it if missing."""
    if override:
        p = Path(override)
    else:
        env = os.environ.get("LOCALAPI_DATA_DIR")
        p = _platform_data_root() if not env else Path(env)
    p.mkdir(parents=True, exist_ok=True)
    return p


def config_path() -> Path:
    return user_data_dir() / "config.json"


def pairing_path() -> Path:
    return user_data_dir() / "pairing.json"


def logs_dir() -> Path:
    p = user_data_dir() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def pidfile_path() -> Path:
    return user_data_dir() / "localapi.pid"
