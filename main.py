"""Punto de entrada: levanta uvicorn en 127.0.0.1:44113.

Uso:
    python -m localapi.main
    python localapi/main.py
"""
from __future__ import annotations

import logging
import os
import sys

import uvicorn

from .app import app
from .config import settings
from .core.security.session_watcher import start_session_lock_watcher
from .core.user_paths import user_data_dir


log = logging.getLogger("localapi.main")


def main() -> int:
    data_dir = user_data_dir()
    log.info(
        "Iniciando localapi en %s:%s (data_dir=%s, log_level=%s)",
        settings.host,
        settings.port,
        data_dir,
        settings.log_level,
    )
    start_session_lock_watcher()
    uvicorn.run(
        "localapi.app:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        access_log=False,
        server_header=False,
        date_header=False,
        reload=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
