"""Punto de entrada: levanta uvicorn en 127.0.0.1:44113.

Uso:
    python -m localapi.main
    o
    python localapi/main.py
"""
from __future__ import annotations

import logging
import sys

import uvicorn

from .app import app
from .config import settings


log = logging.getLogger("localapi.main")


def main() -> int:
    log.info(
        "Iniciando localapi en %s:%s (log_level=%s)",
        settings.host,
        settings.port,
        settings.log_level,
    )
    uvicorn.run(
        "localapi.app:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        access_log=False,  # no loguear el body
        server_header=False,
        date_header=False,
        reload=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
