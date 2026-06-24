"""Logging seguro: nunca loguea PIN, base64 ni certificados completos.

Se sustituyen los valores sensibles por `***` antes de emitir el registro.
"""
from __future__ import annotations

import logging
import re
import sys
from typing import Any, Iterable


# Patrones peligrosos que jamas deben quedar en logs
_SENSITIVE_KEYS = {
    "pin",
    "password",
    "clave",
    "documentobase64",
    "documentobase64",
    "documentofirmadobase64",
    "metadata",
    "metadatab64",
    "metadatabase64",
    "certificado",
    "certchain",
    "pkcs12",
    "p12",
    "pfx",
    "privatekey",
    "key",
}


def _is_sensitive(key: str | None) -> bool:
    if not key:
        return False
    k = key.lower()
    return any(s in k for s in _SENSITIVE_KEYS)


class SafeLogFormatter(logging.Formatter):
    """Formatter que redacta automaticamente valores sensibles."""

    def __init__(self, fmt: str | None = None) -> None:
        super().__init__(fmt or "%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        original = super().format(record)
        # Redacta posibles Base64 largos
        original = re.sub(r"\b[A-Za-z0-9+/]{120,}={0,2}\b", "<base64-redacted>", original)
        # Redacta hex de 64 chars (sha256)
        original = re.sub(r"\b[a-f0-9]{64}\b", "<sha256-redacted>", original)
        return original


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(SafeLogFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    # Reduce ruido de librerias
    for noisy in ("uvicorn.access", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def redact_mapping(data: Any) -> Any:
    if isinstance(data, dict):
        out: dict = {}
        for k, v in data.items():
            if _is_sensitive(k):
                out[k] = "***"
            else:
                out[k] = redact_mapping(v)
        return out
    if isinstance(data, (list, tuple)):
        return [redact_mapping(x) for x in data]
    return data
