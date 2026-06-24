"""Utilidades criptograficas de bajo nivel (hash, base64, validacion PDF)."""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from datetime import datetime, timezone
from typing import Tuple


_PDF_MAGIC = b"%PDF-"
_CEDULA_RE = re.compile(r"\d{6,15}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_base64(value: str) -> bytes:
    value = value.strip().replace("\n", "").replace("\r", "")
    if not value:
        raise ValueError("Base64 vacio.")
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise ValueError(f"Base64 invalido: {exc}") from exc


def encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def is_pdf(data: bytes) -> bool:
    if not data or len(data) < 5:
        return False
    return data[:5] == _PDF_MAGIC


def normalize_cedula(value: str | None) -> str:
    if not value:
        return ""
    digits = re.sub(r"\D", "", value)
    return digits


def extract_cedula_from_subject(subject: str) -> str:
    """Extrae una cedula (secuencia 6-15 digitos) del CN del subject."""
    if not subject:
        return ""
    match = _CEDULA_RE.search(subject)
    return match.group(0) if match else ""


def parse_iso(value: str) -> datetime:
    if isinstance(value, datetime):
        return value
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def to_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
