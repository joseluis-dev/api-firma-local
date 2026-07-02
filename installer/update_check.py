"""Update checker con firma digital.

Firma esperada: el servidor publica ``updates/manifest.json`` con:

    {
      "version": "1.0.1",
      "url": "https://updates.example.com/GadSignLocalAPI-1.0.1-setup.exe",
      "sha256": "<hex>",
      "signature": "<base64 RSA-SHA256 del manifest firmado por la clave publica>"
    }

La aplicacion verifica la firma con la clave publica incrustada y
descarga solo si la version es mayor a la actual.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Optional


log = logging.getLogger(__name__)


# Clave publica RSA en PEM (sustituir con la real al publicar)
DEFAULT_PUBLIC_KEY_PEM = b"""
-----BEGIN PUBLIC KEY-----
REEMPLAZAR_CON_CLAVE_PUBLICA_REAL
-----END PUBLIC KEY-----
"""


def _verify_signature(payload: bytes, signature_b64: str, pubkey_pem: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except Exception as exc:
        log.error("cryptography no disponible: %s", exc)
        return False
    try:
        key = serialization.load_pem_public_key(pubkey_pem)
        sig = base64.b64decode(signature_b64)
        key.verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[attr-defined]
        return True
    except Exception as exc:
        log.error("Firma de update invalida: %s", exc)
        return False


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_and_verify(
    manifest_url: str,
    current_version: str,
    pubkey_pem: bytes = DEFAULT_PUBLIC_KEY_PEM,
    timeout: int = 15,
) -> Optional[dict]:
    """Devuelve el manifest verificado si hay una version mayor.

    Requiere ``requests``.
    """
    try:
        import requests
    except Exception:
        log.error("requests no disponible.")
        return None
    try:
        r = requests.get(manifest_url, timeout=timeout)
        r.raise_for_status()
        manifest_bytes = r.content
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except Exception as exc:
        log.error("No se pudo obtener manifest: %s", exc)
        return None

    sig = manifest.get("signature", "")
    payload = json.dumps(
        {k: v for k, v in manifest.items() if k != "signature"},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    if not _verify_signature(payload, sig, pubkey_pem):
        log.error("Manifest con firma invalida, se descarta.")
        return None

    new_v = manifest.get("version", "0.0.0")
    if _compare_versions(new_v, current_version) <= 0:
        return None
    return manifest


def _compare_versions(a: str, b: str) -> int:
    pa = [int(x) for x in a.split(".") if x.isdigit()]
    pb = [int(x) for x in b.split(".") if x.isdigit()]
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    for x, y in zip(pa, pb):
        if x < y:
            return -1
        if x > y:
            return 1
    return 0


def download_and_verify(
    manifest: dict, target_path: Path, timeout: int = 60
) -> bool:
    try:
        import requests
    except Exception:
        return False
    expected = manifest.get("sha256", "").lower()
    try:
        with requests.get(manifest["url"], stream=True, timeout=timeout) as r:
            r.raise_for_status()
            h = hashlib.sha256()
            with open(target_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    f.write(chunk)
                    h.update(chunk)
    except Exception as exc:
        log.error("Descarga fallo: %s", exc)
        return False
    actual = h.hexdigest()
    if actual.lower() != expected:
        log.error("SHA-256 no coincide: esperado=%s real=%s", expected, actual)
        try:
            target_path.unlink()
        except Exception:
            pass
        return False
    return True
