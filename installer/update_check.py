"""Update checker with digital signature verification.

Protocol: server publishes ``manifest.json`` and ``manifest.json.sig``.
The signature covers the exact UTF-8 bytes of ``manifest.json`` using
RSA-PSS-SHA256. The public key is embedded at build time.

Manifest schema v1::

    {
      "schema": 1,
      "channel": "stable",
      "version": "1.0.1",
      "url": "https://updates.example.com/GadSignLocalAPI-1.0.1-setup.exe",
      "sha256": "<64-char hex>",
      "size": 73400320,
      "published_at": "2026-08-04T15:00:00Z",
      "expires_at": "2026-08-11T15:00:00Z"
    }
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

DEFAULT_PUBLIC_KEY_PEM: bytes = (
    b"-----BEGIN PUBLIC KEY-----\n"
    b"REPLACE_WITH_REAL_PUBLIC_KEY\n"
    b"-----END PUBLIC KEY-----\n"
)

MAX_MANIFEST_BYTES = 65536
MAX_DOWNLOAD_MB = 256
DOWNLOAD_CHUNK = 65536
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_DOWNLOAD_HOSTS: tuple[str, ...] = ("updates.example.com",)

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class UpdateResult(Enum):
    NO_UPDATE = auto()
    UPDATE_AVAILABLE = auto()
    NETWORK_ERROR = auto()
    MANIFEST_INVALID = auto()
    SIGNATURE_INVALID = auto()
    DOWNLOAD_INVALID = auto()
    DISK_FULL = auto()
    INSTALLER_LAUNCH_FAILED = auto()


@dataclass
class CheckResult:
    result: UpdateResult
    manifest: Optional[dict] = None
    detail: str = ""


# ---------------------------------------------------------------------------
# SemVer
# ---------------------------------------------------------------------------


_SEMVER_RE = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+(?P<metadata>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


def _parse_semver(version: str) -> Optional[tuple[int, int, int, Optional[str]]]:
    m = _SEMVER_RE.match(version.strip())
    if not m:
        return None
    return (
        int(m.group("major")),
        int(m.group("minor")),
        int(m.group("patch")),
        m.group("prerelease"),
    )


def _compare_semver(a: str, b: str) -> int:
    pa = _parse_semver(a)
    pb = _parse_semver(b)
    if not pa or not pb:
        return 0
    for x, y in zip(pa[:3], pb[:3]):
        if x < y:
            return -1
        if x > y:
            return 1
    if pa[3] is None and pb[3] is not None:
        return 1
    if pa[3] is not None and pb[3] is None:
        return -1
    return 0


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def _verify_signature(
    payload: bytes, signature_b64: str, pubkey_pem: bytes
) -> bool:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        key = serialization.load_pem_public_key(pubkey_pem)
        sig = base64.b64decode(signature_b64, validate=True)
        key.verify(sig, payload, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ), hashes.SHA256())
        return True
    except Exception as exc:
        log.error("Manifest signature invalid: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Manifest fetching and validation
# ---------------------------------------------------------------------------


def _validate_manifest(
    manifest: dict, current_version: str, channel: str = "stable"
) -> Optional[str]:
    if not isinstance(manifest, dict):
        return "manifest is not a JSON object"
    schema = manifest.get("schema")
    if schema != 1:
        return f"unsupported schema: {schema}"
    if manifest.get("channel", "") != channel:
        return f"channel mismatch: expected={channel}"

    version = manifest.get("version", "")
    if not _parse_semver(version):
        return f"invalid semver: {version}"
    if channel == "stable" and _parse_semver(version) and _parse_semver(version)[3] is not None:
        return f"stable channel rejects prerelease: {version}"
    if _compare_semver(version, current_version) <= 0:
        return None

    sha256 = manifest.get("sha256", "")
    if not SHA256_RE.fullmatch(sha256):
        return f"invalid sha256: {sha256[:32]}..."

    url = manifest.get("url", "")
    if not url.startswith("https://"):
        return "url is not HTTPS"
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
        return f"host not in allowlist: {parsed.hostname}"

    size = manifest.get("size", 0)
    if isinstance(size, str):
        try:
            size = int(size)
        except ValueError:
            size = 0
    if not isinstance(size, int) or size <= 0:
        return f"invalid size: {size}"
    if size > MAX_DOWNLOAD_MB * 1024 * 1024:
        return f"size exceeds {MAX_DOWNLOAD_MB} MB"

    try:
        published = manifest.get("published_at", "")
        expires = manifest.get("expires_at", "")
        if published:
            datetime.fromisoformat(published.strip("Z"))
        if expires:
            expire_dt = datetime.fromisoformat(expires.strip("Z"))
            expire_dt = expire_dt.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expire_dt:
                return f"manifest expired at {expires}"
    except Exception as exc:
        return f"invalid date: {exc}"

    return None


def fetch_manifest(
    manifest_url: str,
    current_version: str,
    pubkey_pem: bytes = DEFAULT_PUBLIC_KEY_PEM,
    channel: str = "stable",
    timeout: int = 15,
) -> CheckResult:
    try:
        import requests
    except Exception:
        return CheckResult(UpdateResult.NETWORK_ERROR, detail="requests not available")

    if not manifest_url.startswith("https://"):
        return CheckResult(UpdateResult.MANIFEST_INVALID, detail="manifest_url must be HTTPS")

    # Fetch manifest.json
    try:
        r = requests.get(manifest_url, timeout=timeout, allow_redirects=False)
        r.raise_for_status()
        manifest_bytes = r.content
    except Exception as exc:
        log.error("Cannot fetch manifest: %s", exc)
        return CheckResult(UpdateResult.NETWORK_ERROR, detail=str(exc)[:200])

    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        return CheckResult(UpdateResult.MANIFEST_INVALID, detail="manifest too large")

    # Fetch manifest.json.sig
    sig_url = manifest_url.removesuffix(".json") + ".json.sig"
    try:
        r = requests.get(sig_url, timeout=timeout, allow_redirects=False)
        r.raise_for_status()
        sig_b64 = r.text.strip()
    except Exception as exc:
        log.error("Cannot fetch manifest signature: %s", exc)
        return CheckResult(UpdateResult.SIGNATURE_INVALID, detail=str(exc)[:200])

    if not _verify_signature(manifest_bytes, sig_b64, pubkey_pem):
        return CheckResult(UpdateResult.SIGNATURE_INVALID)

    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except Exception as exc:
        return CheckResult(UpdateResult.MANIFEST_INVALID, detail=f"invalid JSON: {exc}")

    error = _validate_manifest(manifest, current_version, channel)
    if error is not None:
        return CheckResult(UpdateResult.MANIFEST_INVALID, detail=error)

    version = manifest["version"]
    if _compare_semver(version, current_version) <= 0:
        return CheckResult(UpdateResult.NO_UPDATE)

    return CheckResult(UpdateResult.UPDATE_AVAILABLE, manifest=manifest)


# ---------------------------------------------------------------------------
# Secure download
# ---------------------------------------------------------------------------


def download_installer(manifest: dict, updates_dir: Path, timeout: int = 300) -> CheckResult:
    try:
        import requests
    except Exception:
        return CheckResult(UpdateResult.DOWNLOAD_INVALID, detail="requests not available")

    expected_sha256 = manifest.get("sha256", "").lower()
    expected_size = manifest.get("size", 0)
    if isinstance(expected_size, str):
        try:
            expected_size = int(expected_size)
        except ValueError:
            expected_size = 0

    updates_dir.mkdir(parents=True, exist_ok=True)
    rand = uuid.uuid4().hex[:8]
    part_path = updates_dir / f"{rand}.exe.part"
    final_path = updates_dir / f"GadSignLocalAPI-{manifest['version']}-setup.exe"

    if final_path.exists():
        actual = _sha256_file(final_path)
        if actual.lower() == expected_sha256:
            log.info("Installer already downloaded: %s", final_path)
            return CheckResult(UpdateResult.UPDATE_AVAILABLE, manifest=manifest)
        final_path.unlink()

    if part_path.exists():
        part_path.unlink()

    try:
        hasher = hashlib.sha256()
        downloaded = 0
        with requests.get(manifest["url"], stream=True, timeout=timeout) as r:
            r.raise_for_status()
            content_length = r.headers.get("Content-Length")
            if content_length:
                cl = int(content_length)
                if expected_size and cl != expected_size:
                    return CheckResult(
                        UpdateResult.DOWNLOAD_INVALID,
                        detail=f"Content-Length mismatch: {cl} != {expected_size}",
                    )

            with open(part_path, "xb") as f:
                for chunk in r.iter_content(chunk_size=DOWNLOAD_CHUNK):
                    if not chunk:
                        continue
                    f.write(chunk)
                    hasher.update(chunk)
                    downloaded += len(chunk)
                    if downloaded > MAX_DOWNLOAD_MB * 1024 * 1024:
                        part_path.unlink()
                        return CheckResult(UpdateResult.DOWNLOAD_INVALID, detail="size limit exceeded")

        actual_sha256 = hasher.hexdigest()
        if actual_sha256.lower() != expected_sha256:
            part_path.unlink()
            return CheckResult(
                UpdateResult.DOWNLOAD_INVALID,
                detail=f"SHA-256 mismatch: {actual_sha256[:16]}... != {expected_sha256[:16]}...",
            )

        if expected_size and downloaded != expected_size:
            part_path.unlink()
            return CheckResult(
                UpdateResult.DOWNLOAD_INVALID,
                detail=f"size mismatch: {downloaded} != {expected_size}",
            )

        os.replace(part_path, final_path)
        log.info("Downloaded and verified: %s", final_path)
        return CheckResult(UpdateResult.UPDATE_AVAILABLE, manifest=manifest)

    except OSError as exc:
        if "No space" in str(exc) or "disk full" in str(exc).lower():
            if part_path.exists():
                part_path.unlink()
            return CheckResult(UpdateResult.DISK_FULL, detail=str(exc)[:200])
        return CheckResult(UpdateResult.DOWNLOAD_INVALID, detail=str(exc)[:200])
    except Exception as exc:
        if part_path.exists():
            part_path.unlink()
        log.error("Download failed: %s", exc)
        return CheckResult(UpdateResult.DOWNLOAD_INVALID, detail=str(exc)[:200])


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(DOWNLOAD_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()
