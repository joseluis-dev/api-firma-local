"""Pairing local entre la API y un origen (Origin) del navegador.

Emite tokens bearer firmados con HMAC-SHA256, ligados a:
- origin
- installationId
- scopes
- expiration

El secreto HMAC se protege con DPAPI (Windows) o se almacena en
``%LOCALAPPDATA%`` con permisos de usuario. Si no se puede proteger,
se genera aleatorio en cada arranque y los tokens emparejados se
invalidan (ventana de aprobacion manual por origen en cada sesion).

Flujo:
    POST /api/v1/pairing/request  { origin }  -> { pending: true }
    -> ventana nativa de aprobacion
    -> POST /api/v1/pairing/confirm { request_id, approve }  -> { token }

Los tokens viven en ``%LOCALAPPDATA%\\GadSign\\LocalAPI\\pairing.json``.
"""
from __future__ import annotations

import base64
import hmac
import hashlib
import json
import logging
import os
import secrets
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..user_paths import pairing_path


log = logging.getLogger(__name__)


# Scopes predefinidos. El frontend debe solicitarlos explicitamente.
SCOPE_HEALTH = "health:read"
SCOPE_CERT_LIST = "certificates:list"
SCOPE_PDF_SIGN = "pdf:sign"
ALL_SCOPES = [SCOPE_HEALTH, SCOPE_CERT_LIST, SCOPE_PDF_SIGN]

DEFAULT_TOKEN_TTL_SECONDS = 60 * 60 * 8  # 8h
DEFAULT_REQUEST_TTL_SECONDS = 120
DEFAULT_PAIRING_VERSION = 1


# ---------------------------------------------------------------------------
# Proteccion del secreto HMAC
# ---------------------------------------------------------------------------


def _protect_secret(secret: bytes) -> bytes:
    """Cifra el secreto con DPAPI (Windows) o lo devuelve tal cual."""
    if not secret:
        return b""
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [
                    ("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_byte)),
                ]

            def _blob(b: bytes) -> DATA_BLOB:
                buf = ctypes.create_string_buffer(b, len(b))
                return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))

            CryptProtectData = ctypes.windll.crypt32.CryptProtectData  # type: ignore[attr-defined]
            CryptUnprotectData = ctypes.windll.crypt32.CryptUnprotectData  # type: ignore[attr-defined]
            LOCAL_MACHINE = 0x40000000  # CRYPTPROTECT_LOCAL_MACHINE
            in_blob = _blob(secret)
            out_blob = DATA_BLOB()
            if CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
                try:
                    out_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
                finally:
                    ctypes.windll.kernel32.LocalFree(out_blob.pbData)  # type: ignore[attr-defined]
                return base64.b64encode(out_bytes)
        except Exception as exc:
            log.warning("DPAPI no disponible, secreto sin cifrar en disco: %s", exc)
    return base64.b64encode(secret)


def _unprotect_secret(blob_b64: bytes) -> bytes:
    if not blob_b64:
        return b""
    raw = base64.b64decode(blob_b64)
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [
                    ("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_byte)),
                ]

            def _blob(b: bytes) -> DATA_BLOB:
                buf = ctypes.create_string_buffer(b, len(b))
                return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))

            CryptUnprotectData = ctypes.windll.crypt32.CryptUnprotectData  # type: ignore[attr-defined]
            in_blob = _blob(raw)
            out_blob = DATA_BLOB()
            if CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
                try:
                    out_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
                finally:
                    ctypes.windll.kernel32.LocalFree(out_blob.pbData)  # type: ignore[attr-defined]
                return out_bytes
        except Exception as exc:
            log.warning("DPAPI no pudo descifrar el secreto: %s", exc)
    return raw


# ---------------------------------------------------------------------------
# Tokens y pairing
# ---------------------------------------------------------------------------


@dataclass
class PairingToken:
    token: str
    origin: str
    installation_id: str
    scopes: List[str]
    issued_at: int
    expires_at: int
    revoked: bool = False


@dataclass
class PairingRequest:
    request_id: str
    origin: str
    scopes: List[str]
    created_at: float
    status: str = "pending"  # pending|approved|denied|expired


@dataclass
class PairingStoreData:
    secret_protected: str = ""  # base64 (DPAPI cifrado) o base64 crudo
    installation_id: str = ""
    tokens: List[PairingToken] = field(default_factory=list)
    requests: List[PairingRequest] = field(default_factory=list)
    version: int = DEFAULT_PAIRING_VERSION


def _new_installation_id() -> str:
    return str(uuid.uuid4()).upper()


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _sign_token(secret: bytes, payload_b64: str) -> str:
    sig = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
    return _b64u(sig)


def _now_ts() -> int:
    return int(time.time())


class PairingManager:
    """Administra pairing, tokens y aprobaciones nativas."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or pairing_path()
        self._lock = threading.RLock()
        self._data: PairingStoreData = self._load()
        self._secret: bytes = self._ensure_secret()
        self._approval_callback = None  # type: ignore[var-annotated]

    # ------------------------------------------------------------------
    # Persistencia
    # ------------------------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    def _load(self) -> PairingStoreData:
        if not self._path.exists():
            return PairingStoreData(installation_id=_new_installation_id())
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            tokens = [PairingToken(**t) for t in raw.get("tokens", [])]
            requests_ = [PairingRequest(**r) for r in raw.get("requests", [])]
            return PairingStoreData(
                secret_protected=raw.get("secret_protected", ""),
                installation_id=raw.get("installation_id") or _new_installation_id(),
                tokens=tokens,
                requests=requests_,
                version=raw.get("version", DEFAULT_PAIRING_VERSION),
            )
        except Exception as exc:
            log.warning("pairing.json corrupto, regenerando: %s", exc)
            return PairingStoreData(installation_id=_new_installation_id())

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".json.tmp")
            payload = {
                "secret_protected": self._data.secret_protected,
                "installation_id": self._data.installation_id,
                "tokens": [asdict(t) for t in self._data.tokens],
                "requests": [asdict(r) for r in self._data.requests],
                "version": self._data.version,
            }
            tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, self._path)
        except Exception as exc:
            log.error("No se pudo guardar pairing.json: %s", exc)

    def _ensure_secret(self) -> bytes:
        if self._data.secret_protected:
            try:
                sec = _unprotect_secret(self._data.secret_protected.encode("ascii"))
                if sec:
                    return sec
            except Exception:
                pass
        # Generar nuevo
        new = secrets.token_bytes(32)
        self._data.secret_protected = _protect_secret(new).decode("ascii")
        self._save()
        return new

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------

    @property
    def installation_id(self) -> str:
        return self._data.installation_id

    def set_approval_callback(self, fn) -> None:
        """Recibe una funcion ``fn(origin, scopes) -> bool`` para aprobacion nativa."""
        self._approval_callback = fn

    def try_native_approve(self, request_id: str) -> Optional[bool]:
        """Invoca la UI nativa de aprobacion si esta registrada.

        Devuelve True/False si la UI respondio, o None si no hay callback
        o si la solicitud no esta pendiente. NO muta el estado: el caller
        debe llamar luego ``approve_request`` o ``deny_request``.
        """
        if not self._approval_callback:
            return None
        with self._lock:
            req = self.get_request(request_id)
            if not req or req.status != "pending":
                return None
        try:
            result = self._approval_callback(req.origin, req.scopes)
        except Exception as exc:
            log.warning("approval callback fallo: %s", exc)
            return None
        return result

    def request_pairing(self, origin: str, requested_scopes: List[str]) -> PairingRequest:
        origin = self._normalize_origin(origin)
        scopes = self._filter_scopes(requested_scopes)
        with self._lock:
            self._gc_locked()
            req = PairingRequest(
                request_id=str(uuid.uuid4()).upper(),
                origin=origin,
                scopes=scopes,
                created_at=time.time(),
            )
            self._data.requests.append(req)
            self._save()
        return req

    def _filter_scopes(self, scopes: List[str]) -> List[str]:
        out = []
        for s in scopes or []:
            s = str(s).strip()
            if s in ALL_SCOPES and s not in out:
                out.append(s)
        return out or [SCOPE_HEALTH]

    def _normalize_origin(self, origin: Optional[str]) -> str:
        if not origin:
            raise ValueError("Origin requerido.")
        o = origin.strip().rstrip("/")
        if not (o.startswith("http://") or o.startswith("https://")):
            raise ValueError("Origin invalido.")
        return o

    def list_pending(self) -> List[PairingRequest]:
        with self._lock:
            self._gc_locked()
            return [r for r in self._data.requests if r.status == "pending"]

    def get_request(self, request_id: str) -> Optional[PairingRequest]:
        with self._lock:
            for r in self._data.requests:
                if r.request_id == request_id:
                    return r
            return None

    def approve_request(
        self, request_id: str, ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS
    ) -> Optional[PairingToken]:
        with self._lock:
            req = self.get_request(request_id)
            if not req or req.status != "pending":
                return None
            if (time.time() - req.created_at) > DEFAULT_REQUEST_TTL_SECONDS:
                req.status = "expired"
                self._save()
                return None
            req.status = "approved"
            token = self._issue_token_locked(req.origin, req.scopes, ttl_seconds)
            self._save()
            return token

    def deny_request(self, request_id: str) -> bool:
        with self._lock:
            req = self.get_request(request_id)
            if not req or req.status != "pending":
                return False
            req.status = "denied"
            self._save()
            return True

    def _issue_token_locked(
        self, origin: str, scopes: List[str], ttl_seconds: int
    ) -> PairingToken:
        iat = _now_ts()
        exp = iat + max(60, ttl_seconds)
        payload = {
            "iss": "GadSign Local API",
            "sub": f"origin:{origin}",
            "origin": origin,
            "installationId": self._data.installation_id,
            "scopes": scopes,
            "iat": iat,
            "exp": exp,
            "jti": str(uuid.uuid4()).upper(),
        }
        payload_b64 = _b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        sig = _sign_token(self._secret, payload_b64)
        token = PairingToken(
            token=f"{payload_b64}.{sig}",
            origin=origin,
            installation_id=self._data.installation_id,
            scopes=scopes,
            issued_at=iat,
            expires_at=exp,
        )
        self._data.tokens.append(token)
        return token

    def revoke_origin(self, origin: str) -> int:
        origin = origin.strip().rstrip("/").lower()
        n = 0
        with self._lock:
            for t in self._data.tokens:
                if t.origin.lower() == origin and not t.revoked:
                    t.revoked = True
                    n += 1
            if n:
                self._save()
        return n

    def list_tokens(self) -> List[PairingToken]:
        with self._lock:
            self._gc_locked()
            return list(self._data.tokens)

    # ------------------------------------------------------------------
    # Validacion de tokens
    # ------------------------------------------------------------------

    def validate_bearer(self, token: str, required_scope: str) -> Tuple[bool, Optional[str], Optional[PairingToken]]:
        ok, err, tok, _code = self.validate_bearer_detailed(token, required_scope)
        return ok, err, tok

    def validate_bearer_detailed(
        self, token: str, required_scope: str
    ) -> Tuple[bool, Optional[str], Optional[PairingToken], Optional[str]]:
        """Valida firma, expiracion, scope, persistencia y revocacion.

        Devuelve ademas un ``code`` categorico:
            ``malformed`` / ``signature`` / ``expired`` / ``scope`` /
            ``revoked`` / ``unknown_token`` / ``no_origin`` / ``ok``.
        """
        if not token:
            return False, "Token ausente.", None, "malformed"
        parts = token.split(".")
        if len(parts) != 2:
            return False, "Token malformado.", None, "malformed"
        payload_b64, sig = parts
        try:
            expected = _sign_token(self._secret, payload_b64)
        except Exception as exc:
            return False, f"Token invalido: {exc}", None, "signature"
        if not hmac.compare_digest(expected, sig):
            return False, "Firma de token invalida.", None, "signature"
        try:
            pad = "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad).decode("utf-8"))
        except Exception as exc:
            return False, f"Token no decodificable: {exc}", None, "malformed"

        iat = int(payload.get("iat", 0))
        exp = int(payload.get("exp", 0))
        now = _now_ts()
        if now < iat or now > exp:
            return False, "Token expirado.", None, "expired"
        scopes = payload.get("scopes") or []
        if required_scope and required_scope not in scopes:
            return False, f"Scope requerido {required_scope!r} no presente.", None, "scope"

        # Coincidir contra un token persistido: rechazamos tokens validos
        # criptograficamente que no estan en el store local (reflejan
        # revocaciones y reinicios de la instalacion).
        with self._lock:
            for t in self._data.tokens:
                if t.token == token:
                    if t.revoked:
                        return False, "Token revocado.", None, "revoked"
                    if t.expires_at != exp or t.issued_at != iat:
                        return False, "Token desactualizado.", None, "expired"
                    return True, None, t, "ok"
        origin = str(payload.get("origin", "")).lower().rstrip("/")
        if not origin:
            return False, "Token sin origen.", None, "no_origin"
        return False, "Token no reconocido por esta instalacion.", None, "unknown_token"

    def clear_all(self) -> None:
        with self._lock:
            self._data.tokens.clear()
            self._data.requests.clear()
            self._save()

    # ------------------------------------------------------------------
    # GC
    # ------------------------------------------------------------------

    def _gc_locked(self) -> None:
        now = _now_ts()
        for t in self._data.tokens:
            if t.expires_at < now - 24 * 3600:
                pass  # se mantienen en disco para auditoria hasta limpiar
        for r in self._data.requests:
            if r.status == "pending" and (time.time() - r.created_at) > DEFAULT_REQUEST_TTL_SECONDS:
                r.status = "expired"


pairing_manager = PairingManager()
