"""FastAPI dependencies for pairing, nonce, origin, host validation."""
from __future__ import annotations

import logging
import threading
import time
from typing import Dict, Optional

from fastapi import Request

from ...config import settings
from ..config_store import config_store
from ..errors import (
    AuthForbiddenError,
    AuthRequiredError,
    HostNotAllowedError,
    LocalApiError,
    OriginNotAllowedError,
    ReplayDetectedError,
    TokenExpiredError,
    TokenRevokedError,
)
from .pairing import PairingToken, pairing_manager


log = logging.getLogger(__name__)


# Endpoints publicos (no requieren bearer ni replay).
PUBLIC_PATHS = {
    "/",
    "/api/v1/health",
    "/api/v1/pairing/request",
    "/api/v1/pairing/confirm",
    "/api/v1/pairing/status",
    "/api/v1/openapi.json",
    "/api/v1/docs",
    "/api/v1/docs/oauth2-redirect",
    "/favicon.ico",
}


# Host permitidos en el header Host.
_ALLOWED_HOSTS = {"127.0.0.1:44113", "localhost:44113", "127.0.0.1", "localhost"}


def _is_loopback_client(request: Request) -> bool:
    if not request.client:
        return False
    h = request.client.host
    return h in {"127.0.0.1", "::1", "localhost"}


def require_loopback(request: Request) -> None:
    if not _is_loopback_client(request):
        log.warning("Bloqueando request no-loopback: %s", request.client)
        raise LocalApiError(
            "API local solo acepta conexiones loopback.",
            status_code=403,
        )


def require_host(request: Request) -> None:
    host = request.headers.get("host", "")
    if host and host not in _ALLOWED_HOSTS:
        log.warning("Host no permitido: %s", host)
        raise HostNotAllowedError(f"Host {host!r} no permitido.")


def origin_matches_allowed(request: Request) -> bool:
    cfg = config_store.get()
    origin = (request.headers.get("origin") or "").strip().rstrip("/")
    if not origin:
        # Misma-origen (frontend servido desde 127.0.0.1:44113) o curl local.
        return True
    allowed = [o.strip().rstrip("/").lower() for o in cfg.effective_allowed_origins()]
    return origin.lower() in allowed


def extract_bearer(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if not auth:
        return None
    parts = auth.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def require_bearer(request: Request, scope: str) -> Optional[PairingToken]:
    """Valida Authorization: Bearer y devuelve el PairingToken.

    Si ``require_pairing`` esta desactivado en la configuracion, devuelve
    ``None`` (modo compatibilidad) y no falla.

    Levanta errores semanticos:
        - ``AuthRequiredError``    si no hay token
        - ``AuthForbiddenError``   si la firma es invalida
        - ``TokenExpiredError``    si el token expiro
        - ``TokenRevokedError``    si el token fue revocado
        - ``OriginNotAllowedError`` si el Origin no coincide con el token
    """
    cfg = config_store.get()
    if not cfg.require_pairing:
        return None
    token = extract_bearer(request)
    if not token:
        raise AuthRequiredError(
            "Token local requerido. Empareje el origen primero con "
            "POST /api/v1/pairing/request."
        )
    ok, err, tok, code = pairing_manager.validate_bearer_detailed(token, scope)
    if not ok:
        log.info("Bearer invalido: %s", err)
        if code == "expired":
            raise TokenExpiredError(err or "Token expirado.")
        if code == "revoked":
            raise TokenRevokedError(err or "Token revocado.")
        if code == "scope":
            raise AuthForbiddenError(err or "Scope insuficiente.")
        if code == "unknown_token":
            # Token bien firmado pero no persistido localmente: rechazar.
            raise AuthRequiredError(
                "Token no reconocido por esta instalacion. Empareje nuevamente."
            )
        raise AuthForbiddenError(err or "Bearer invalido.")
    if tok is not None and cfg.effective_allowed_origins():
        origin = (request.headers.get("origin") or "").strip().rstrip("/")
        if origin and origin.lower() != tok.origin.lower():
            log.warning(
                "Origin %s no coincide con token de %s",
                origin, tok.origin,
            )
            raise OriginNotAllowedError(
                "El Origin no coincide con el token emparejado."
            )
    return tok


# ---------------------------------------------------------------------------
# Replay protection: timestamp + nonce.
# ---------------------------------------------------------------------------


_MAX_SKEW_SECONDS = 300  # +-5 min
_NONCE_TTL_SECONDS = 600  # 10 min
_known_nonces: Dict[str, float] = {}
_nonces_lock = threading.Lock()


def _purge_nonces_locked() -> None:
    cutoff = time.time() - _NONCE_TTL_SECONDS
    for k in list(_known_nonces.keys()):
        if _known_nonces[k] < cutoff:
            _known_nonces.pop(k, None)


def check_replay_headers(request: Request, required: bool = False) -> None:
    """Valida X-LocalAPI-Timestamp y X-LocalAPI-Request-Id.

    Si ``required`` es True (endpoints protegidos) lanza 400 si faltan
    headers. Si es False (publicos) los valida solo si vienen.
    """
    ts_str = request.headers.get("x-localapi-timestamp")
    nonce = request.headers.get("x-localapi-request-id")
    if not ts_str or not nonce:
        if required:
            raise LocalApiError(
                "Faltan cabeceras X-LocalAPI-Timestamp y X-LocalAPI-Request-Id.",
                status_code=400,
            )
        return  # opcional para endpoints no protegidos
    try:
        ts = int(ts_str)
    except ValueError:
        raise LocalApiError("X-LocalAPI-Timestamp invalido.", status_code=400)
    now = int(time.time())
    if abs(now - ts) > _MAX_SKEW_SECONDS:
        raise AuthForbiddenError(
            "Timestamp fuera de la ventana permitida."
        )
    if not nonce or len(nonce) < 8 or len(nonce) > 128:
        raise LocalApiError(
            "X-LocalAPI-Request-Id invalido.", status_code=400
        )
    with _nonces_lock:
        _purge_nonces_locked()
        if nonce in _known_nonces:
            raise ReplayDetectedError(
                "requestId ya utilizado (posible replay)."
            )
        _known_nonces[nonce] = time.time()
