"""Router FastAPI con los endpoints del contrato.

- GET  /api/v1/health
- POST /api/v1/pairing/request   (publico, requiere Origin)
- POST /api/v1/pairing/confirm   (publico)
- GET  /api/v1/pairing/status    (publico)
- POST /api/v1/certificados      (requiere Bearer)
- POST /api/v1/firmar/pdf        (requiere Bearer + confirmacion nativa)
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .. import __version__
from ..config import settings
from ..core.config_store import config_store
from ..core.errors import LocalApiError
from ..core.errors import (
    AuthRequiredError,
    OriginNotAllowedError,
    UserCancelledError,
)
from ..core.rate_limiter import RateLimiter
from ..core.schemas import (
    CertificadosRequest,
    CertificadosResponse,
    FirmarPdfRequest,
    FirmarPdfResponse,
    HealthResponse,
    HealthUnavailableResponse,
)
from ..core.security.confirmation import ask_signature_confirmation
from ..core.security.deps import (
    PUBLIC_PATHS,
    check_replay_headers,
    extract_bearer,
    origin_matches_allowed,
    require_bearer,
    require_loopback,
)
from ..core.security.pairing import (
    SCOPE_CERT_LIST,
    SCOPE_PDF_SIGN,
    pairing_manager,
)
from ..core.token_service import token_service


log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")
limiter = RateLimiter(max_requests=settings.rate_limit_per_minute, window_seconds=60)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _error_response(exc: LocalApiError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content=exc.to_dict())


def _internal_error_response(exc: Exception) -> JSONResponse:
    log.exception("Error interno no controlado: %s", exc)
    body = {
        "code": "INTERNAL_ERROR",
        "message": "Error interno de la API local.",
        "details": [str(exc)[:200]],
    }
    return JSONResponse(status_code=500, content=body)


def _check_rate(request: Request, endpoint: str) -> None:
    if not limiter.hit(_client_key(request), endpoint):
        raise LocalApiError(
            "Demasiadas solicitudes; intente mas tarde.",
            code="INVALID_INPUT",  # usamos INVALID_INPUT como 429
            status_code=429,
        )


def _log_request(request: Request, endpoint: str, body_summary: str = "") -> None:
    log.info(
        "REQ %s %s from=%s origin=%s ua=%s body=%s",
        request.method,
        endpoint,
        request.client.host if request.client else "?",
        request.headers.get("origin", "-"),
        request.headers.get("user-agent", "-")[:60],
        body_summary[:120],
    )


def _enforce_replay_protection(request: Request) -> None:
    if request.url.path in PUBLIC_PATHS:
        return
    check_replay_headers(request, required=True)


def _enforce_origin(request: Request) -> None:
    if request.url.path in PUBLIC_PATHS:
        return
    if not origin_matches_allowed(request):
        origin = request.headers.get("origin", "")
        log.warning("Origin no permitido: %s", origin)
        raise LocalApiError(
            f"Origen {origin!r} no permitido por la configuracion local.",
            status_code=403,
        )


def _bearer_for(scope: str):
    """FastAPI dependency factory que valida el bearer token."""
    def _dep(request: Request):
        return require_bearer(request, scope)
    return _dep


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@router.get("/health")
def health(request: Request):
    _check_rate(request, "/health")
    try:
        data = token_service.health(__version__)
        if data["status"] != "ok":
            return JSONResponse(
                status_code=503,
                content=HealthUnavailableResponse(
                    code="LOCAL_API_UNAVAILABLE",
                    message="No se detecto ningun driver compatible",
                ).model_dump(),
            )
        # /health siempre expone status/version/capabilities/installationId.
        # providers se reservan para clientes emparejados (info mas detallada).
        cfg = config_store.get()
        is_paired = bool(extract_bearer(request))
        providers = data["providers"] if (is_paired or not cfg.require_pairing) else []
        return HealthResponse(
            status=data["status"],
            version=data["version"],
            capabilities=data["capabilities"],
            providers=providers,
        )
    except LocalApiError as exc:
        return _error_response(exc)
    except Exception as exc:
        return _internal_error_response(exc)


# ---------------------------------------------------------------------------
# Pairing
# ---------------------------------------------------------------------------


class PairingRequestIn(BaseModel):
    origin: str
    scopes: list = Field(default_factory=list)


class PairingConfirmIn(BaseModel):
    requestId: str
    approve: bool


@router.post("/pairing/request")
def pairing_request(req: PairingRequestIn, request: Request):
    _check_rate(request, "/pairing/request")
    try:
        # Validar Origin contra la configuracion local.
        header_origin = (request.headers.get("origin") or "").strip().rstrip("/")
        if not header_origin:
            raise OriginNotAllowedError(
                "La peticion debe incluir el header Origin."
            )
        if not origin_matches_allowed(request):
            raise OriginNotAllowedError(
                f"Origen {header_origin!r} no permitido."
            )
        # El body.origin debe coincidir con el header Origin (normalizado).
        body_origin = (req.origin or "").strip().rstrip("/")
        if body_origin.lower() != header_origin.lower():
            log.warning(
                "pairing/request body.origin=%s != header.origin=%s",
                body_origin, header_origin,
            )
            raise LocalApiError(
                "body.origin no coincide con el header Origin.",
                status_code=400,
            )
        pr = pairing_manager.request_pairing(header_origin, req.scopes)
        log.info(
            "Pairing request creado: id=%s origin=%s scopes=%s",
            pr.request_id, pr.origin, pr.scopes,
        )
        # La API dispara la ventana nativa de aprobacion de inmediato.
        # El frontend solo necesita esperar el resultado via polling
        # o recibir el token en esta misma respuesta si la UI respondio.
        approved_via_ui = pairing_manager.try_native_approve(pr.request_id)
        if approved_via_ui is True:
            tok = pairing_manager.approve_request(pr.request_id)
            if tok:
                return {
                    "requestId": pr.request_id,
                    "status": "approved",
                    "origin": tok.origin,
                    "scopes": tok.scopes,
                    "token": tok.token,
                    "expiresAt": tok.expires_at,
                    "installationId": tok.installation_id,
                }
        if approved_via_ui is False:
            return _error_response(
                UserCancelledError("El usuario cancelo la aprobacion de emparejamiento.")
            )
        # Si la UI no respondio, devolvemos pending para que el frontend
        # pueda hacer polling via /pairing/status o llamar /pairing/confirm.
        return {
            "requestId": pr.request_id,
            "origin": pr.origin,
            "scopes": pr.scopes,
            "status": pr.status,
            "instructions": (
                "Revise la ventana de aprobacion del sistema. Si no aparece, "
                "use POST /api/v1/pairing/confirm con el requestId."
            ),
        }
    except LocalApiError as exc:
        return _error_response(exc)
    except Exception as exc:
        return _internal_error_response(exc)


@router.post("/pairing/confirm")
def pairing_confirm(req: PairingConfirmIn, request: Request):
    _check_rate(request, "/pairing/confirm")
    try:
        if req.approve:
            tok = pairing_manager.approve_request(req.requestId)
            if not tok:
                return _error_response(
                    LocalApiError(
                        "Solicitud de emparejamiento expirada o invalida.",
                        status_code=404,
                    )
                )
            log.info("Pairing aprobado: origin=%s exp=%s", tok.origin, tok.expires_at)
            return {
                "token": tok.token,
                "origin": tok.origin,
                "scopes": tok.scopes,
                "expiresAt": tok.expires_at,
                "installationId": tok.installation_id,
            }
        else:
            ok = pairing_manager.deny_request(req.requestId)
            return {"ok": ok}
    except LocalApiError as exc:
        return _error_response(exc)
    except Exception as exc:
        return _internal_error_response(exc)


@router.get("/pairing/status")
def pairing_status(request: Request):
    _check_rate(request, "/pairing/status")
    return {
        "installationId": pairing_manager.installation_id,
        "requirePairing": config_store.get().require_pairing,
        "devMode": config_store.get().dev_mode,
        "allowedOrigins": config_store.get().effective_allowed_origins(),
        "activeTokens": [
            {
                "origin": t.origin,
                "scopes": t.scopes,
                "issuedAt": t.issued_at,
                "expiresAt": t.expires_at,
                "revoked": t.revoked,
            }
            for t in pairing_manager.list_tokens()
            if not t.revoked
        ],
    }


# ---------------------------------------------------------------------------
# Certificados
# ---------------------------------------------------------------------------


@router.post("/certificados", response_model=CertificadosResponse)
def certificados(
    req: CertificadosRequest,
    request: Request,
    _tok=Depends(_bearer_for(SCOPE_CERT_LIST)),
):
    _check_rate(request, "/certificados")
    _enforce_replay_protection(request)
    _log_request(
        request,
        "/certificados",
        f"provider={req.provider} pinMode={req.pinMode}",
    )
    try:
        return token_service.list_certificates(
            provider=req.provider or settings.default_provider,
            tipo=req.tipoKeyStoreProvider or "TOKEN",
            pin_mode=req.pinMode or settings.default_pin_mode,
            inline_pin=None,
            request_timeout_s=settings.request_timeout_seconds,
        )
    except LocalApiError as exc:
        log.info("RESP /certificados %s: %s", exc.status_code, exc.code.value)
        return _error_response(exc)
    except Exception as exc:
        return _internal_error_response(exc)


# ---------------------------------------------------------------------------
# Firmar PDF
# ---------------------------------------------------------------------------


@router.post("/firmar/pdf", response_model=FirmarPdfResponse)
def firmar_pdf(
    req: FirmarPdfRequest,
    request: Request,
    _tok=Depends(_bearer_for(SCOPE_PDF_SIGN)),
):
    _check_rate(request, "/firmar/pdf")
    _enforce_replay_protection(request)
    _log_request(
        request,
        "/firmar/pdf",
        f"cert={req.certificadoId} sha256={req.documentoSha256[:12]}... pinMode={req.pinMode}",
    )
    try:
        # 1. Confirmacion nativa ANTES de pedir PIN o de tocar el token.
        cfg = config_store.get()
        if cfg.require_user_confirmation:
            origin = request.headers.get("origin", "origen-desconocido")
            razon = (req.firma.razon if req.firma else "Firmado digitalmente") or "Firmado digitalmente"
            page = 1
            try:
                if req.firma and req.firma.pagina is not None:
                    page = int(req.firma.pagina)
            except Exception:
                pass
            approved = ask_signature_confirmation(
                origin=origin,
                cert_subject=req.certificadoId,
                cert_serial=req.certificadoId,
                document_sha256=req.documentoSha256,
                razon=razon,
                page=page,
            )
            if approved is False:
                log.info("Firma cancelada por el usuario (UI).")
                return _error_response(
                    LocalApiError(
                        "El usuario cancelo la solicitud de firma.",
                        code="USER_CANCELLED",
                        status_code=400,
                    )
                )
            if approved is None:
                log.warning("Ventana de confirmacion no respondio (timeout/error).")
                return _error_response(
                    LocalApiError(
                        "No se pudo mostrar la ventana de confirmacion.",
                        code="USER_CANCELLED",
                        status_code=400,
                    )
                )
        return token_service.sign_pdf(
            documento_base64=req.documentoBase64,
            documento_sha256=req.documentoSha256,
            certificado_id=req.certificadoId,
            provider=settings.default_provider,
            tipo="TOKEN",
            pin_mode=req.pinMode or settings.default_pin_mode,
            inline_pin=None,
            firma_params=req.firma.model_dump(),
            metadata_b64=req.metadataBase64,
            request_timeout_s=settings.request_timeout_seconds,
            sign_timeout_s=settings.sign_timeout_seconds,
        )
    except LocalApiError as exc:
        log.info("RESP /firmar/pdf %s: %s", exc.status_code, exc.code.value)
        return _error_response(exc)
    except Exception as exc:
        return _internal_error_response(exc)
