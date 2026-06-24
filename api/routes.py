"""Router FastAPI con los endpoints del contrato.

- GET  /api/v1/health
- POST /api/v1/certificados
- POST /api/v1/firmar/pdf
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..config import settings
from ..core.errors import LocalApiError
from ..core.rate_limiter import RateLimiter
from ..core.schemas import (
    CertificadosRequest,
    CertificadosResponse,
    FirmarPdfRequest,
    FirmarPdfResponse,
    HealthResponse,
    HealthUnavailableResponse,
)
from ..core.token_service import token_service
from .. import __version__


log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")
limiter = RateLimiter(max_requests=settings.rate_limit_per_minute, window_seconds=60)


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
        "REQ %s %s from=%s ua=%s body=%s",
        request.method,
        endpoint,
        request.client.host if request.client else "?",
        request.headers.get("user-agent", "-")[:60],
        body_summary[:120],
    )


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
        return HealthResponse(**data)
    except LocalApiError as exc:
        return _error_response(exc)
    except Exception as exc:
        return _internal_error_response(exc)


@router.post("/certificados", response_model=CertificadosResponse)
def certificados(req: CertificadosRequest, request: Request):
    _check_rate(request, "/certificados")
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


@router.post("/firmar/pdf", response_model=FirmarPdfResponse)
def firmar_pdf(req: FirmarPdfRequest, request: Request):
    _check_rate(request, "/firmar/pdf")
    _log_request(
        request,
        "/firmar/pdf",
        f"cert={req.certificadoId} sha256={req.documentoSha256[:12]}... pinMode={req.pinMode}",
    )
    try:
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
