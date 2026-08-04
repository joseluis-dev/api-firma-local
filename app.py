"""Aplicacion FastAPI y middleware de seguridad."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.types import Scope

from . import __version__
from .api.routes import router
from .config import settings
from .core.config_store import config_store
from .core.errors import LocalApiError
from .core.logging_config import configure_logging, redact_mapping
from .core.security.confirmation import (
    ask_pairing_approval,
    ask_signature_confirmation,
)
from .core.security.deps import (
    extract_bearer,
    origin_matches_allowed,
    require_bearer,
)
from .core.security.pairing import pairing_manager


log = logging.getLogger(__name__)

configure_logging(settings.log_level)

# Conectar la API con la UI nativa de aprobacion
pairing_manager.set_approval_callback(ask_pairing_approval)


app = FastAPI(
    title="localapi - Firma con Token",
    version=__version__,
    docs_url="/api/v1/docs",
    redoc_url=None,
    openapi_url="/api/v1/openapi.json",
)


def _current_cors_origins() -> list:
    return list(config_store.get().effective_allowed_origins())


# CORS estricto: solo origenes autorizados por config_store.
app.add_middleware(
    CORSMiddleware,
    allow_origins=_current_cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-LocalAPI-Request-Id",
        "X-LocalAPI-Timestamp",
    ],
    expose_headers=[
        "X-LocalAPI-Request-Id",
    ],
    max_age=600,
)


# Cabeceras de seguridad minimas
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}


def _attach_cors(response: JSONResponse, request: Request) -> JSONResponse:
    """Asegura que cualquier respuesta JSON lleve CORS si el Origin es valido.

    Esto cubre los casos en los que el middleware CORSMiddleware no
    agrega cabeceras (por ejemplo, errores 4xx/5xx antes de la negociacion
    de CORS o respuestas lanzadas manualmente por dependencias).
    """
    if "access-control-allow-origin" in {k.lower() for k in response.headers.keys()}:
        return response
    origin = (request.headers.get("origin") or "").strip().rstrip("/")
    if not origin:
        return response
    if origin_matches_allowed(request):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    return response


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    # 1. Bloquear todo lo que no sea loopback
    if not _is_loopback_request(request):
        log.warning("Bloqueando request no-loopback: %s", request.client)
        resp = JSONResponse(
            status_code=403,
            content={
                "code": "LOCAL_API_UNAVAILABLE",
                "message": "API local solo acepta conexiones loopback.",
                "details": [],
            },
        )
        return _attach_cors(resp, request)

    # 2. Validar Host (anti-DNS-rebinding basico)
    host = request.headers.get("host", "")
    if host and host not in {"127.0.0.1:44113", "localhost:44113", "127.0.0.1", "localhost"}:
        log.warning("Host no permitido: %s", host)
        resp = JSONResponse(
            status_code=403,
            content={
                "code": "HOST_NOT_ALLOWED",
                "message": "Host no permitido.",
                "details": [],
            },
        )
        return _attach_cors(resp, request)

    try:
        response = await call_next(request)
    except LocalApiError as exc:
        response = JSONResponse(status_code=exc.status_code, content=exc.to_dict())
        response = _attach_cors(response, request)
    except Exception as exc:
        log.exception("Error inesperado: %s", exc)
        response = JSONResponse(
            status_code=500,
            content={
                "code": "INTERNAL_ERROR",
                "message": "Error interno de la API local.",
                "details": [str(exc)[:200]],
            },
        )
        response = _attach_cors(response, request)

    for k, v in _SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


def _is_loopback_request(request: Request) -> bool:
    if not request.client:
        return False
    host = request.client.host
    return host in {"127.0.0.1", "::1", "localhost"}


@app.get("/", include_in_schema=False)
def root():
    return {
        "name": "localapi",
        "version": __version__,
        "installationId": pairing_manager.installation_id,
        "endpoints": [
            "GET  /api/v1/health",
            "POST /api/v1/pairing/request",
            "POST /api/v1/pairing/confirm",
            "GET  /api/v1/pairing/status",
            "POST /api/v1/certificados",
            "POST /api/v1/firmar/pdf",
        ],
    }


app.include_router(router)
