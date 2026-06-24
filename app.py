"""Aplicacion FastAPI y middleware de seguridad."""
from __future__ import annotations

import logging
import re

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.routes import router
from .config import settings
from .core.errors import LocalApiError
from .core.logging_config import configure_logging, redact_mapping


log = logging.getLogger(__name__)

configure_logging(settings.log_level)

app = FastAPI(
    title="localapi - Firma con Token",
    version="1.0.0",
    docs_url="/api/v1/docs",
    redoc_url=None,
    openapi_url="/api/v1/openapi.json",
)

# CORS estricto: solo origen del frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
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


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    if not _is_loopback_request(request):
        log.warning("Bloqueando request no-loopback: %s", request.client)
        return JSONResponse(
            status_code=403,
            content={
                "code": "LOCAL_API_UNAVAILABLE",
                "message": "API local solo acepta conexiones loopback.",
                "details": [],
            },
        )
    try:
        response = await call_next(request)
    except LocalApiError as exc:
        response = JSONResponse(status_code=exc.status_code, content=exc.to_dict())
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
        "version": "1.0.0",
        "endpoints": [
            "GET /api/v1/health",
            "POST /api/v1/certificados",
            "POST /api/v1/firmar/pdf",
        ],
    }


app.include_router(router)
