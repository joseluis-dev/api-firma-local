"""Schemas Pydantic para request y response de la API local.

Estos modelos reflejan el contrato HTTP del documento de diseno.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator


PinMode = Literal["LOCAL_PROMPT", "INLINE", "NONE"]
KeyStoreType = Literal["TOKEN", "PCSC"]


# Acepta numero o string (compatibilidad hacia atras con el frontend).
Num = Union[str, float, int]


class ProviderInfo(BaseModel):
    id: str
    name: str
    installed: bool


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"] = "ok"
    version: str
    capabilities: List[str]
    providers: List[ProviderInfo]


class HealthUnavailableResponse(BaseModel):
    code: str
    message: str


class CertificateInfo(BaseModel):
    id: str
    cedula: str
    subject: str
    issuer: str
    serial: str
    validFrom: datetime
    validTo: datetime
    provider: str
    tokenLabel: str
    # Nuevos campos legibles / utilidad para el frontend
    displayName: str = ""
    shortName: str = ""
    type: str = "UNKNOWN"  # SIGNING, AUTH, CA, ROOT, UNKNOWN
    isCa: bool = False
    hasPrivateKey: bool = False
    signable: bool = False


class CertificadosRequest(BaseModel):
    provider: Optional[str] = "AUTO"
    tipoKeyStoreProvider: Optional[KeyStoreType] = "TOKEN"
    pinMode: Optional[PinMode] = "LOCAL_PROMPT"
    expectedCedula: Optional[str] = None


class CertificadosResponse(BaseModel):
    certificados: List[CertificateInfo]


class FirmaParametros(BaseModel):
    # Aliases historicos (compatibilidad hacia atras).
    formatoDocumento: str = "pdf"
    pagina: Num = "1"
    tipoEstampado: str = "QR"
    razon: str = "Firmado digitalmente"
    llx: Num = "120"
    lly: Num = "180"
    ancho: Num = "200"
    alto: Num = "70"
    # Origen de coordenadas: PDF_BOTTOM_LEFT (por defecto) o TOP_LEFT
    # (util si el frontend envia coordenadas en pixeles del visor).
    coordOrigin: str = "PDF_BOTTOM_LEFT"
    renderedWidth: Optional[Num] = None
    renderedHeight: Optional[Num] = None
    pdfWidth: Optional[Num] = None
    pdfHeight: Optional[Num] = None

    # Campos reales del frontend (top-left en pixeles del visor).
    page: Optional[Num] = None
    x: Optional[Num] = None
    y: Optional[Num] = None
    width: Optional[Num] = None
    height: Optional[Num] = None
    pageWidth: Optional[Num] = None
    pageHeight: Optional[Num] = None
    # Si el frontend envia el centro del indicador visual, mandar estos
    # offsets para que la API centre el box. Por defecto, x/y ya son
    # la esquina superior izquierda del indicador, asi que se dejan
    # en 0 si no se envian.
    indicatorCenterOffsetX: Optional[Num] = None
    indicatorCenterOffsetY: Optional[Num] = None

    # Contenido opcional del codigo QR. Si se omite, la API genera
    # uno local con metadatos de la firma.
    qrUrl: Optional[str] = None
    qrContent: Optional[str] = None
    # Texto que aparece junto al QR (lado derecho).
    qrText: Optional[str] = None

    # Bloques nuevos que el frontend envia con metadata completa de
    # ubicacion. Si ``rectangulo`` esta presente, define la posicion
    # exacta en puntos PDF y se ignora todo lo demas.
    ubicacion: Optional["FirmaUbicacion"] = None
    rectangulo: Optional["FirmaRectangulo"] = None


class FirmaUbicacion(BaseModel):
    pagina: Optional[Num] = None
    page: Optional[Num] = None
    x: Optional[Num] = None
    y: Optional[Num] = None
    width: Optional[Num] = None
    height: Optional[Num] = None
    llx: Optional[Num] = None
    lly: Optional[Num] = None
    pageWidth: Optional[Num] = None
    pageHeight: Optional[Num] = None
    indicatorCenterOffsetX: Optional[Num] = None
    indicatorCenterOffsetY: Optional[Num] = None
    units: Optional[str] = None
    origin: Optional[str] = None
    coordinateSystem: Optional[str] = None


class FirmaRectangulo(BaseModel):
    lowerLeftX: Optional[Num] = None
    lowerLeftY: Optional[Num] = None
    upperRightX: Optional[Num] = None
    upperRightY: Optional[Num] = None
    centerX: Optional[Num] = None
    centerY: Optional[Num] = None


class FirmarPdfRequest(BaseModel):
    documentoBase64: str = Field(..., min_length=1)
    documentoSha256: str = Field(..., min_length=64, max_length=64)
    certificadoId: str = Field(..., min_length=1)
    expectedCedula: Optional[str] = None
    firma: FirmaParametros
    metadataBase64: Optional[str] = None
    pinMode: Optional[PinMode] = "LOCAL_PROMPT"

    @field_validator("documentoSha256")
    @classmethod
    def _hash_hex(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
            raise ValueError("documentoSha256 debe ser SHA-256 en hex (64 chars).")
        return v


class CertificadoResumen(BaseModel):
    cedula: str
    serial: str
    subject: str
    issuer: str
    validFrom: datetime
    validTo: datetime


class FirmaLocalInfo(BaseModel):
    provider: str
    driver: str
    algorithm: str
    signedAt: datetime


class FirmarPdfResponse(BaseModel):
    documentoFirmadoBase64: str
    documentoOriginalSha256: str
    certificado: CertificadoResumen
    firmaLocal: FirmaLocalInfo


class ErrorResponse(BaseModel):
    code: str
    message: str
    details: List = []
