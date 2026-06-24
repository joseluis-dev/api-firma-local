"""Codigos de error y excepcion base para la API local.

Estos codigos coinciden con el contrato HTTP del backend `api_firma`.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional


class ErrorCode(str, Enum):
    LOCAL_API_UNAVAILABLE = "LOCAL_API_UNAVAILABLE"
    DRIVER_NOT_FOUND = "DRIVER_NOT_FOUND"
    TOKEN_NOT_FOUND = "TOKEN_NOT_FOUND"
    TOKEN_LOCKED = "TOKEN_LOCKED"
    PIN_REQUIRED = "PIN_REQUIRED"
    PIN_INVALID = "PIN_INVALID"
    CERTIFICATE_NOT_FOUND = "CERTIFICATE_NOT_FOUND"
    CEDULA_MISMATCH = "CEDULA_MISMATCH"
    SIGNATURE_REJECTED = "SIGNATURE_REJECTED"
    INVALID_PDF = "INVALID_PDF"
    INVALID_INPUT = "INVALID_INPUT"
    TIMEOUT = "TIMEOUT"
    USER_CANCELLED = "USER_CANCELLED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class LocalApiError(Exception):
    """Excepcion base de la API local."""

    status_code: int = 500
    code: ErrorCode = ErrorCode.INTERNAL_ERROR

    def __init__(
        self,
        message: str,
        *,
        code: Optional[ErrorCode] = None,
        status_code: Optional[int] = None,
        details: Optional[List[Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        if status_code is not None:
            self.status_code = status_code
        self.details = details or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code.value,
            "message": self.message,
            "details": self.details,
        }


class InvalidInputError(LocalApiError):
    status_code = 400
    code = ErrorCode.INVALID_INPUT


class InvalidPdfError(LocalApiError):
    status_code = 400
    code = ErrorCode.INVALID_PDF


class PinRequiredError(LocalApiError):
    status_code = 401
    code = ErrorCode.PIN_REQUIRED


class PinInvalidError(LocalApiError):
    status_code = 403
    code = ErrorCode.PIN_INVALID


class CedulaMismatchError(LocalApiError):
    status_code = 409
    code = ErrorCode.CEDULA_MISMATCH


class TokenNotFoundError(LocalApiError):
    status_code = 404
    code = ErrorCode.TOKEN_NOT_FOUND


class CertificateNotFoundError(LocalApiError):
    status_code = 404
    code = ErrorCode.CERTIFICATE_NOT_FOUND


class DriverNotFoundError(LocalApiError):
    status_code = 409
    code = ErrorCode.DRIVER_NOT_FOUND


class TokenLockedError(LocalApiError):
    status_code = 423
    code = ErrorCode.TOKEN_LOCKED


class SignatureRejectedError(LocalApiError):
    status_code = 422
    code = ErrorCode.SIGNATURE_REJECTED


class TimeoutError_(LocalApiError):
    status_code = 504
    code = ErrorCode.TIMEOUT


class UserCancelledError(LocalApiError):
    status_code = 400
    code = ErrorCode.USER_CANCELLED


# Re-export local aliases used elsewhere
__all__ = [
    "ErrorCode",
    "LocalApiError",
    "InvalidInputError",
    "InvalidPdfError",
    "PinRequiredError",
    "PinInvalidError",
    "CedulaMismatchError",
    "TokenNotFoundError",
    "CertificateNotFoundError",
    "DriverNotFoundError",
    "TokenLockedError",
    "SignatureRejectedError",
    "TimeoutError_",
    "UserCancelledError",
    "LocalApiUnavailableError",
]


class LocalApiUnavailableError(LocalApiError):
    status_code = 503
    code = ErrorCode.LOCAL_API_UNAVAILABLE
