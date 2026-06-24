"""Driver mock para desarrollo y pruebas sin token fisico.

NUNCA debe usarse en produccion. Se activa con ``MOCK_DRIVER=true``.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from ..crypto_utils import encode_base64
from ..errors import (
    CertificateNotFoundError,
    PinInvalidError,
    TokenLockedError,
    TokenNotFoundError,
)
from ..schemas import CertificateInfo
from .base import SignatureRequest, SignatureResult, TokenDriver


_MOCK_CEDULA = "1804724555"
_MOCK_PIN = "1234"
_MOCK_LABEL = "Token Demo (Mock)"


def _mock_certificates(provider_id: str) -> List[CertificateInfo]:
    now = datetime.now(timezone.utc)
    return [
        CertificateInfo(
            id="alias-demo-1",
            cedula=_MOCK_CEDULA,
            subject="CN=JUAN PEREZ DEMO, O=LocalAPI Mock",
            issuer="CN=Mock CA",
            serial="AABBCCDDEEFF",
            validFrom=now - timedelta(days=30),
            validTo=now + timedelta(days=365 * 2),
            provider=provider_id,
            tokenLabel=_MOCK_LABEL,
        )
    ]


class MockDriver(TokenDriver):
    provider_id = "MOCK"
    provider_name = "Mock Token"
    driver_kind = "MOCK"

    def __init__(self) -> None:
        self._failures = 0
        self._locked = False
        self._present = True

    def is_available(self) -> bool:
        return self._present and not self._locked

    def get_token_label(self) -> str:
        return _MOCK_LABEL

    def _check_locked(self) -> None:
        if self._locked:
            raise TokenLockedError("Token mock bloqueado por intentos fallidos.")
        if not self._present:
            raise TokenNotFoundError("Token mock no insertado.")

    def list_certificates(
        self,
        *,
        pin: Optional[str] = None,
        expected_cedula: Optional[str] = None,
    ) -> List[CertificateInfo]:
        self._check_locked()
        # En modo NONE (sin PIN) no se valida nada.
        if pin is not None and pin != "" and pin != _MOCK_PIN:
            self._failures += 1
            if self._failures >= 3:
                self._locked = True
                raise TokenLockedError("PIN mock incorrecto 3 veces; token bloqueado.")
            raise PinInvalidError("PIN mock incorrecto.")
        self._failures = 0
        certs = _mock_certificates(self.provider_id)
        if expected_cedula:
            certs = [c for c in certs if c.cedula == expected_cedula]
            if not certs:
                raise CertificateNotFoundError(
                    f"No hay certificado con cedula {expected_cedula}."
                )
        return certs

    def sign(self, request: SignatureRequest) -> SignatureResult:
        self._check_locked()
        if request.pin and request.pin != _MOCK_PIN:
            self._failures += 1
            if self._failures >= 3:
                self._locked = True
                raise TokenLockedError("PIN mock incorrecto 3 veces; token bloqueado.")
            raise PinInvalidError("PIN mock incorrecto.")
        self._failures = 0

        if request.key_alias not in {"alias-demo-1", "alias-1"}:
            raise CertificateNotFoundError(
                f"Certificado {request.key_alias} no existe en el mock."
            )

        # Genera una "firma" deterministica (no criptograficamente valida)
        # Unicamente para validar el contrato HTTP.
        sig = hashlib.sha512(
            request.data + request.key_alias.encode("utf-8")
        ).digest() + os.urandom(32)

        cert_der = b"MOCK-CERT-DER-" + hashlib.sha256(
            _MOCK_CEDULA.encode("utf-8")
        ).digest()[:32]

        return SignatureResult(
            signature=sig,
            algorithm=f"{request.algorithm}withMOCK",
            certificate_der=cert_der,
            certificate_chain_der=[cert_der],
        )

    def get_certificate_der(self, cert_id: str, pin: Optional[str] = None) -> bytes:
        if cert_id not in {"alias-demo-1", "alias-1"}:
            raise CertificateNotFoundError(
                f"Certificado {cert_id} no existe en el mock."
            )
        from hashlib import sha256
        return b"MOCK-CERT-DER-" + sha256(_MOCK_CEDULA.encode("utf-8")).digest()[:32]
