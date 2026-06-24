"""Driver PCSC para tokens contactless / smart cards.

Implementacion basica: detecta lectores y tarjetas, y delega la firma
real al stack PKCS#11 cuando el fabricante expone un modulo sobre PCSC.
La firma PAdES contra APDUs crudos queda fuera de alcance y debe
sustituirse por el modulo PKCS#11 del fabricante.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from ..errors import DriverNotFoundError, TokenNotFoundError
from ..schemas import CertificateInfo
from .base import SignatureRequest, SignatureResult, TokenDriver


log = logging.getLogger(__name__)


def _import_pyscard():
    try:
        from smartcard.System import readers  # type: ignore
        from smartcard.Exceptions import CardConnectionException  # type: ignore

        return readers, CardConnectionException
    except Exception as exc:  # pragma: no cover
        raise DriverNotFoundError(
            "Libreria pyscard no disponible. Instala con: pip install pyscard"
        ) from exc


class PcscDriver(TokenDriver):
    provider_id = "PCSC"
    provider_name = "PC/SC Smartcard"
    driver_kind = "PCSC"

    def __init__(self, reader_index: int = 0) -> None:
        self._reader_index = reader_index

    def is_available(self) -> bool:
        try:
            readers, _ = _import_pyscard()
            r = readers()
            return bool(r and len(r) > 0)
        except Exception as exc:
            log.info("PCSC no disponible: %s", exc)
            return False

    def get_token_label(self) -> str:
        try:
            readers, _ = _import_pyscard()
            r = readers()
            if r and len(r) > self._reader_index:
                return str(r[self._reader_index])
        except Exception:
            pass
        return "PCSC Reader"

    def list_certificates(
        self,
        *,
        pin: Optional[str] = None,
        expected_cedula: Optional[str] = None,
    ) -> List[CertificateInfo]:
        readers, _ = _import_pyscard()
        r = readers()
        if not r or len(r) == 0:
            raise TokenNotFoundError("No hay lectores PCSC conectados.")
        # PCSC puro no expone certificados sin APDUs especificos del fabricante.
        # Se recomienda complementar con PKCS#11 sobre PCSC.
        raise DriverNotFoundError(
            "Listado de certificados PCSC requiere un modulo PKCS#11 del fabricante. "
            "Configura PKCS11_MODULE_PATH."
        )

    def sign(self, request: SignatureRequest) -> SignatureResult:
        raise DriverNotFoundError(
            "Firma PAdES sobre PCSC puro no implementada. "
            "Apoyate en el modulo PKCS#11 del fabricante."
        )
