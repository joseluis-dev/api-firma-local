"""Interfaz abstracta de los drivers de token.

Cualquier backend (PKCS#11, PCSC, mock) implementa ``TokenDriver``.
"""
from __future__ import annotations

import abc
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from ..crypto_utils import to_iso
from ..schemas import CertificateInfo


log = logging.getLogger(__name__)


@dataclass
class SignatureRequest:
    data: bytes
    algorithm: str
    pin: str
    key_alias: str


@dataclass
class SignatureResult:
    signature: bytes
    algorithm: str
    certificate_der: bytes
    certificate_chain_der: List[bytes]


class TokenDriver(abc.ABC):
    """Contrato que todo driver de token debe cumplir."""

    provider_id: str = "BASE"
    provider_name: str = "Base"
    driver_kind: str = "BASE"  # PKCS11 o PCSC

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Devuelve True si el driver detecta hardware/utilizable."""

    @abc.abstractmethod
    def get_token_label(self) -> str:
        """Etiqueta legible del token insertado."""

    @abc.abstractmethod
    def list_certificates(
        self,
        *,
        pin: Optional[str] = None,
        expected_cedula: Optional[str] = None,
    ) -> List[CertificateInfo]:
        """Lista los certificados de firma del token."""

    @abc.abstractmethod
    def sign(self, request: SignatureRequest) -> SignatureResult:
        """Firma datos con la clave privada del alias indicado."""

    def supports_algorithm(self, algorithm: str) -> bool:
        return algorithm.upper() in {"SHA512", "SHA384", "SHA256"}


def _format_subject_components(subject: str) -> str:
    return subject.replace(",", ", ")


_CN_OID_RE = re.compile(r"CN=([^,+]+)")


def _extract_cn(subject: str) -> str:
    m = _CN_OID_RE.search(subject)
    return m.group(1).strip() if m else ""


def _classify_cert_type(cert) -> str:
    """Clasifica el certificado en SIGNING / AUTH / CA / ROOT / UNKNOWN."""
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID

    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = bool(bc.value.ca)
    except x509.ExtensionNotFound:
        pass

    if is_ca:
        # root si subject == issuer
        if cert.subject.rfc4514_string() == cert.issuer.rfc4514_string():
            return "ROOT"
        return "CA"

    # Heuristica: si tiene EKU con nonRepudiation -> SIGNING
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        for usage in eku.value:
            if usage == ExtendedKeyUsageOID.NON_REPUDIATION:
                return "SIGNING"
            if usage == ExtendedKeyUsageOID.CLIENT_AUTH:
                return "AUTH"
    except x509.ExtensionNotFound:
        pass

    return "UNKNOWN"


def _build_display_name(cert_type: str, subject: str, issuer: str) -> str:
    cn = _extract_cn(subject)
    if cert_type == "SIGNING":
        return f"Firma digital - {cn}" if cn else "Firma digital"
    if cert_type == "AUTH":
        return f"Autenticacion - {cn}" if cn else "Autenticacion"
    if cert_type == "ROOT":
        return f"Autoridad raiz - {cn}" if cn else "Autoridad raiz"
    if cert_type == "CA":
        issuer_cn = _extract_cn(issuer)
        return f"CA {issuer_cn}" if issuer_cn else "Entidad certificadora"
    if cn:
        return cn
    return "Certificado"


def certificate_info_from_x509(
    *,
    cert_id: str,
    cert_der: bytes,
    provider_id: str,
    token_label: str,
) -> CertificateInfo:
    """Construye un CertificateInfo a partir de un certificado X.509 DER."""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    cert = x509.load_der_x509_certificate(cert_der, default_backend())

    subject = _format_subject_components(cert.subject.rfc4514_string())
    issuer = _format_subject_components(cert.issuer.rfc4514_string())
    serial = format(cert.serial_number, "x").upper().rjust(2, "0")

    not_before: datetime = cert.not_valid_before_utc
    not_after: datetime = cert.not_valid_after_utc

    cedula = _extract_cedula(cert)
    cert_type = _classify_cert_type(cert)
    is_ca = cert_type in {"CA", "ROOT"}
    display = _build_display_name(cert_type, subject, issuer)
    short = _extract_cn(subject) or cert_id

    return CertificateInfo(
        id=cert_id,
        cedula=cedula,
        subject=subject,
        issuer=issuer,
        serial=serial,
        validFrom=not_before,
        validTo=not_after,
        provider=provider_id,
        tokenLabel=token_label,
        displayName=display,
        shortName=short,
        type=cert_type,
        isCa=is_ca,
        hasPrivateKey=False,  # el driver lo rellena
        signable=False,        # el driver lo rellena
    )


def _extract_cedula(cert) -> str:
    """Extrae la cedula del certificado.

    Prioriza el OID ``SERIAL_NUMBER`` y luego el CN. Ignora OIDs
    bancarios no estandar como ``2.5.4.5`` que aparecen en algunos
    certificados del Banco Central.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from ..crypto_utils import normalize_cedula

    candidates: list[str] = []

    # 1. SERIAL_NUMBER estandar X.500
    try:
        for sn in cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER):
            if sn.value and sn.value.strip():
                candidates.append(sn.value)
    except Exception:
        pass

    # 2. CN (solo la parte del CN, no el subject completo)
    try:
        for cn in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            if cn.value:
                candidates.append(cn.value)
    except Exception:
        pass

    # 3. SAN serialNumber
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for value in san.value:
            text = str(value)
            candidates.append(text)
    except Exception:
        pass

    for raw in candidates:
        digits = normalize_cedula(raw)
        if 6 <= len(digits) <= 15:
            return digits
    return ""
