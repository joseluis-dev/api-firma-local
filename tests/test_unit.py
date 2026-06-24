"""Pruebas unitarias pequenas (sin token)."""
from __future__ import annotations

from localapi.core.crypto_utils import (
    decode_base64,
    encode_base64,
    extract_cedula_from_subject,
    is_pdf,
    normalize_cedula,
    sha256_hex,
)
from localapi.core.errors import (
    CedulaMismatchError,
    InvalidInputError,
    InvalidPdfError,
)


def test_base64_roundtrip() -> None:
    data = b"hola mundo\x00\x01\x02"
    s = encode_base64(data)
    assert decode_base64(s) == data


def test_is_pdf() -> None:
    assert is_pdf(b"%PDF-1.4\n")
    assert not is_pdf(b"not a pdf")
    assert not is_pdf(b"")


def test_sha256() -> None:
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_normalize_cedula() -> None:
    assert normalize_cedula("180.472.455-5") == "1804724555"
    assert normalize_cedula("") == ""


def test_extract_cedula_from_subject() -> None:
    assert extract_cedula_from_subject("CN=JUAN PEREZ 1804724555") == "1804724555"
    assert extract_cedula_from_subject("CN=foo") == ""


def test_invalid_pdf_raises() -> None:
    pdf = b"no es pdf"
    try:
        from localapi.core.pdf_signer import PadesParams, sign_pdf_bytes

        sign_pdf_bytes(
            pdf_bytes=pdf,
            certificate_der=None,
            certificate_chain_der=None,
            digest_algorithm="SHA512",
            signer_func=lambda d, a: d,
            params=PadesParams(),
        )
    except InvalidPdfError:
        pass
    else:
        raise AssertionError("Debio lanzar InvalidPdfError")


def test_error_codes() -> None:
    e = CedulaMismatchError("x")
    assert e.code.value == "CEDULA_MISMATCH"
    assert e.status_code == 409
    e2 = InvalidInputError("x")
    assert e2.status_code == 400
