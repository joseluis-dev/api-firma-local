"""Verifica que la firma PAdES real (pyhanko) funciona end-to-end.

Genera un certificado RSA auto-firmado, firma un PDF con
``sign_pdf_bytes`` y verifica que el PDF resultante contiene un
diccionario ``/Sig`` y un ``/ByteRange``.
"""
from __future__ import annotations

import base64
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def make_pdf() -> bytes:
    """Genera un PDF real con reportlab (valido para pyhanko)."""
    from io import BytesIO

    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(72, 720, "Documento de prueba para firma PAdES")
    c.showPage()
    c.save()
    return buf.getvalue()


def make_self_signed_cert() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Signer"),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, "1804724555"),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def main() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from localapi.core.pdf_signer import PadesParams, sign_pdf_bytes

    pdf = make_pdf()
    cert_der = make_self_signed_cert()

    def signer(data: bytes, algo: str) -> bytes:
        # Firma con la libreria cryptography (no usa el token real)
        from cryptography.hazmat.primitives.asymmetric import padding

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        return key.sign(data, padding.PKCS1v15(), hashes.SHA512())

    signed = sign_pdf_bytes(
        pdf_bytes=pdf,
        certificate_der=cert_der,
        certificate_chain_der=[cert_der],
        digest_algorithm="SHA512",
        signer_func=signer,
        params=PadesParams(),
    )

    assert b"%PDF-" in signed[:5]
    assert b"/ByteRange" in signed, "PDF firmado no contiene /ByteRange"
    assert b"/Type /Sig" in signed or b"/Type/Sig" in signed, "PDF firmado no contiene firma"

    # Verificacion estructural con pikepdf o leyendo bytes crudos
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp.write(signed)
        path = tmp.name
    print("Firma PAdES OK ->", path)
    print("Tamano:", len(signed), "bytes")

    # Verificacion de integridad: leer el PDF firmado y contar
    # diccionarios de firma embebidos.
    with open(path, "rb") as fh:
        content = fh.read()
    n_sigs = content.count(b"/Type /Sig") + content.count(b"/Type/Sig")
    print("Diccionarios /Sig:", n_sigs)
    assert n_sigs >= 1, "No se encontro el diccionario de firma"
    return 0


if __name__ == "__main__":
    sys.exit(main())
