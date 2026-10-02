"""Firma PAdES con pyhanko.

Wrapper tolerante: si pyhanko no esta disponible o el certificado
es del mock, produce un PDF con un trailer de firma. Para PKCS#11
real, intenta construir un PDF firmado PAdES-BES con apariencia
visible.
"""
from __future__ import annotations

import asyncio
import io
import logging
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from .errors import InvalidPdfError, SignatureRejectedError


log = logging.getLogger(__name__)


@dataclass
class PadesParams:
    page: int = 1
    llx: float = 120.0
    lly: float = 180.0
    width: float = 110.0
    height: float = 36.0
    razon: str = "Firmado digitalmente"
    tipo_estampado: str = "QR"
    digest_algorithm: str = "SHA512"
    coord_origin: str = "PDF_BOTTOM_LEFT"
    rendered_width: Optional[float] = None
    rendered_height: Optional[float] = None
    pdf_width: Optional[float] = None
    pdf_height: Optional[float] = None
    qr_url: Optional[str] = None
    qr_content: Optional[str] = None
    qr_text: Optional[str] = None
    signer_name: Optional[str] = None
    # Datos del certificado para enriquecer el QR/stamp.
    serial: str = ""
    cedula: str = ""
    issuer: str = ""


SignerFunc = Callable[[bytes, str], bytes]


@dataclass
class PreparedPdfSignature:
    """A prepared PDF and CMS attributes; no private-key operation yet."""

    signed_data: bytes
    digest_algorithm: str
    _finish: Callable[[bytes], bytes]

    def sign(self, signer_func: SignerFunc) -> bytes:
        signature = signer_func(self.signed_data, self.digest_algorithm)
        return self._finish(signature)


def _is_pdf(data: bytes) -> bool:
    return data[:5] == b"%PDF-"


def _read_page_size(pdf_bytes: bytes) -> Optional[Tuple[float, float]]:
    """Lee el tamano de la primera pagina del PDF sin firmarlo."""
    try:
        from pyhanko.pdf_utils.reader import PdfFileReader

        f = io.BytesIO(pdf_bytes)
        r = PdfFileReader(f)
        pages = r.root["/Pages"]["/Kids"]
        if not pages:
            return None
        first = pages[0]
        if not isinstance(first, dict):
            first = first.get_object()
        mb = first.get("/MediaBox")
        if not mb or len(mb) < 4:
            return None
        return float(mb[2]), float(mb[3])
    except Exception as exc:  # pragma: no cover
        log.debug("No se pudo leer tamano de pagina: %s", exc)
        return None


def _resolve_box(
    params: PadesParams,
) -> Tuple[int, Tuple[int, int, int, int]]:
    """Calcula la pagina 0-based y el box de la firma visible.

    El box es (x1, y1, x2, y2) en puntos PDF, con origen
    bottom-left (sistema PDF).

    Si ``coord_origin=TOP_LEFT`` y se envian tamano renderizado/pdf,
    convierte desde pixeles del visor al sistema PDF.
    Si no hay tamano renderizado pero hay ``pdf_height``, asume que
    las coordenadas ya estan en puntos PDF y solo se invierte el Y.
    """
    page_0based = max(0, params.page - 1)

    x1 = float(params.llx)
    y1 = float(params.lly)
    w = float(params.width)
    h = float(params.height)
    if w <= 0:
        w = PadesParams.width
    if h <= 0:
        h = PadesParams.height

    if params.coord_origin.upper() == "TOP_LEFT":
        pdf_w = params.pdf_width
        pdf_h = params.pdf_height
        rendered_w = params.rendered_width
        rendered_h = params.rendered_height
        if pdf_w and pdf_h and rendered_w and rendered_h:
            # Conversion desde pixeles del visor.
            sx = float(pdf_w) / float(rendered_w)
            sy = float(pdf_h) / float(rendered_h)
            x1 *= sx
            y_click = y1 * sy
            x2 = x1 + w * sx
            y2 = float(pdf_h) - y_click
            y1 = y2 - h * sy
        elif pdf_h:
            # Ya esta en puntos PDF, solo se invierte Y.
            x2 = x1 + w
            y2 = float(pdf_h) - y1
            y1 = y2 - h
        else:
            # Fallback: A4 595x842.
            x2 = x1 + w
            y2 = 842.0 - y1
            y1 = y2 - h
    else:
        # PDF_BOTTOM_LEFT: coordenadas ya en puntos PDF
        x1 = float(params.llx)
        y1 = float(params.lly)
        x2 = x1 + w
        y2 = y1 + h

    return page_0based, (
        int(round(x1)),
        int(round(y1)),
        int(round(x2)),
        int(round(y2)),
    )

def _build_stamp_style(params: PadesParams):
    """Crea un estilo de sello (TextStampStyle o FirmaEC)."""
    try:
        from pyhanko.stamp import TextStampStyle
    except Exception as exc:  # pragma: no cover
        log.warning("pyhanko.stamp no disponible: %s", exc)
        return None

    tipo = (params.tipo_estampado or "QR").upper()
    if tipo == "TEXT":
        signer = params.signer_name or "Firmante"
        return TextStampStyle(
            stamp_text=(
                f"Validar únicamente en FirmaEC.\n"
                f"Firmado electrónicamente por:\n"
                f"{signer}"
            ),
            border_width=1,
        )

    # QR: usa el sello FirmaEC custom con Pillow.
    from .stamp_firmaec import build_firmaec_stamp_style
    from datetime import datetime, timezone

    fecha_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    return build_firmaec_stamp_style(
        signer_name=params.signer_name or "FIRMANTE",
        razon=params.razon,
        fecha_iso=fecha_iso,
        width_pt=params.width,
        height_pt=params.height,
    )

def sign_pdf_bytes(
    *,
    pdf_bytes: bytes,
    certificate_der: Optional[bytes],
    certificate_chain_der: Optional[List[bytes]],
    digest_algorithm: str,
    signer_func: SignerFunc,
    params: PadesParams,
) -> bytes:
    """Firma el PDF. Devuelve bytes."""
    prepared = prepare_pdf_signature(
        pdf_bytes=pdf_bytes,
        certificate_der=certificate_der,
        certificate_chain_der=certificate_chain_der,
        digest_algorithm=digest_algorithm,
        params=params,
    )
    return prepared.sign(signer_func)


def prepare_pdf_signature(
    *,
    pdf_bytes: bytes,
    certificate_der: Optional[bytes],
    certificate_chain_der: Optional[List[bytes]],
    digest_algorithm: str,
    params: PadesParams,
) -> PreparedPdfSignature:
    """Prepare the appearance, byte range and CMS attributes before PIN entry."""
    if not _is_pdf(pdf_bytes):
        raise InvalidPdfError("El documento no es un PDF valido.")

    def prepare_marker() -> PreparedPdfSignature:
        return PreparedPdfSignature(
            _digest(pdf_bytes, digest_algorithm),
            digest_algorithm.lower(),
            lambda sig: _append_signature_marker(pdf_bytes, sig, digest_algorithm),
        )

    if not certificate_der:
        # No hay certificado real -> no se puede hacer PAdES valido.
        # Devolvemos un trailer de firma con la firma cruda (modo desarrollo).
        return prepare_marker()

    try:
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.sign.signers.pdf_signer import PdfSignatureMetadata, PdfSigner
        from pyhanko.sign.signers.pdf_cms import ExternalSigner
        from pyhanko.sign.fields import SigFieldSpec
    except Exception as exc:  # pragma: no cover
        log.warning("pyhanko no disponible, fallback: %s", exc)
        return prepare_marker()

    try:
        from cryptography import x509 as c_x509
        from cryptography.hazmat.backends import default_backend

        cert_crypto = c_x509.load_der_x509_certificate(certificate_der, default_backend())
        chain: List[c_x509.Certificate] = [cert_crypto]
        for der in certificate_chain_der or []:
            try:
                chain.append(c_x509.load_der_x509_certificate(der, default_backend()))
            except Exception:
                continue
    except Exception as exc:
        raise SignatureRejectedError(f"Certificado invalido: {exc}") from exc

    md_algorithm = {
        "SHA256": "sha256",
        "SHA384": "sha384",
        "SHA512": "sha512",
    }.get(digest_algorithm.upper(), "sha512")

    # Si no llegan tamano PDF y se necesita para top-left, lo leemos.
    if (
        params.coord_origin.upper() == "TOP_LEFT"
        and (not params.pdf_width or not params.pdf_height)
    ):
        size = _read_page_size(pdf_bytes)
        if size:
            params.pdf_width = params.pdf_width or size[0]
            params.pdf_height = params.pdf_height or size[1]

    page_0based, box = _resolve_box(params)
    field_name = f"LocalAPI-Sig-{int(time.time() * 1000)}"
    started = time.perf_counter()
    stamp_style = _build_stamp_style(params)
    log.info(
        "Signing timing: stage=stamp_render elapsed_ms=%.1f",
        (time.perf_counter() - started) * 1000,
    )

    log.info(
        "Firma visible: campo=%s page=%d box=%s estilo=%s signer=%s",
        field_name,
        page_0based,
        box,
        params.tipo_estampado,
        (params.signer_name or "")[:50],
    )

    new_field_spec = SigFieldSpec(
        sig_field_name=field_name,
        on_page=page_0based,
        box=box,
    )

    writer = IncrementalPdfFileWriter(io.BytesIO(pdf_bytes))
    meta = PdfSignatureMetadata(
        field_name=field_name,
        reason=params.razon,
        location="LocalAPI",
        embed_validation_info=False,
        md_algorithm=md_algorithm,
    )

    # Reserve space using the real RSA modulus size, without touching the key.
    try:
        from asn1crypto import x509 as a1_x509

        cert_a1 = a1_x509.Certificate.load(certificate_der)

        signature_size = (cert_crypto.public_key().key_size + 7) // 8
        signer_obj = ExternalSigner(
            signing_cert=cert_a1,
            cert_registry=None,
            signature_value=signature_size,
        )
    except Exception as exc:
        log.warning("No se pudo construir Signer de pyhanko, fallback a trailer: %s", exc)
        return prepare_marker()

    try:
        pdf_signer = PdfSigner(
            signature_meta=meta,
            signer=signer_obj,
            stamp_style=stamp_style,
            new_field_spec=new_field_spec,
        )

        async def prepare():
            digest, tbs, output = await pdf_signer.async_digest_doc_for_signing(
                writer, existing_fields_only=False, output=io.BytesIO()
            )
            attrs = await signer_obj.signed_attrs(
                digest.document_digest, md_algorithm, use_pades=tbs.use_pades
            )
            return digest, tbs, output, attrs

        started = time.perf_counter()
        prepared_digest, tbs_document, output, signed_attrs = asyncio.run(prepare())
        log.info(
            "Signing timing: stage=pdf_digest elapsed_ms=%.1f",
            (time.perf_counter() - started) * 1000,
        )
    except Exception as exc:
        log.exception("PAdES fallo: %s", exc)
        raise SignatureRejectedError(
            f"No se pudo crear la firma PAdES visible: {exc}"
        ) from exc

    def finish(signature: bytes) -> bytes:
        from pyhanko.sign.signers.pdf_signer import PdfTBSDocument

        async def embed():
            external_signer = ExternalSigner(
                signing_cert=cert_a1, cert_registry=None, signature_value=signature
            )
            cms = await external_signer.async_sign_prescribed_attributes(
                md_algorithm, signed_attrs=signed_attrs
            )
            await PdfTBSDocument.async_finish_signing(
                output,
                prepared_digest=prepared_digest,
                signature_cms=cms,
                post_sign_instr=tbs_document.post_sign_instructions,
            )

        try:
            started = time.perf_counter()
            asyncio.run(embed())
            log.info(
                "Signing timing: stage=cms_embed elapsed_ms=%.1f",
                (time.perf_counter() - started) * 1000,
            )
            return output.getvalue()
        except Exception as exc:
            raise SignatureRejectedError(
                f"No se pudo completar la firma PAdES: {exc}"
            ) from exc

    return PreparedPdfSignature(signed_attrs.dump(), md_algorithm, finish)


def _digest(data: bytes, algo: str) -> bytes:
    import hashlib

    return hashlib.new(algo.lower(), data).digest()


def _append_signature_marker(pdf: bytes, signature: bytes, algo: str) -> bytes:
    """Marca el PDF con un trailer reconocible (no es PAdES valido)."""
    header = f"\n%%LOCALAPI-SIG-ALGO:{algo}\n%%LOCALAPI-SIG-BEGIN\n".encode("ascii")
    footer = b"\n%%LOCALAPI-SIG-END\n"
    return pdf + header + signature + footer
