"""Sello personalizado estilo FirmaEC.

Renderiza un QR + texto multiformato con Pillow y lo incrusta
como apariencia de firma PAdES via pyhanko.
"""
from __future__ import annotations

import io
import logging
import os
from typing import Optional

from PIL import Image as _PilImage
from pyhanko.stamp.base import BaseStamp

log = logging.getLogger(__name__)


_FONT_REGULAR: Optional[str] = None
_FONT_BOLD: Optional[str] = None


def _find_fonts() -> None:
    """Carga fuentes TrueType de Windows.

    Prioridad: Segoe UI (regular/bold) por mejor legibilidad.
    """
    global _FONT_REGULAR, _FONT_BOLD
    if _FONT_REGULAR is not None:
        return
    try:
        from PIL import ImageFont
    except ImportError:  # pragma: no cover
        return
    for path in (
        r"C:\Windows\Fonts\segoeui.ttf",
        r"C:\Windows\Fonts\verdana.ttf",
        r"C:\Windows\Fonts\calibri.ttf",
        r"C:\Windows\Fonts\arial.ttf",
    ):
        try:
            ImageFont.truetype(path, 10)
            _FONT_REGULAR = path
            break
        except Exception:
            continue
    for path in (
        r"C:\Windows\Fonts\segoeuib.ttf",
        r"C:\Windows\Fonts\verdanab.ttf",
        r"C:\Windows\Fonts\calibrib.ttf",
        r"C:\Windows\Fonts\arialbd.ttf",
    ):
        try:
            ImageFont.truetype(path, 10)
            _FONT_BOLD = path
            break
        except Exception:
            continue


def render_firmaec_stamp_png(
    *,
    signer_name: str,
    razon: str,
    fecha_iso: str,
    width_pt: float = 110.0,
    height_pt: float = 36.0,
) -> bytes:
    """Renderiza el sello FirmaEC como bytes PNG.

    QR de 36 puntos junto a texto de 3.25/6.25 puntos en el perfil
    de 110 x 36 puntos. El nombre se ajusta sin recortarlo.
    """
    import qrcode
    from PIL import Image, ImageDraw, ImageFont

    _find_fonts()

    signer = (signer_name or "FIRMANTE").upper()
    qr_payload = _build_qr_payload(
        signer_name=signer,
        razon=razon,
        fecha_iso=fecha_iso,
    )

    # Four pixels per PDF point preserves small type at 288 DPI.
    scale = 4
    img_w = int(round(width_pt * scale))
    img_h = int(round(height_pt * scale))

    img = Image.new("RGB", (img_w, img_h), "white")
    draw = ImageDraw.Draw(img)

    layout_scale = min(width_pt / 110.0, height_pt / 36.0)

    font_small_size = max(1, int(round(3.25 * scale * layout_scale)))
    font_bold_size = max(1, int(round(6.25 * scale * layout_scale)))

    def load_font(path, size):
        if path:
            return ImageFont.truetype(path, size)
        try:
            return ImageFont.load_default(size=size)
        except TypeError:  # Pillow 10.0 has a fixed-size default font.
            return ImageFont.load_default()

    font_small = load_font(_FONT_REGULAR, font_small_size)
    font_bold = load_font(_FONT_BOLD or _FONT_REGULAR, font_bold_size)

    # The reference QR occupies the full 36-point height.
    qr_display = int(round(36.0 * scale * layout_scale))
    qr = qrcode.QRCode(box_size=3, border=4)
    qr.add_data(qr_payload)
    qr.make()
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    qr_img = qr_img.resize((qr_display, qr_display), Image.NEAREST)

    gap = max(1, int(round((2 / 3) * scale * layout_scale)))
    margin_top = max(1, int(round(scale * layout_scale)))

    qr_x = 0
    qr_y = (img_h - qr_display) // 2
    img.paste(qr_img, (qr_x, qr_y))

    # Texto: usa todo el ancho restante del area util.
    text_x = qr_x + qr_display + gap
    text_right = img_w - margin_top
    text_max_w = text_right - text_x

    def _text_bbox(txt: str, ft):
        b = draw.textbbox((0, 0), txt, font=ft)
        return b[2] - b[0], b[3] - b[1]

    def _wrap_text(txt: str, ft, max_w: int) -> list[str]:
        """Divide el texto en lineas que quepan en max_w."""
        words = txt.split()
        lines: list[str] = []
        current = ""
        for word in words:
            test = (current + " " + word).strip()
            w, _ = _text_bbox(test, ft)
            if w <= max_w or not current:
                current = test
            else:
                lines.append(current)
                current = word
        if current:
            lines.append(current)
        return lines

    line1 = "Validar únicamente en FirmaEC."
    line2 = "Firmado electrónicamente por:"
    # Si las lineas secundarias no caben, reducir tamano hasta que quepan
    l1_w, l1_h = _text_bbox(line1, font_small)
    l2_w, l2_h = _text_bbox(line2, font_small)
    if max(l1_w, l2_w) > text_max_w:
        # Reduce secondary text only if the custom box requires it.
        ratio_small = text_max_w / max(l1_w, l2_w)
        reduced_small_size = max(
            int(round(font_small_size * ratio_small)),
            1,
        )
        font_small = load_font(_FONT_REGULAR, reduced_small_size)
        l1_w, l1_h = _text_bbox(line1, font_small)
        l2_w, l2_h = _text_bbox(line2, font_small)

    # Prefer two lines, but fit both width and height for longer names.
    name_lines = _wrap_text(signer, font_bold, text_max_w)
    name_font = font_bold
    line_gap = max(1, int(round(scale * layout_scale)))
    while True:
        name_line_heights = [_text_bbox(nl, name_font)[1] for nl in name_lines]
        total_text_h = l1_h + l2_h + sum(name_line_heights) + line_gap * (1 + len(name_lines))
        fits_width = all(_text_bbox(nl, name_font)[0] <= text_max_w for nl in name_lines)
        fits_height = total_text_h <= img_h - 2 * margin_top
        if fits_width and fits_height and len(name_lines) <= 2:
            break
        if font_bold_size <= 1:
            if not fits_width or not fits_height:
                raise ValueError("Signer name does not fit the signature stamp.")
            break
        font_bold_size -= 1
        name_font = load_font(_FONT_BOLD or _FONT_REGULAR, font_bold_size)
        name_lines = _wrap_text(signer, name_font, text_max_w)
    y_start = max(margin_top, (img_h - total_text_h) // 2)

    y = y_start
    draw.text((text_x, y), line1, fill="black", font=font_small, anchor="lt")
    y += l1_h + line_gap
    draw.text((text_x, y), line2, fill="black", font=font_small, anchor="lt")
    y += l2_h + line_gap
    for nl, nl_h in zip(name_lines, name_line_heights):
        draw.text((text_x, y), nl, fill="black", font=name_font, anchor="lt")
        y += nl_h + line_gap

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _build_qr_payload(
    *,
    signer_name: str,
    razon: str,
    fecha_iso: str,
) -> str:
    return (
        f"FIRMADO POR: {signer_name}\n"
        f"RAZON: {razon}\n"
        "LOCALIZACION: \n"
        f"FECHA: {fecha_iso}\n"
        "VALIDAR CON: www.firmadigital.gob.ec\n"
        "Firmado digitalmente con GadSign_Salcedo"
    )


class FirmaECStampStyle:
    """Estilo de sello FirmaEC: QR a la izquierda, texto a la derecha."""

    border_width: int = 0
    border_color = None
    background = None
    background_opacity: float = 1.0

    def __init__(self, *, png_bytes: bytes, stamp_width: float, stamp_height: float):
        self.png = png_bytes
        self.stamp_width = stamp_width
        self.stamp_height = stamp_height
        self.background_layout = None

    def create_stamp(self, writer, box, text_params):
        from pyhanko.pdf_utils.layout import BoxConstraints

        if not box.width_defined:
            box.width = self.stamp_width
        if not box.height_defined:
            box.height = self.stamp_height
        return FirmaECStamp(
            writer=writer, style=self, box=box, png_bytes=self.png
        )


class FirmaECStamp(BaseStamp):
    """Sello PAdES estilo FirmaEC, hereda de ``BaseStamp``."""

    def __init__(self, *, writer, style, box, png_bytes: bytes):
        super().__init__(writer=writer, style=style, box=box)
        self._png_bytes = png_bytes

    def _render_inner_content(self):
        """Renderiza la imagen QR+texto dentro del sello."""
        from pyhanko.pdf_utils import generic
        from pyhanko.pdf_utils.content import ResourceType
        from pyhanko.pdf_utils.generic import pdf_name

        img = _PilImage.open(io.BytesIO(self._png_bytes))
        w, h = img.size
        raw = img.convert("RGB").tobytes("raw", "RGB")
        xobj_stream = generic.StreamObject(stream_data=raw)
        xobj_stream.compress()
        xobj_stream[pdf_name("/Type")] = pdf_name("/XObject")
        xobj_stream[pdf_name("/Subtype")] = pdf_name("/Image")
        xobj_stream[pdf_name("/Width")] = generic.NumberObject(w)
        xobj_stream[pdf_name("/Height")] = generic.NumberObject(h)
        xobj_stream[pdf_name("/ColorSpace")] = pdf_name("/DeviceRGB")
        xobj_stream[pdf_name("/BitsPerComponent")] = generic.NumberObject(8)
        xobj_stream[pdf_name("/Filter")] = pdf_name("/FlateDecode")

        img_ref_name = "/Img" + os.urandom(4).hex()
        img_ref = self.writer.add_object(xobj_stream)
        self.set_resource(
            ResourceType.XOBJECT,
            pdf_name(img_ref_name),
            img_ref,
        )

        bbox = self.box
        draw = b"%g 0 0 %g 0 0 cm %s Do" % (
            bbox.width,
            bbox.height,
            img_ref_name.encode("ascii"),
        )
        return [draw]


def build_firmaec_stamp_style(
    *,
    signer_name: str,
    razon: str,
    fecha_iso: str,
    width_pt: float = 110.0,
    height_pt: float = 36.0,
) -> FirmaECStampStyle:
    """Crea el estilo de sello FirmaEC listo para pyhanko ``PdfSigner``."""
    png = render_firmaec_stamp_png(
        signer_name=signer_name,
        razon=razon,
        fecha_iso=fecha_iso,
        width_pt=width_pt,
        height_pt=height_pt,
    )
    return FirmaECStampStyle(png_bytes=png, stamp_width=width_pt, stamp_height=height_pt)
