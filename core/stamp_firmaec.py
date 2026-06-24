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
    width_pt: float = 170.0,
    height_pt: float = 64.0,
) -> bytes:
    """Renderiza el sello FirmaEC como bytes PNG.

    Layout: area interna util ocupa el 94% del rectangulo. El QR
    va pegado al inicio del area util y el texto ocupa el resto
    del ancho. Altura al 100%. El nombre del firmante se divide
    en lineas que quepan en el espacio restante.
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

    scale = 2
    img_w = int(round(width_pt * scale))
    img_h = int(round(height_pt * scale))

    img = Image.new("RGB", (img_w, img_h), "white")
    draw = ImageDraw.Draw(img)

    visual_scale_y = 1.0

    font_small_size = int(round(6.0 * scale * visual_scale_y))
    font_bold_size = int(round(8.0 * scale * visual_scale_y))
    if _FONT_REGULAR:
        font_small = ImageFont.truetype(_FONT_REGULAR, font_small_size)
    else:
        font_small = ImageFont.load_default()
    if _FONT_BOLD:
        font_bold = ImageFont.truetype(_FONT_BOLD, font_bold_size)
    else:
        font_bold = font_small

    # QR: ocupa la mayor parte del alto del sello.
    qr_display = int(round(height_pt * 0.85 * scale * visual_scale_y))
    qr = qrcode.QRCode(box_size=3, border=2)
    qr.add_data(qr_payload)
    qr.make()
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    qr_img = qr_img.resize((qr_display, qr_display), Image.NEAREST)

    # Area util interna: 94% del ancho, centrada vertical.
    inner_w = int(img_w * 0.94)
    inner_x = (img_w - inner_w) // 2
    gap = int(round(3 * scale))  # espacio entre QR y texto
    margin_top = int(round(2 * scale))  # margen interno minimo

    qr_x = inner_x
    qr_y = (img_h - qr_display) // 2
    img.paste(qr_img, (qr_x, qr_y))

    # Texto: usa todo el ancho restante del area util.
    text_x = qr_x + qr_display + gap
    text_right = inner_x + inner_w
    text_max_w = text_right - text_x

    def _text_bbox(txt: str, ft):
        b = draw.textbbox((0, 0), txt, font=ft)
        return b[2] - b[0], b[3] - b[1]

    def _wrap_text(txt: str, ft, max_w: int) -> list[str]:
        """Divide el texto en lineas que quepan en max_w."""
        words = txt.split(" ")
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

    def _wrap_text_balanced(txt: str, ft, max_w: int, target_lines: int) -> list[str]:
        """Wrap favoreciendo exactamente ``target_lines`` lineas.

        Reparte las palabras intentando balancear el ancho entre
        las lineas resultantes. Si no es posible en target_lines,
        devuelve el wrap estandar.
        """
        words = txt.split(" ")
        if len(words) <= target_lines:
            return [txt]
        # Calcular wrap estandar primero
        greedy = _wrap_text(txt, ft, max_w)
        if len(greedy) <= target_lines:
            return greedy
        # Intentar balancear
        if _FONT_BOLD is None:
            return greedy
        # Calcular anchos de cada palabra
        word_widths = [(_text_bbox(w, ft)[0], w) for w in words]
        total = sum(ww for ww, _ in word_widths)
        # Construir lineas balanceadas por tamano objetivo
        target_per_line = total / target_lines
        lines: list[str] = []
        current: list[str] = []
        current_w = 0
        for ww, w in word_widths:
            if not current:
                current = [w]
                current_w = ww
                continue
            # Si anadir esta palabra se pasa de max_w, cerrar linea
            trial_text = " ".join(current + [w])
            trial_w = _text_bbox(trial_text, ft)[0]
            if trial_w > max_w and current:
                lines.append(" ".join(current))
                current = [w]
                current_w = ww
                continue
            # Si ya tenemos target_lines-1 lineas, forzar lo restante
            if len(lines) == target_lines - 1:
                lines.append(" ".join(current + [w]))
                current = []
                current_w = 0
                continue
            # Si current_w >= target_per_line, cerrar linea
            if current_w >= target_per_line and current:
                lines.append(" ".join(current))
                current = [w]
                current_w = ww
            else:
                current.append(w)
                current_w += ww
        if current:
            lines.append(" ".join(current))
        # Validar que todas quepan
        for ln in lines:
            if _text_bbox(ln, ft)[0] > max_w:
                return greedy
        return lines if lines else greedy

    line1 = "Validar unicamente en FirmaEC."
    line2 = "Firmado electronicamente por:"
    # Si las lineas secundarias no caben, reducir tamano hasta que quepan
    l1_w, l1_h = _text_bbox(line1, font_small)
    l2_w, l2_h = _text_bbox(line2, font_small)
    if max(l1_w, l2_w) > text_max_w:
        # Reducir tamano hasta que ambas quepan (minimo 4pt escalado).
        ratio_small = text_max_w / max(l1_w, l2_w)
        reduced_small_size = max(
            int(round(font_small_size * ratio_small)),
            int(round(4.0 * scale)),
        )
        font_small = (
            ImageFont.truetype(_FONT_REGULAR, reduced_small_size)
            if _FONT_REGULAR
            else font_small
        )
        l1_w, l1_h = _text_bbox(line1, font_small)
        l2_w, l2_h = _text_bbox(line2, font_small)

    # Wrap del nombre favoreciendo 2 lineas balanceadas.
    name_lines = _wrap_text_balanced(signer, font_bold, text_max_w, target_lines=2)
    name_font = font_bold
    # Si quedan 3+ lineas, reducir tamano del firmante.
    if len(name_lines) > 2:
        shrink = 0.85
        smaller_size = max(int(round(font_bold_size * shrink)), int(round(6 * scale)))
        smaller_bold = (
            ImageFont.truetype(_FONT_BOLD, smaller_size) if _FONT_BOLD else font_bold
        )
        name_lines = _wrap_text_balanced(signer, smaller_bold, text_max_w, target_lines=2)
        # Si aun no entran en 2 lineas, forzar wrap estandar
        if len(name_lines) > 2:
            name_lines = _wrap_text(signer, smaller_bold, text_max_w)
        name_font = smaller_bold

    name_line_heights = [_text_bbox(nl, name_font)[1] for nl in name_lines]
    line_gap = int(round(2 * scale * visual_scale_y))
    total_text_h = (
        l1_h
        + l2_h
        + sum(name_line_heights)
        + line_gap * (2 + len(name_lines) - 1)
    )
    y_start = max(margin_top, (img_h - total_text_h) // 2)

    y = y_start
    draw.text((text_x, y), line1, fill="black", font=font_small)
    y += l1_h + line_gap
    draw.text((text_x, y), line2, fill="black", font=font_small)
    y += l2_h + line_gap
    for nl, nl_h in zip(name_lines, name_line_heights):
        draw.text((text_x, y), nl, fill="black", font=name_font)
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
    width_pt: float = 170.0,
    height_pt: float = 64.0,
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
