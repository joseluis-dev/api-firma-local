"""Capa de servicio: orquesta drivers, PIN, validaciones y firma PAdES."""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import List, Optional

from ..config import settings
from .config_store import config_store
from .crypto_utils import (
    decode_base64,
    encode_base64,
    is_pdf,
    sha256_hex,
)
from .drivers.base import SignatureRequest, TokenDriver
from .drivers.factory import get_driver, has_real_driver, list_available_providers
from .errors import (
    CertificateNotFoundError,
    InvalidInputError,
    InvalidPdfError,
    LocalApiError,
    PinInvalidError,
    PinRequiredError,
    TimeoutError_,
    TokenLockedError,
    UserCancelledError,
)
from .pdf_signer import PadesParams, sign_pdf_bytes
from .pin_dialog import ask_pin
from .schemas import (
    CertificateInfo,
    CertificadosResponse,
    FirmaLocalInfo,
    FirmarPdfResponse,
)


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cache de PIN en memoria, por token.
# - Solo dura ``PIN_CACHE_TTL_SECONDS`` para reducir la ventana de exposicion.
# - Se invalida ante PIN_INVALID / TOKEN_LOCKED / timeout / cancelacion.
# - Un lock por token evita dos dialogos de PIN simultaneos.
# ---------------------------------------------------------------------------


class _PinCache:
    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._entry_lock = threading.Lock()
        self._data: dict[str, tuple[str, float]] = {}

    def get(self, key: str) -> Optional[str]:
        if self._ttl <= 0:
            return None
        with self._lock:
            entry = self._data.get(key)
            if not entry:
                return None
            pin, ts = entry
            if time.monotonic() - ts > self._ttl:
                self._data.pop(key, None)
                return None
            return pin

    def put(self, key: str, pin: str) -> None:
        if self._ttl <= 0:
            return
        with self._lock:
            self._data[key] = (pin, time.monotonic())

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def entry_lock(self, key: str) -> threading.Lock:
        with self._entry_lock:
            lock = self._data.get(("__lock__", key))
            if lock is None:
                lock = threading.Lock()
                self._data[("__lock__", key)] = lock  # type: ignore[assignment]
            return lock


_pin_cache = _PinCache(ttl_seconds=settings.pin_cache_ttl_seconds)

_pin_ttl_provider = False


def _pin_cache_ttl() -> int:
    try:
        return config_store.get().pin_cache_ttl_seconds
    except Exception:
        return settings.pin_cache_ttl_seconds


def _sign_timeout() -> int:
    try:
        return config_store.get().sign_timeout_seconds
    except Exception:
        return settings.sign_timeout_seconds


def _request_timeout() -> int:
    try:
        return config_store.get().request_timeout_seconds
    except Exception:
        return settings.request_timeout_seconds


# ---------------------------------------------------------------------------
# Cache de certificados por token.
# Se llena al llamar a /certificados y se consulta en /firmar/pdf.
# Solo almacena metadata publica; nunca PIN, ni DER completo.
# ---------------------------------------------------------------------------


class _CertCache:
    def __init__(self) -> None:
        self._data: dict[str, list[dict]] = {}

    def put(self, key: str, certs: list) -> None:
        # Guardamos solo la metadata publica (no DER, no PIN).
        self._data[key] = [
            {
                "id": c.id,
                "cedula": c.cedula,
                "subject": c.subject,
                "issuer": c.issuer,
                "serial": c.serial,
                "validFrom": c.validFrom,
                "validTo": c.validTo,
                "provider": c.provider,
                "tokenLabel": c.tokenLabel,
                "displayName": c.displayName,
                "shortName": c.shortName,
                "type": c.type,
                "isCa": c.isCa,
                "hasPrivateKey": c.hasPrivateKey,
                "signable": c.signable,
            }
            for c in certs
        ]

    def get(self, key: str) -> list[dict]:
        return list(self._data.get(key, []))

    def find(self, key: str, cert_id: str) -> Optional[dict]:
        for c in self._data.get(key, []):
            if c.get("id") == cert_id:
                return c
        return None

    def clear(self, key: Optional[str] = None) -> None:
        if key is None:
            self._data.clear()
        else:
            self._data.pop(key, None)


_cert_cache = _CertCache()


def _resolve_pin(pin_mode: str, inline_pin: Optional[str]) -> Optional[str]:
    if pin_mode == "INLINE":
        return inline_pin
    if pin_mode == "LOCAL_PROMPT":
        return None  # se solicita en el driver
    if pin_mode == "NONE":
        return None
    raise InvalidInputError(f"pinMode {pin_mode} no soportado.")


def _capture_pin(
    pin_mode: str,
    inline_pin: Optional[str],
    token_label: str,
    cache_key: Optional[str] = None,
) -> str:
    if pin_mode == "INLINE":
        if not inline_pin:
            raise PinRequiredError("pinMode=INLINE requiere el PIN en el body.")
        return inline_pin
    if pin_mode == "LOCAL_PROMPT":
        if cache_key:
            cached = _pin_cache.get(cache_key)
            if cached is not None:
                log.debug("PIN servido desde cache (token=%s)", token_label)
                return cached
        pin = ask_pin(token_label)
        if cache_key and pin:
            _pin_cache.put(cache_key, pin)
        return pin
    if pin_mode == "NONE":
        return ""
    raise InvalidInputError(f"pinMode {pin_mode} no soportado.")


def _run_with_timeout(func, timeout_s: int):
    """Ejecuta ``func`` con un timeout duro. Lanza TimeoutError_ si expira."""
    import threading

    result_box: dict = {}

    def worker() -> None:
        try:
            result_box["value"] = func()
        except Exception as exc:
            result_box["error"] = exc

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout_s)
    if t.is_alive():
        raise TimeoutError_(f"Operacion excedio {timeout_s}s.")
    if "error" in result_box:
        raise result_box["error"]
    return result_box.get("value")


class TokenService:
    """Punto unico que el API HTTP consume."""

    def __init__(self) -> None:
        self._pin_attempts: dict[str, int] = {}

    def health(self, version: str) -> dict:
        providers = list_available_providers()
        real = has_real_driver()
        capabilities = ["PDF_PADES_TOKEN", "CERTIFICATE_LIST"]
        return {
            "status": "ok" if real else "degraded",
            "version": version,
            "capabilities": capabilities,
            "providers": providers,
        }

    @staticmethod
    def _cache_key(provider: str, token_label: str) -> str:
        return f"{provider.upper()}|{token_label}"

    def _capture_pin_cached(
        self,
        pin_mode: str,
        inline_pin: Optional[str],
        provider: str,
        token_label: str,
    ) -> str:
        """Captura el PIN serializando dialogos concurrentes por token.

        Si otro hilo esta pidiendo el PIN del mismo token, espera a que
        termine y reusa el resultado.
        """
        cache_key = self._cache_key(provider, token_label) if pin_mode == "LOCAL_PROMPT" else None
        lock = _pin_cache.entry_lock(cache_key or "__noprompt__")

        with lock:
            return _capture_pin(pin_mode, inline_pin, token_label, cache_key=cache_key)

    def _capture_pin_for_driver(
        self,
        pin_mode: str,
        inline_pin: Optional[str],
        driver: TokenDriver,
        token_label: str,
    ) -> str:
        """Captura PIN usando la identidad real del driver para el cache.

        Esto evita que un mismo token con providers logicos distintos
        (AUTO vs SAFENET) tenga caches de PIN separados.
        """
        return self._capture_pin_cached(
            pin_mode, inline_pin, driver.provider_id, token_label
        )

    def list_certificates(
        self,
        *,
        provider: str,
        tipo: str,
        pin_mode: str,
        inline_pin: Optional[str],
        request_timeout_s: int,
    ) -> CertificadosResponse:
        driver = get_driver(provider, tipo)
        token_label = driver.get_token_label() if driver.is_available() else "Token"
        # Usar la identidad real del driver para que el cache de PIN
        # coincida con el provider real aunque el frontend mande "AUTO".
        real_provider = driver.provider_id
        cache_key = self._cache_key(real_provider, token_label)

        # Listar certificados NO requiere PIN: la mayoria de tokens
        # permiten sesion publica (read-only) para enumerar los
        # certificados publicos del token. Si el driver no lo soporta,
        # devolvera ``PinRequiredError`` y se propaga.
        def _do_list() -> List[CertificateInfo]:
            return driver.list_certificates(pin=None)

        try:
            certs = _run_with_timeout(_do_list, request_timeout_s)
        except LocalApiError as exc:
            self._invalidate_pin_on_error(exc, cache_key)
            raise

        # Almacenar en cache para reutilizar en /firmar/pdf
        _cert_cache.put(cache_key, certs)
        return CertificadosResponse(certificados=certs)

    @staticmethod
    def _invalidate_pin_on_error(exc: LocalApiError, cache_key: Optional[str]) -> None:
        if not cache_key:
            return
        code = exc.code.value
        if code in {
            "PIN_INVALID",
            "PIN_REQUIRED",
            "TOKEN_LOCKED",
            "USER_CANCELLED",
            "TIMEOUT",
        }:
            _pin_cache.invalidate(cache_key)

    def sign_pdf(
        self,
        *,
        documento_base64: str,
        documento_sha256: str,
        certificado_id: str,
        provider: str,
        tipo: str,
        pin_mode: str,
        inline_pin: Optional[str],
        firma_params: dict,
        metadata_b64: Optional[str],
        request_timeout_s: int,
        sign_timeout_s: Optional[int] = None,
    ) -> FirmarPdfResponse:
        # 1. Decodificar y validar PDF
        try:
            pdf_bytes = decode_base64(documento_base64)
        except ValueError as exc:
            raise InvalidInputError(str(exc)) from exc
        if not is_pdf(pdf_bytes):
            raise InvalidPdfError("El documento no es un PDF valido.")

        # 2. Validar hash
        actual_hash = sha256_hex(pdf_bytes)
        if actual_hash.lower() != documento_sha256.lower():
            raise InvalidInputError(
                f"SHA-256 no coincide. Esperado={documento_sha256} Real={actual_hash}"
            )

        # 3. Cargar driver
        driver = get_driver(provider, tipo)
        if not driver.is_available():
            from .errors import TokenNotFoundError, DriverNotFoundError

            try:
                driver.get_token_label()
                raise TokenNotFoundError("Driver detectado pero token no presente.")
            except TokenNotFoundError:
                raise
            except Exception:
                raise DriverNotFoundError("Driver de token no disponible.")

        # 4. Buscar metadata del certificado en cache (sin re-listar, sin PIN)
        token_label = driver.get_token_label()
        real_provider = driver.provider_id
        cache_key = self._cache_key(real_provider, token_label)

        cached = _cert_cache.find(cache_key, certificado_id)
        if cached is None:
            # No esta en cache: leerlo del token sin PIN.
            try:
                single_info = _run_with_timeout(
                    lambda: driver.get_certificate_info(certificado_id, pin=None),
                    request_timeout_s,
                )
            except LocalApiError:
                raise
            except Exception as exc:
                raise LocalApiError(
                    f"No se pudo leer el certificado {certificado_id!r}: {exc}"
                ) from exc
            _cert_cache.put(cache_key, [type("C", (), single_info)()])
            cached = single_info

        if not cached.get("signable", False):
            raise CertificateNotFoundError(
                f"El certificado {certificado_id!r} no es firmable "
                f"(type={cached.get('type', '?')}, "
                f"isCa={cached.get('isCa', '?')}, "
                f"hasPrivateKey={cached.get('hasPrivateKey', '?')}). "
                "Use un certificado con signable=true (Signing Certificate / User Certificate)."
            )

        # 5. expectedCedula se ignora: el frontend puede enviarla o no.
        # La API no valida la cedula contra el certificado.

        cert = type(
            "Cert",
            (),
            {
                "id": cached["id"],
                "cedula": cached.get("cedula", ""),
                "subject": cached.get("subject", ""),
                "issuer": cached.get("issuer", ""),
                "serial": cached.get("serial", ""),
                "validFrom": cached.get("validFrom"),
                "validTo": cached.get("validTo"),
            },
        )()

        # 6. Preparar placement
        signer_name = _resolve_signer_name(cached)
        placement = _resolve_placement(firma_params)
        placement["box"] = _scale_box_centered(placement["box"], 0.90)
        log.info(
            "placement source=%s page=%d box=%s signer=%s",
            placement.get("source"),
            placement["page"],
            placement["box"],
            signer_name,
        )

        pades_params = PadesParams(
            page=placement["page"],
            llx=float(placement["box"][0]),
            lly=float(placement["box"][1]),
            width=float(placement["box"][2] - placement["box"][0]),
            height=float(placement["box"][3] - placement["box"][1]),
            razon=firma_params.get("razon", "Firmado digitalmente"),
            tipo_estampado=firma_params.get("tipoEstampado", "QR"),
            digest_algorithm="SHA512",
            coord_origin="PDF_BOTTOM_LEFT",
            qr_url=firma_params.get("qrUrl"),
            qr_content=firma_params.get("qrContent"),
            qr_text=firma_params.get("qrText"),
            signer_name=signer_name,
            serial=str(cached.get("serial", "")),
            cedula=str(cached.get("cedula", "")),
            issuer=str(cached.get("issuer", "")),
        )

        # 7. Capturar PIN solo justo antes de firmar.
        sign_timeout = sign_timeout_s or _sign_timeout()
        log.info(
            "Iniciando firma PDF: provider=%s cert=%s sign_timeout=%ss",
            driver.provider_id,
            certificado_id,
            sign_timeout,
        )

        pin: Optional[str] = None
        if pin_mode in {"LOCAL_PROMPT", "INLINE"}:
            try:
                pin = _run_with_timeout(
                    lambda: self._capture_pin_for_driver(
                        pin_mode, inline_pin, driver, token_label
                    ),
                    request_timeout_s,
                )
            except LocalApiError as exc:
                self._invalidate_pin_on_error(exc, cache_key)
                raise

        try:
            if driver.provider_id == "MOCK":
                signed = self._sign_with_driver(driver, pdf_bytes, pades_params, pin, certificado_id)
            else:
                signed = self._run_sign_with_timeout(
                    driver, pdf_bytes, pades_params, pin, certificado_id, sign_timeout
                )
        except LocalApiError as exc:
            self._invalidate_pin_on_error(exc, cache_key)
            raise

        return FirmarPdfResponse(
            documentoFirmadoBase64=encode_base64(signed),
            documentoOriginalSha256=actual_hash,
            certificado={
                "cedula": cert.cedula,
                "serial": cert.serial,
                "subject": cert.subject,
                "issuer": cert.issuer,
                "validFrom": cert.validFrom,
                "validTo": cert.validTo,
            },
            firmaLocal=FirmaLocalInfo(
                provider=driver.provider_id,
                driver=driver.driver_kind,
                algorithm=pades_params.digest_algorithm + "withTOKEN",
                signedAt=datetime.now(timezone.utc),
            ),
        )

    def _sign_with_driver(
        self,
        driver: TokenDriver,
        pdf_bytes: bytes,
        params: PadesParams,
        pin: Optional[str],
        cert_id: str,
    ) -> bytes:
        """Para driver mock: firma "decorativa" con hash al final del PDF."""
        from hashlib import sha512

        sig_req = SignatureRequest(
            data=sha512(pdf_bytes).digest(),
            algorithm=params.digest_algorithm,
            pin=pin or "1234",
            key_alias=cert_id,
        )
        result = driver.sign(sig_req)
        # Devuelve el PDF intacto + un trailer de firma. Solo para mock.
        trailer = (
            b"\n%%LOCALAPI-MOCK-SIG:\n"
            + result.signature
            + b"\n%%END-SIG\n"
        )
        return pdf_bytes + trailer

    def _sign_pades(
        self,
        driver: TokenDriver,
        pdf_bytes: bytes,
        params: PadesParams,
        pin: Optional[str],
        cert_id: str,
    ) -> bytes:
        """Firma PAdES real usando el driver para obtener cert + signature."""

        def sign_func(data: bytes, md_algo: str) -> bytes:
            algo_name = {
                "sha256": "SHA256",
                "sha384": "SHA384",
                "sha512": "SHA512",
            }.get(md_algo.lower(), "SHA512")
            return driver.sign(
                SignatureRequest(
                    data=data,
                    algorithm=algo_name,
                    pin=pin or "",
                    key_alias=cert_id,
                )
            ).signature

        # Necesitamos el cert_der del alias.
        cert_der = self._get_cert_der(driver, cert_id, pin)
        if not cert_der:
            raise CertificateNotFoundError(
                f"No se pudo obtener el certificado DER para alias={cert_id!r}. "
                "El driver no expuso get_certificate_der."
            )

        return sign_pdf_bytes(
            pdf_bytes=pdf_bytes,
            certificate_der=cert_der,
            certificate_chain_der=[cert_der],
            digest_algorithm=params.digest_algorithm,
            signer_func=sign_func,
            params=params,
        )

    def _get_cert_der(
        self, driver: TokenDriver, cert_id: str, pin: Optional[str]
    ) -> Optional[bytes]:
        """Intenta obtener el certificado en formato DER desde el driver."""
        getter = getattr(driver, "get_certificate_der", None)
        if callable(getter):
            try:
                return getter(cert_id=cert_id, pin=pin)
            except Exception as exc:
                log.debug("get_certificate_der fallo: %s", exc)
        return None

    def _run_sign_with_timeout(
        self,
        driver: TokenDriver,
        pdf_bytes: bytes,
        params: PadesParams,
        pin: Optional[str],
        cert_id: str,
        timeout_s: int,
    ) -> bytes:
        """Firma con timeout duro para soportar Touch Sense del token."""
        box: dict = {}

        def worker() -> None:
            try:
                box["value"] = self._sign_pades(
                    driver, pdf_bytes, params, pin, cert_id
                )
            except Exception as exc:
                box["error"] = exc

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout_s)
        if t.is_alive():
            log.warning(
                "Firma cancelada por timeout (%ss). Token probablemente "
                "esperando confirmacion Touch Sense.",
                timeout_s,
            )
            from .errors import TimeoutError_

            raise TimeoutError_(
                f"Firma excedio {timeout_s}s. El token no respondio. "
                "Asegurese de presionar el token fisico (Touch Sense)."
            )
        if "error" in box:
            raise box["error"]
        return box.get("value")


def sha512_digest(pdf_bytes: bytes) -> bytes:
    from hashlib import sha512

    return sha512(pdf_bytes).digest()


def _as_float(value) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value, default: int = 1) -> int:
    f = _as_float(value)
    if f is None:
        return default
    return int(f)


def _extract_cn(subject: str) -> Optional[str]:
    """Extrae el CN de un subject RFC4514. Devuelve None si no hay."""
    if not subject:
        return None
    for part in subject.split(","):
        kv = part.strip().split("=", 1)
        if len(kv) == 2 and kv[0].strip().upper() == "CN":
            return kv[1].strip()
    return None


def _resolve_signer_name(cached: dict) -> str:
    """Devuelve el nombre del firmante en mayusculas.

    Prioridad: shortName > CN del subject > displayName limpiando
    prefijos como 'Firma digital - '.
    """
    if cached.get("shortName"):
        return str(cached["shortName"]).upper()
    cn = _extract_cn(str(cached.get("subject", "")))
    if cn:
        return cn.upper()
    display = str(cached.get("displayName", "")).strip()
    for prefix in ("Firma digital - ", "Autenticacion - "):
        if display.startswith(prefix):
            display = display[len(prefix):]
    return display.upper() if display else "FIRMANTE"


def _resolve_placement(firma_params: dict) -> dict:
    """Resuelve la ubicacion exacta de la firma en puntos PDF.

    Devuelve ``{"source": str, "page": int, "box": (x1,y1,x2,y2)}``
    con origen bottom-left (sistema PDF). El box es el rectangulo de
    la firma visible.

    Prioridad:
    1. ``firma.rectangulo``  (fuente de verdad para el flujo token)
    2. ``firma.ubicacion`` con coordinateSystem/PDF_POINTS + origin/BOTTOM_LEFT
    3. ``firma.ubicacion`` con x/y/width/height y origin/TOP_LEFT
    4. ``firma.x``/``firma.y``/``firma.width``/``firma.height`` top-level
    5. fallback legacy ``firma.llx``/``firma.lly``/``firma.ancho``/``firma.alto``
    """
    # 1. rectangulo (fuente de verdad)
    rect = firma_params.get("rectangulo")
    if isinstance(rect, dict) and all(
        _as_float(rect.get(k)) is not None
        for k in ("lowerLeftX", "lowerLeftY", "upperRightX", "upperRightY")
    ):
        page = (
            _as_int(firma_params.get("page"))
            or _as_int(firma_params.get("pagina"))
            or 1
        )
        return {
            "source": "rectangulo",
            "page": page,
            "box": (
                int(round(_as_float(rect["lowerLeftX"]) or 0)),
                int(round(_as_float(rect["lowerLeftY"]) or 0)),
                int(round(_as_float(rect["upperRightX"]) or 0)),
                int(round(_as_float(rect["upperRightY"]) or 0)),
            ),
        }

    # 2. ubicacion
    ubi = firma_params.get("ubicacion")
    if isinstance(ubi, dict):
        page = (
            _as_int(ubi.get("page"))
            or _as_int(ubi.get("pagina"))
            or _as_int(firma_params.get("page"))
            or _as_int(firma_params.get("pagina"))
            or 1
        )

        origin = str(ubi.get("origin", "")).upper()
        cs = str(ubi.get("coordinateSystem", "")).upper()

        if "BOTTOM" in origin or "PDF" in cs:
            x = _as_float(ubi.get("x")) or 0.0
            y = _as_float(ubi.get("y")) or 0.0
            w = _as_float(ubi.get("width")) or 200.0
            h = _as_float(ubi.get("height")) or 70.0
            if w <= 0:
                w = 170.0
            if h <= 0:
                h = 64.0
            return {
                "source": "ubicacion_bottom_left",
                "page": page,
                "box": (
                    int(round(x)),
                    int(round(y)),
                    int(round(x + w)),
                    int(round(y + h)),
                ),
            }

        if "TOP" in origin:
            x = _as_float(ubi.get("x")) or 0.0
            y = _as_float(ubi.get("y")) or 0.0
            w = _as_float(ubi.get("width")) or 200.0
            h = _as_float(ubi.get("height")) or 70.0
            ph = _as_float(ubi.get("pageHeight")) or _as_float(firma_params.get("pageHeight")) or 842.0
            if w <= 0:
                w = 170.0
            if h <= 0:
                h = 64.0
            return {
                "source": "ubicacion_top_left",
                "page": page,
                "box": (
                    int(round(x)),
                    int(round(ph - y - h)),
                    int(round(x + w)),
                    int(round(ph - y)),
                ),
            }

    # 3. top-level x/y/width/height
    x = _as_float(firma_params.get("x"))
    y = _as_float(firma_params.get("y"))
    if x is not None and y is not None:
        page = (
            _as_int(firma_params.get("page"))
            or _as_int(firma_params.get("pagina"))
            or 1
        )
        w = _as_float(firma_params.get("width")) or 200.0
        h = _as_float(firma_params.get("height")) or 70.0
        ph = _as_float(firma_params.get("pageHeight")) or 842.0
        if w <= 0:
            w = 170.0
        if h <= 0:
            h = 70.0
        return {
            "source": "top_level_xy",
            "page": page,
            "box": (
                int(round(x)),
                int(round(ph - y - h)),
                int(round(x + w)),
                int(round(ph - y)),
            ),
        }

    # 4. fallback legacy
    page = (
        _as_int(firma_params.get("page"))
        or _as_int(firma_params.get("pagina"))
        or 1
    )
    lx = _as_float(firma_params.get("llx")) or 120.0
    ly = _as_float(firma_params.get("lly")) or 180.0
    w = _as_float(firma_params.get("width")) or _as_float(firma_params.get("ancho")) or 200.0
    h = _as_float(firma_params.get("height")) or _as_float(firma_params.get("alto")) or 70.0
    if w <= 0:
        w = 170.0
    if h <= 0:
        h = 64.0
    return {
        "source": "legacy_llx_lly",
        "page": page,
        "box": (
            int(round(lx)),
            int(round(ly)),
            int(round(lx + w)),
            int(round(ly + h)),
        ),
    }


def _scale_box_centered(box, factor: float):
    """Escala el rectangulo manteniendo el mismo centro.

    Sirve para reducir (o aumentar) el tamano del campo de firma
    sin cambiar la posicion visual.
    """
    if factor == 1.0:
        return box
    x1, y1, x2, y2 = box
    cx = (x1 + x2) / 2
    cy = (y1 + y2) / 2
    w = (x2 - x1) * factor
    h = (y2 - y1) * factor
    return (
        int(round(cx - w / 2)),
        int(round(cy - h / 2)),
        int(round(cx + w / 2)),
        int(round(cy + h / 2)),
    )


token_service = TokenService()
