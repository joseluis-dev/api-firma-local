"""Driver PKCS#11 usando ``python-pkcs11``.

Soporta los vendors que exponen un PKCS#11 estandar:
ePass3003, Bit4Id, Safenet, UKC, etc.
"""
from __future__ import annotations

import logging
from typing import Any, List, Optional

from ..errors import (
    CertificateNotFoundError,
    DriverNotFoundError,
    PinInvalidError,
    TokenLockedError,
    TokenNotFoundError,
)
from ..schemas import CertificateInfo
from .base import SignatureRequest, SignatureResult, TokenDriver, certificate_info_from_x509


log = logging.getLogger(__name__)

_ALG_MAP = {
    "SHA256": "SHA256_RSA_PKCS",
    "SHA384": "SHA384_RSA_PKCS",
    "SHA512": "SHA512_RSA_PKCS",
}


def _import_pkcs11():
    try:
        import pkcs11  # type: ignore
        from pkcs11 import constants  # type: ignore

        # En python-pkcs11 0.8.x, Mechanism vive en el modulo raiz,
        # no en ``constants``. Lo exponemos bajo ``constants.Mechanism``
        # para mantener compatibilidad con el resto del codigo.
        if not hasattr(constants, "Mechanism"):
            constants.Mechanism = pkcs11.Mechanism  # type: ignore[attr-defined]
        return pkcs11, constants
    except Exception as exc:  # pragma: no cover - opcional
        raise DriverNotFoundError(
            "Libreria python-pkcs11 no disponible. "
            "Instala con: pip install python-pkcs11"
        ) from exc


def _attr(obj: Any, attr: Any, default: Any = None) -> Any:
    """Acceso tolerante a atributos PKCS#11 (no todos los objetos tienen
    todos los atributos)."""
    try:
        return obj[attr]
    except (KeyError, AttributeError, TypeError):
        return default


def _label_of(obj: Any, constants: Any) -> str:
    val = _attr(obj, constants.Attribute.LABEL, b"")
    if val is None:
        return ""
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="ignore").rstrip("\x00").strip()
        except Exception:
            return ""
    return str(val).rstrip("\x00").strip()


def _id_of(obj: Any, constants: Any) -> str:
    val = _attr(obj, constants.Attribute.ID, b"")
    if isinstance(val, (bytes, bytearray)):
        return val.hex()
    return str(val) if val else ""


class Pkcs11Driver(TokenDriver):
    provider_id = "PKCS11"
    provider_name = "PKCS#11 Generic"
    driver_kind = "PKCS11"

    def __init__(self, module_path: str) -> None:
        if not module_path:
            raise DriverNotFoundError(
                "PKCS11_MODULE_PATH no configurado. Define la ruta a la DLL/SO del fabricante."
            )
        self._module_path = module_path

    def is_available(self) -> bool:
        try:
            pkcs11, _ = _import_pkcs11()
            pkcs11.lib(self._module_path)
            return True
        except Exception as exc:
            log.info("PKCS11 lib no disponible: %s", exc)
            return False

    def _open_session(self, pin: Optional[str] = None):
        pkcs11, _ = _import_pkcs11()
        try:
            lib = pkcs11.lib(self._module_path)
        except Exception as exc:
            raise DriverNotFoundError(
                f"No se pudo cargar la libreria PKCS#11 {self._module_path}: {exc}"
            ) from exc

        try:
            tokens = list(lib.get_tokens())
        except Exception as exc:
            raise TokenNotFoundError(f"No se detectaron tokens: {exc}") from exc
        if not tokens:
            raise TokenNotFoundError("No hay tokens PKCS#11 insertados.")

        token = tokens[0]
        try:
            if pin:
                return token.open(user_pin=pin)
            return token.open()
        except Exception as exc:
            self._map_session_error(exc)
            raise  # type: ignore[misc]

    @staticmethod
    def _map_session_error(exc: Exception) -> None:
        msg = str(exc).lower()
        type_name = type(exc).__name__.lower()
        if "locked" in msg or "locked" in type_name or "ckr_pin_locked" in msg:
            raise TokenLockedError("Token bloqueado por intentos fallidos.") from exc
        if (
            "incorrect" in msg
            or "invalid" in msg
            or "ckr_pin_incorrect" in msg
            or "pinincorrect" in type_name
        ):
            raise PinInvalidError("PIN incorrecto.") from exc
        # Cualquier otro error -> PIN invalido por defecto
        raise PinInvalidError(f"No se pudo abrir sesion: {exc}") from exc

    def get_token_label(self) -> str:
        try:
            pkcs11, _ = _import_pkcs11()
            lib = pkcs11.lib(self._module_path)
            for token in lib.get_tokens():
                return token.label or "PKCS#11 Token"
        except Exception as exc:
            log.info("Token label no disponible: %s", exc)
        return "PKCS#11 Token"

    def list_certificates(
        self,
        *,
        pin: Optional[str] = None,
        expected_cedula: Optional[str] = None,
    ) -> List[CertificateInfo]:
        pkcs11, constants = _import_pkcs11()
        token_label = self.get_token_label()
        # Si se pasa PIN intentamos sesion autenticada para enumerar
        # claves privadas. Si no, sesion publica (no requiere PIN).
        try:
            session_cm = self._open_session(pin) if pin else self._open_session()
        except (PinInvalidError, TokenLockedError):
            if pin is not None:
                # Si nos dieron PIN pero no abrio, propagar error
                raise
            # Sin PIN, reintentar: algunos tokens no soportan sesion
            # publica y requieren PIN. Devolvemos un error claro.
            from ..errors import PinRequiredError
            raise PinRequiredError(
                "El token requiere PIN para listar certificados."
            )

        with session_cm as session:
            certs: List[CertificateInfo] = []
            discarded: List[str] = []

            # Enumerar claves privadas solo si tenemos sesion autenticada.
            priv_keys: list = []
            if pin:
                try:
                    priv_keys = list(
                        session.get_objects(
                            {
                                constants.Attribute.CLASS: (
                                    constants.ObjectClass.PRIVATE_KEY
                                )
                            }
                        )
                    )
                except Exception as exc:
                    log.debug("No se pudieron enumerar claves privadas: %s", exc)
            priv_labels = {_label_of(k, constants) for k in priv_keys}
            priv_ids = {_id_of(k, constants) for k in priv_keys}
            log.info(
                "PKCS#11 expone %d clave(s) privada(s) (token=%s)",
                len(priv_keys),
                token_label,
            )

            try:
                cert_objects = list(
                    session.get_objects(
                        {
                            constants.Attribute.CLASS: constants.ObjectClass.CERTIFICATE
                        }
                    )
                )
            except Exception as exc:
                raise DriverNotFoundError(
                    f"No se pudieron enumerar certificados: {exc}"
                ) from exc

            log.info(
                "PKCS#11 devolvio %d objetos CERTIFICATE (token=%s)",
                len(cert_objects),
                token_label,
            )

            for obj in cert_objects:
                cert_der = bytes(_attr(obj, constants.Attribute.VALUE, b""))
                if not cert_der:
                    continue
                if cert_der[:1] != b"\x30":
                    discarded.append("der-invalido")
                    continue
                label = _label_of(obj, constants) or _id_of(obj, constants)
                obj_id = _id_of(obj, constants)
                alias = label or obj_id or f"cert-{len(certs) + 1}"
                try:
                    info = certificate_info_from_x509(
                        cert_id=alias,
                        cert_der=cert_der,
                        provider_id=self.provider_id,
                        token_label=token_label,
                    )
                except Exception as exc:
                    log.debug("Certificado descartado (%s): %s", alias, exc)
                    discarded.append(f"parse-fail:{alias}")
                    continue

                # Detectar si tiene clave privada asociada.
                if pin:
                    has_key = (
                        alias in priv_labels
                        or (obj_id and obj_id in priv_ids)
                        or info.isCa is False
                    )
                    if info.isCa and info.type != "ROOT":
                        has_key = False
                else:
                    # Sin PIN, no podemos enumerar claves privadas.
                    # Heuristica: certificado no CA y label no parece
                    # CA/ROOT es probablemente firmable.
                    has_key = not info.isCa
                info.hasPrivateKey = bool(has_key)
                info.signable = bool(info.hasPrivateKey and not info.isCa)

                log.info(
                    "Cert OK alias=%s type=%s signable=%s serial=%s cedula=%s",
                    info.id,
                    info.type,
                    info.signable,
                    info.serial,
                    info.cedula or "-",
                )

                certs.append(info)

            if discarded:
                log.info("Certificados descartados: %s", ",".join(discarded[:10]))

            if expected_cedula and certs:
                log.info(
                    "expectedCedula=%s (se ignora en listado; se valida al firmar)",
                    expected_cedula,
                )

            if not certs:
                raise CertificateNotFoundError(
                    "El token no expuso certificados legibles."
                )

            def _order_key(c: CertificateInfo):
                if c.signable and c.type == "SIGNING":
                    return (0, c.id)
                if c.signable and c.type == "AUTH":
                    return (1, c.id)
                if c.signable:
                    return (2, c.id)
                if c.type == "CA":
                    return (3, c.id)
                if c.type == "ROOT":
                    return (4, c.id)
                return (5, c.id)

            certs.sort(key=_order_key)
            return certs

    def sign(self, request: SignatureRequest) -> SignatureResult:
        if not request.pin:
            from ..errors import PinRequiredError

            raise PinRequiredError("Se requiere PIN para firmar (pinMode=LOCAL_PROMPT).")

        pkcs11, constants = _import_pkcs11()
        alg = (request.algorithm or "SHA512").upper()
        mech_name = _ALG_MAP.get(alg)
        if not mech_name:
            raise CertificateNotFoundError(f"Algoritmo {alg} no soportado.")
        mechanism = getattr(constants.Mechanism, mech_name)

        token_label = self.get_token_label()
        with self._open_session(request.pin) as session:
            private_key, cert_obj = self._find_key_and_cert(
                session, constants, request.key_alias
            )
            cert_der = (
                bytes(_attr(cert_obj, constants.Attribute.VALUE, b""))
                if cert_obj
                else b""
            )

            from ...config import settings as _settings

            if _settings.touch_sense_message:
                log.info(
                    "Esperando confirmacion Touch Sense del token (alias=%s, "
                    "timeout=%ss). Presione el token fisico para autorizar.",
                    request.key_alias,
                    _settings.sign_timeout_seconds,
                )

            try:
                signature = private_key.sign(request.data, mechanism=mechanism)
            except Exception as exc:
                self._map_sign_error(exc)

            log.info(
                "Firma autorizada por token (alias=%s, alg=%s)",
                request.key_alias,
                alg,
            )

            return SignatureResult(
                signature=bytes(signature),
                algorithm=f"{alg}withRSA",
                certificate_der=cert_der,
                certificate_chain_der=[cert_der] if cert_der else [],
            )

    @staticmethod
    def _map_sign_error(exc: Exception) -> None:
        msg = str(exc).lower()
        type_name = type(exc).__name__.lower()
        if "locked" in msg or "locked" in type_name or "ckr_pin_locked" in msg:
            raise TokenLockedError("Token bloqueado durante la firma.") from exc
        if "cancel" in msg or "user_cancelled" in type_name or "ckr_function_canceled" in msg:
            raise UserCancelledError(
                "Operacion cancelada en el token (no se confirmo Touch Sense)."
            ) from exc
        if "timeout" in msg or "ckr_timeout" in msg:
            raise TimeoutError_(
                "Timeout esperando confirmacion Touch Sense del token."
            ) from exc
        if (
            "incorrect" in msg
            or "invalid" in msg
            or "ckr_pin_incorrect" in msg
            or "pinincorrect" in type_name
        ):
            raise PinInvalidError("PIN incorrecto durante la firma.") from exc
        # Cualquier otro error -> firma rechazada
        from ..errors import SignatureRejectedError

        raise SignatureRejectedError(f"El driver rechazo la firma: {exc}") from exc

    def get_certificate_der(self, cert_id: str, pin: Optional[str] = None) -> bytes:
        """Devuelve el certificado en formato DER sin listar todos."""
        pkcs11, constants = _import_pkcs11()
        with self._open_session(pin) as session:
            for c in session.get_objects(
                {constants.Attribute.CLASS: constants.ObjectClass.CERTIFICATE}
            ):
                label = _label_of(c, constants) or _id_of(c, constants)
                cid = _id_of(c, constants)
                if label == cert_id or (cid and cid == cert_id):
                    return bytes(_attr(c, constants.Attribute.VALUE, b""))
        raise CertificateNotFoundError(
            f"Certificado {cert_id!r} no encontrado en el token."
        )

    def _find_key_and_cert(self, session, constants, alias: str):
        private_key = None
        cert_obj = None
        # 1. Localizar el cert seleccionado por label o por CKA_ID
        for c in session.get_objects(
            {constants.Attribute.CLASS: constants.ObjectClass.CERTIFICATE}
        ):
            label = _label_of(c, constants) or _id_of(c, constants)
            cid = _id_of(c, constants)
            if label == alias or (cid and cid == alias):
                cert_obj = c
                break

        if cert_obj is None:
            raise CertificateNotFoundError(
                f"Certificado {alias!r} no existe en el token."
            )

        # 2. Buscar clave privada por CKA_ID del cert (no por label)
        cert_id_hex = _id_of(cert_obj, constants)
        if cert_id_hex:
            for key in session.get_objects(
                {constants.Attribute.CLASS: constants.ObjectClass.PRIVATE_KEY}
            ):
                if _id_of(key, constants) == cert_id_hex:
                    private_key = key
                    break

        # 3. Fallback: buscar por label si no se encontro por ID
        if private_key is None:
            cert_label = (
                _label_of(cert_obj, constants) or _id_of(cert_obj, constants)
            )
            for key in session.get_objects(
                {constants.Attribute.CLASS: constants.ObjectClass.PRIVATE_KEY}
            ):
                label = _label_of(key, constants) or _id_of(key, constants)
                if label == cert_label:
                    private_key = key
                    break

        # 4. Si llegamos aqui sin clave, el cert no es firmable
        if private_key is None:
            raise CertificateNotFoundError(
                f"El certificado {alias!r} no tiene clave privada en el token. "
                "Use un certificado con signable=true (Signing Certificate / User Certificate)."
            )
        return private_key, cert_obj

    def get_certificate_info(
        self, cert_id: str, pin: Optional[str] = None
    ) -> dict:
        """Devuelve metadata de un certificado especifico (sin listar todos)."""
        pkcs11, constants = _import_pkcs11()
        try:
            session_cm = self._open_session(pin) if pin else self._open_session()
        except (PinInvalidError, TokenLockedError):
            if pin is not None:
                raise
            from ..errors import PinRequiredError
            raise PinRequiredError(
                "El token requiere PIN para leer el certificado."
            )
        with session_cm as session:
            # Materializamos la lista de claves privadas UNA sola vez,
            # porque ``session.get_objects`` devuelve un SearchIter que
            # abre una busqueda activa; no se pueden anidar dos.
            priv_keys = list(
                session.get_objects(
                    {
                        constants.Attribute.CLASS: constants.ObjectClass.PRIVATE_KEY
                    }
                )
            )
            priv_ids = {_id_of(k, constants) for k in priv_keys}
            priv_labels = {_label_of(k, constants) for k in priv_keys}

            for c in session.get_objects(
                {constants.Attribute.CLASS: constants.ObjectClass.CERTIFICATE}
            ):
                label = _label_of(c, constants) or _id_of(c, constants)
                cid = _id_of(c, constants)
                if label == cert_id or (cid and cid == cert_id):
                    cert_der = bytes(_attr(c, constants.Attribute.VALUE, b""))
                    from .base import certificate_info_from_x509

                    info = certificate_info_from_x509(
                        cert_id=label or cid,
                        cert_der=cert_der,
                        provider_id=self.provider_id,
                        token_label=self.get_token_label(),
                    )
                    has_key = (
                        (label in priv_labels)
                        or (cid and cid in priv_ids)
                        or (not info.isCa)
                    )
                    if info.isCa and info.type != "ROOT":
                        has_key = False
                    info.hasPrivateKey = bool(has_key)
                    info.signable = bool(info.hasPrivateKey and not info.isCa)
                    return {
                        "id": info.id,
                        "cedula": info.cedula,
                        "subject": info.subject,
                        "issuer": info.issuer,
                        "serial": info.serial,
                        "validFrom": info.validFrom,
                        "validTo": info.validTo,
                        "provider": info.provider,
                        "tokenLabel": info.tokenLabel,
                        "displayName": info.displayName,
                        "shortName": info.shortName,
                        "type": info.type,
                        "isCa": info.isCa,
                        "hasPrivateKey": info.hasPrivateKey,
                        "signable": info.signable,
                    }
        raise CertificateNotFoundError(
            f"Certificado {cert_id!r} no encontrado en el token."
        )
