"""Fabrica de drivers segun configuracion y provider solicitado.

Expone ademas el catalogo de proveedores que el frontend espera en
``/api/v1/health`` (EPASS3003, BIT4ID, SAFENET, UKC, PCSC).
"""
from __future__ import annotations

import logging
import os
from typing import List, Optional

from ...config import settings
from ..errors import DriverNotFoundError
from .base import TokenDriver
from .mock_driver import MockDriver
from .pcsc_driver import PcscDriver
from .pkcs11_driver import Pkcs11Driver


log = logging.getLogger(__name__)


# Catalogo publico de proveedores. El id es el que ve el frontend.
# El campo ``module_name`` permite probar instalacion sin que el
# usuario configure nada.
PROVIDER_CATALOG: List[dict] = [
    {
        "id": "EPASS3003",
        "name": "ePass3003",
        "kind": "PKCS11",
        "module_candidates": [
            r"C:\Windows\System32\ePass3003PKCS11.dll",
            "/usr/lib/epass3003/libePass3003.so",
        ],
    },
    {
        "id": "BIT4ID",
        "name": "Bit4Id",
        "kind": "PKCS11",
        "module_candidates": [
            r"C:\Windows\System32\bit4ipki.dll",
            "/usr/lib/bit4id/libbit4ipki.so",
        ],
    },
    {
        "id": "SAFENET",
        "name": "SafeNet",
        "kind": "PKCS11",
        "module_candidates": [
            r"C:\Windows\System32\eTPKCS11.dll",
            r"C:\Windows\SysWOW64\eTPKCS11.dll",
            r"C:\Program Files\SafeNet\Authentication\SAC\x64\eTPKCS11.dll",
            r"C:\Program Files (x86)\SafeNet\Authentication\Client\eTPKCS11.dll",
            "/usr/lib/safenet/libeTPKCS11.so",
        ],
    },
    {
        "id": "UKC",
        "name": "UKC ePass",
        "kind": "PKCS11",
        "module_candidates": [
            r"C:\Windows\System32\ukcpkcs11.dll",
            "/usr/lib/ukc/libukcpkcs11.so",
        ],
    },
    {
        "id": "EPASS2003",
        "name": "ePass2003",
        "kind": "PKCS11",
        "module_candidates": [
            r"C:\Windows\System32\ePass2003PKCS11.dll",
        ],
    },
    {
        "id": "PCSC",
        "name": "PC/SC Smartcard",
        "kind": "PCSC",
        "module_candidates": [],
    },
]


def _module_exists(path: str) -> bool:
    try:
        return os.path.isfile(path)
    except Exception:
        return False


def _resolve_module(candidates: List[str], *, allow_global_fallback: bool = True) -> Optional[str]:
    """Encuentra un modulo PKCS#11 disponible.

    Si ``allow_global_fallback`` es True, acepta ``PKCS11_MODULE_PATH``
    como candidato para cualquier provider. Si es False (modo health),
    solo acepta los modulos especificos declarados para ese provider.
    """
    for c in candidates:
        if _module_exists(c):
            return c
    if allow_global_fallback and settings.pkcs11_module_path and _module_exists(
        settings.pkcs11_module_path
    ):
        return settings.pkcs11_module_path
    return None


def _build_mock() -> TokenDriver:
    return MockDriver()


def _build_pkcs11_for(module_path: str) -> TokenDriver:
    return Pkcs11Driver(module_path)


def _build_pcsc() -> TokenDriver:
    return PcscDriver(settings.pcsc_reader_index)


def _build_pkcs11() -> TokenDriver:
    if not settings.pkcs11_module_path:
        raise DriverNotFoundError(
            "PKCS11_MODULE_PATH vacio. Define la ruta al modulo del fabricante."
        )
    return Pkcs11Driver(settings.pkcs11_module_path)


def list_available_providers() -> List[dict]:
    """Lista los proveedores del catalogo y su disponibilidad real.

    Solo cuenta como instalado el modulo PKCS#11 declarado para ese
    provider especifico. No incluye el driver MOCK.
    """
    out: List[dict] = []
    for p in PROVIDER_CATALOG:
        installed = False
        try:
            if p["kind"] == "PCSC":
                drv = _build_pcsc()
                installed = drv.is_available()
            elif p["kind"] == "PKCS11":
                module = _resolve_module(p["module_candidates"], allow_global_fallback=False)
                if module:
                    drv = _build_pkcs11_for(module)
                    installed = drv.is_available()
        except Exception:
            installed = False
        out.append({"id": p["id"], "name": p["name"], "installed": installed})
    return out


def has_real_driver() -> bool:
    """True si al menos un proveedor real (no MOCK) esta instalado."""
    return any(p["installed"] for p in list_available_providers())


def get_driver(provider: str, tipo: str = "TOKEN") -> TokenDriver:
    """Devuelve un driver segun ``provider`` y ``tipoKeyStoreProvider``."""
    provider = (provider or "AUTO").upper()
    tipo = (tipo or "TOKEN").upper()

    # 1. Si el provider es MOCK y esta habilitado -> mock
    if provider == "MOCK":
        if not settings.mock_driver:
            raise DriverNotFoundError("Driver MOCK deshabilitado (MOCK_DRIVER=false).")
        return _build_mock()

    # 2. AUTO sin driver real -> mock si esta habilitado
    if provider == "AUTO":
        if not has_real_driver() and settings.mock_driver:
            log.info("Sin driver real; usando MOCK (desarrollo).")
            return _build_mock()

    # 3. PCSC puro
    if tipo == "PCSC" and provider in {"AUTO", "PCSC"}:
        return _build_pcsc()

    # 4. AUTO con driver real -> primer PKCS#11 disponible
    if provider == "AUTO":
        for p in PROVIDER_CATALOG:
            if p["kind"] != "PKCS11":
                continue
            module = _resolve_module(p["module_candidates"])
            if module:
                return _build_pkcs11_for(module)
        raise DriverNotFoundError(
            "No se detecto ningun modulo PKCS#11 instalado."
        )

    # 5. Provider explicito del catalogo
    for p in PROVIDER_CATALOG:
        if p["id"] != provider:
            continue
        if p["kind"] == "PCSC":
            return _build_pcsc()
        if p["kind"] == "PKCS11":
            module = _resolve_module(p["module_candidates"])
            if not module:
                raise DriverNotFoundError(
                    f"No se encontro modulo PKCS#11 para {provider}."
                )
            return _build_pkcs11_for(module)

    # 6. Provider explicito que no esta en el catalogo (PKCS11 generico)
    if provider == "PKCS11":
        return _build_pkcs11()

    raise DriverNotFoundError(f"Provider {provider} no soportado.")
