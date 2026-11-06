"""Validacion de modulos PKCS#11 configurados por el usuario.

``pkcs11_module_path`` viene de ``config.json`` / ``.env`` (ambos editables
por el usuario) y se carga como libreria nativa: ejecuta codigo en el
proceso de la API. Antes de cargar CUALQUIER ruta configurada se exige que:

- sea absoluta y NO sea UNC ni use prefijos de dispositivo,
- tras resolver enlaces simbolicos y junctions (``os.path.realpath``) apunte
  a un archivo ``.dll`` existente,
- resida en una raiz protegida: en System32 / SysWOW64 solo como hijo
  DIRECTO (hay subcarpetas escribibles por usuarios estandar, p. ej.
  ``spool\\drivers\\color`` o ``Tasks``); en Program Files y
  Program Files (x86) en cualquier subcarpeta,
- ni el archivo, ni ninguna carpeta hasta la raiz, sean modificables por
  usuarios sin privilegios (Everyone, Authenticated Users, Users,
  INTERACTIVE, el usuario actual). Si la ACL no se puede leer, se rechaza.

Las raices se calculan con APIs de Windows (no con variables de entorno,
que el usuario puede redefinir). La firma Authenticode se consulta solo
para registrar una advertencia: no bloquea, porque algunos fabricantes
distribuyen DLL sin firmar.

Los candidatos fijos del catalogo (``PROVIDER_CATALOG``) no pasan por aqui.
"""
from __future__ import annotations

import ctypes
import functools
import logging
import ntpath
import os
import stat
import uuid
from typing import Iterable, List, Mapping, NamedTuple, Optional, Sequence


log = logging.getLogger(__name__)

_ALLOWED_EXTENSIONS = (".dll",)

# Evita repetir la misma advertencia en cada peticion (get_driver evalua
# la ruta una vez por proveedor del catalogo).
_warned: set = set()


def _warn_once(key: tuple, message: str, *args) -> None:
    if key in _warned:
        return
    _warned.add(key)
    log.warning(message, *args)


class RootSet(NamedTuple):
    """Raices protegidas.

    ``direct``: solo se aceptan hijos directos (System32, SysWOW64).
    ``tree``: se acepta cualquier subcarpeta (Program Files).
    """

    direct: List[str]
    tree: List[str]


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


def _guid(text: str) -> _GUID:
    u = uuid.UUID(text)
    return _GUID(u.time_low, u.time_mid, u.time_hi_version, (ctypes.c_ubyte * 8)(*u.bytes[8:]))


_FOLDERID_PROGRAM_FILES = "905e63b6-c1bf-494e-b29c-65b732d3d21a"
_FOLDERID_PROGRAM_FILES_X86 = "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e"


def _windows_roots(env: Mapping[str, str]) -> RootSet:
    """Raices a partir de un entorno dado.

    SOLO para pruebas: en ejecucion las raices salen de ``_win32_roots``
    porque las variables de entorno las puede redefinir el usuario.
    """
    system_root = env.get("SystemRoot") or env.get("windir") or r"C:\Windows"
    program_files = env.get("ProgramFiles") or r"C:\Program Files"
    program_files_x86 = env.get("ProgramFiles(x86)") or r"C:\Program Files (x86)"
    return RootSet(
        direct=[ntpath.join(system_root, "System32"), ntpath.join(system_root, "SysWOW64")],
        tree=[program_files, program_files_x86],
    )


def _win32_roots() -> RootSet:
    """Raices protegidas segun las APIs de Windows (no spoofables por entorno)."""
    direct: List[str] = []
    tree: List[str] = []
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        for name in ("GetSystemDirectoryW", "GetSystemWow64DirectoryW"):
            func = getattr(kernel32, name)
            func.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
            func.restype = ctypes.c_uint
            buf = ctypes.create_unicode_buffer(1024)
            length = func(buf, len(buf))
            if 0 < length < len(buf):  # GetSystemWow64DirectoryW falla en Windows de 32 bits
                direct.append(buf.value)

        shell32 = ctypes.WinDLL("shell32")  # type: ignore[attr-defined]
        ole32 = ctypes.WinDLL("ole32")  # type: ignore[attr-defined]
        get_folder = shell32.SHGetKnownFolderPath
        get_folder.argtypes = [
            ctypes.POINTER(_GUID), ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        ]
        get_folder.restype = ctypes.c_long
        ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
        for folder_id in (_FOLDERID_PROGRAM_FILES, _FOLDERID_PROGRAM_FILES_X86):
            out = ctypes.c_void_p()
            result = get_folder(ctypes.byref(_guid(folder_id)), 0, None, ctypes.byref(out))
            try:
                if result == 0 and out.value:
                    folder = ctypes.wstring_at(out.value)
                    if folder and folder not in tree:
                        tree.append(folder)
            finally:
                ole32.CoTaskMemFree(out)
    except Exception as exc:
        # Sin raices confiables todo se rechaza: nunca se vuelve al entorno.
        log.warning("No se pudieron obtener los directorios protegidos del sistema: %s", exc)
        return RootSet(direct=[], tree=[])
    return RootSet(direct=direct, tree=tree)


def protected_roots() -> RootSet:
    """Raices en las que se acepta un modulo configurado por el usuario."""
    if os.name != "nt":
        return RootSet(direct=[], tree=[])
    return _win32_roots()


# ---------------------------------------------------------------------------
# ACL: nadie sin privilegios debe poder modificar el archivo ni su carpeta
# ---------------------------------------------------------------------------

# SID bien conocidos de usuarios sin privilegios.
_UNTRUSTED_SIDS = frozenset({
    "S-1-1-0",        # Everyone
    "S-1-5-11",       # Authenticated Users
    "S-1-5-32-545",   # BUILTIN\Users
    "S-1-5-4",        # INTERACTIVE
})

_FILE_WRITE_DATA = 0x2      # tambien FILE_ADD_FILE en carpetas
_FILE_APPEND_DATA = 0x4     # tambien FILE_ADD_SUBDIRECTORY
_FILE_DELETE_CHILD = 0x40
_DELETE = 0x10000
_WRITE_DAC = 0x40000
_WRITE_OWNER = 0x80000
_GENERIC_ALL = 0x10000000
_GENERIC_WRITE = 0x40000000
_WRITE_MASK = (
    _FILE_WRITE_DATA | _FILE_APPEND_DATA | _FILE_DELETE_CHILD | _DELETE
    | _WRITE_DAC | _WRITE_OWNER | _GENERIC_ALL | _GENERIC_WRITE
)

_ACCESS_ALLOWED_ACE_TYPES = {0, 5, 9, 11}  # allowed / object / callback / callback object
_OBJECT_ACE_TYPES = {5, 11}
_INHERIT_ONLY_ACE = 0x08


def _win_dll(name: str):
    return ctypes.WinDLL(name, use_last_error=True)  # type: ignore[attr-defined]


def _sid_to_string(sid_ptr: int) -> str:
    advapi32 = _win_dll("advapi32")
    kernel32 = _win_dll("kernel32")
    convert = advapi32.ConvertSidToStringSidW
    convert.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    convert.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    out = ctypes.c_void_p()
    if not convert(ctypes.c_void_p(sid_ptr), ctypes.byref(out)):
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
    try:
        return ctypes.wstring_at(out.value)
    finally:
        kernel32.LocalFree(out)


@functools.lru_cache(maxsize=1)
def _current_user_sid() -> str:
    advapi32 = _win_dll("advapi32")
    kernel32 = _win_dll("kernel32")
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.OpenProcessToken.restype = ctypes.c_int
    advapi32.GetTokenInformation.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
    ]
    advapi32.GetTokenInformation.restype = ctypes.c_int
    token = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x8, ctypes.byref(token)):  # TOKEN_QUERY
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
    try:
        needed = ctypes.c_uint32()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))  # TokenUser
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, 1, buf, needed.value, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]  # TOKEN_USER.User.Sid
        return _sid_to_string(sid_ptr)
    finally:
        kernel32.CloseHandle(token)


def _untrusted_sids() -> frozenset:
    return _UNTRUSTED_SIDS | {_current_user_sid()}


def _dacl_allows_untrusted_write(dacl_ptr: Optional[int], untrusted: Iterable[str]) -> bool:
    """True si la DACL concede algun derecho de escritura a un SID no confiable.

    Una DACL NULL concede acceso total a todos. Las ACE de denegacion se
    ignoran (criterio conservador: ante la duda se rechaza) y las ACE solo
    heredables (INHERIT_ONLY) no afectan al objeto en si.
    """
    if not dacl_ptr:
        return True
    untrusted = set(untrusted)
    advapi32 = _win_dll("advapi32")
    advapi32.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int]
    advapi32.GetAclInformation.restype = ctypes.c_int
    advapi32.GetAce.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetAce.restype = ctypes.c_int

    class ACL_SIZE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("AceCount", ctypes.c_uint32),
            ("AclBytesInUse", ctypes.c_uint32),
            ("AclBytesFree", ctypes.c_uint32),
        ]

    info = ACL_SIZE_INFORMATION()
    if not advapi32.GetAclInformation(dacl_ptr, ctypes.byref(info), ctypes.sizeof(info), 2):  # AclSizeInformation
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
    for index in range(info.AceCount):
        ace = ctypes.c_void_p()
        if not advapi32.GetAce(dacl_ptr, index, ctypes.byref(ace)):
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
        base = ace.value
        ace_type = ctypes.c_ubyte.from_address(base).value
        ace_flags = ctypes.c_ubyte.from_address(base + 1).value
        if ace_type not in _ACCESS_ALLOWED_ACE_TYPES or ace_flags & _INHERIT_ONLY_ACE:
            continue
        mask = ctypes.c_uint32.from_address(base + 4).value
        if not mask & _WRITE_MASK:
            continue
        sid_offset = 8
        if ace_type in _OBJECT_ACE_TYPES:
            object_flags = ctypes.c_uint32.from_address(base + 8).value
            sid_offset = 12 + (16 if object_flags & 0x1 else 0) + (16 if object_flags & 0x2 else 0)
        if _sid_to_string(base + sid_offset) in untrusted:
            return True
    return False


def _windows_path_writable_by_untrusted(path: str) -> bool:
    advapi32 = _win_dll("advapi32")
    kernel32 = _win_dll("kernel32")
    get_info = advapi32.GetNamedSecurityInfoW
    get_info.argtypes = [
        ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_info.restype = ctypes.c_uint32
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    # SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
    error = get_info(path, 1, 0x1 | 0x4, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if error:
        raise OSError(error, f"GetNamedSecurityInfoW fallo para {path!r}")
    try:
        untrusted = _untrusted_sids()
        # El propietario tiene WRITE_DAC implicito: si es un no confiable,
        # puede reescribir la ACL aunque la DACL no lo liste.
        if owner.value and _sid_to_string(owner.value) in untrusted:
            return True
        return _dacl_allows_untrusted_write(dacl.value, untrusted)
    finally:
        kernel32.LocalFree(descriptor)


def _is_writable_by_untrusted(path: str) -> bool:
    """True si usuarios sin privilegios pueden modificar ``path``.

    Lanza ``OSError`` si no se puede determinar (el llamador rechaza).
    En plataformas sin DACL se usa el bit "escritura para otros".
    """
    if os.name != "nt":
        return bool(os.stat(path).st_mode & stat.S_IWOTH)
    return _windows_path_writable_by_untrusted(path)


# ---------------------------------------------------------------------------
# Firma Authenticode (solo informativa)
# ---------------------------------------------------------------------------


def _is_authenticode_signed(path: str) -> Optional[bool]:
    """True/False segun WinVerifyTrust; None si no se pudo comprobar.

    Solo informativo. No consulta la red (sin revocacion, solo cache) y la
    firma por catalogo del propio sistema no se detecta aqui.
    """
    if os.name != "nt":
        return None
    try:
        from ctypes import wintypes

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p),
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p),
            ]

        action = _guid("00aac56b-cd44-11d0-8cc2-00c04fc295ee")  # WINTRUST_ACTION_GENERIC_VERIFY_V2
        file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
        data = WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        data.dwUIChoice = 2  # WTD_UI_NONE
        data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
        data.dwUnionChoice = 1  # WTD_CHOICE_FILE
        data.pFile = ctypes.pointer(file_info)
        data.dwStateAction = 1  # WTD_STATEACTION_VERIFY
        data.dwProvFlags = 0x10 | 0x1000  # sin revocacion + solo cache de URL

        verify = ctypes.windll.wintrust.WinVerifyTrust  # type: ignore[attr-defined]
        verify.argtypes = [wintypes.HANDLE, ctypes.POINTER(_GUID), ctypes.c_void_p]
        verify.restype = ctypes.c_long
        invalid_hwnd = wintypes.HANDLE(-1)
        status = verify(invalid_hwnd, ctypes.byref(action), ctypes.byref(data))
        data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
        verify(invalid_hwnd, ctypes.byref(action), ctypes.byref(data))
        return status == 0
    except Exception as exc:  # pragma: no cover - depende de Windows
        log.debug("No se pudo comprobar la firma Authenticode de %s: %s", path, exc)
        return None


# ---------------------------------------------------------------------------
# Validacion
# ---------------------------------------------------------------------------


def _is_unc_or_device_path(path: str) -> bool:
    return path.startswith(("\\\\", "//"))


def _norm(path: str) -> str:
    return os.path.normcase(os.path.realpath(path)).rstrip("\\/")


def _is_under(candidate: str, root: str) -> bool:
    """True si ``candidate`` esta estrictamente dentro de ``root`` (limite de ruta)."""
    return os.path.normcase(candidate).startswith(_norm(root) + os.sep)


def _is_direct_child(candidate: str, root: str) -> bool:
    return os.path.normcase(os.path.dirname(candidate)).rstrip("\\/") == _norm(root)


def _matching_root(real: str, direct: Sequence[str], tree: Sequence[str]) -> Optional[str]:
    for root in direct:
        if _is_direct_child(real, root):
            return root
    for root in tree:
        if _is_under(real, root):
            return root
    return None


def _acl_chain(real: str, root: str) -> List[str]:
    """El archivo y cada carpeta hasta la raiz (inclusive)."""
    root_norm = _norm(root)
    chain = [real]
    folder = os.path.dirname(real)
    while True:
        chain.append(folder)
        parent = os.path.dirname(folder)
        if os.path.normcase(folder).rstrip("\\/") == root_norm or parent == folder:
            return chain
        folder = parent


def validate_module_path(
    path: Optional[str],
    *,
    allowed_roots: Optional[Sequence[str]] = None,
    direct_roots: Optional[Sequence[str]] = None,
) -> Optional[str]:
    """Devuelve la ruta real del modulo si es confiable, o None si no lo es.

    ``allowed_roots`` (cualquier subcarpeta) y ``direct_roots`` (solo hijos
    directos) permiten inyectar las raices en pruebas / otras plataformas;
    si ninguna se da, se usan los directorios protegidos de Windows.
    Una ruta rechazada se registra como advertencia y el llamador debe
    tratarla como "no configurada".
    """
    if not path or not isinstance(path, str):
        return None

    def reject(reason: str) -> None:
        _warn_once(("reject", path, reason), "pkcs11_module_path ignorado (%s): %r", reason, path)
        return None

    if "\x00" in path:
        return reject("caracter nulo")
    if _is_unc_or_device_path(path):
        return reject("ruta UNC o de dispositivo")
    if not os.path.isabs(path) or (os.name == "nt" and not ntpath.splitdrive(path)[0]):
        return reject("ruta no absoluta")
    try:
        real = os.path.realpath(path)
    except (OSError, ValueError):
        return reject("ruta no resoluble")
    if _is_unc_or_device_path(real):
        return reject("resuelve a una ruta UNC o de dispositivo")
    if os.path.splitext(real)[1].lower() not in _ALLOWED_EXTENSIONS:
        return reject("no es una DLL")
    if not os.path.isfile(real):
        return reject("el archivo no existe")

    if allowed_roots is None and direct_roots is None:
        roots = protected_roots()
        direct, tree = list(roots.direct), list(roots.tree)
    else:
        direct, tree = list(direct_roots or []), list(allowed_roots or [])
    try:
        root = _matching_root(real, direct, tree)
    except (OSError, ValueError):
        root = None
    if root is None:
        return reject("fuera de los directorios protegidos del sistema")

    # Defensa en profundidad: una carpeta "protegida" puede tener subcarpetas
    # o archivos modificables por usuarios estandar. Ante cualquier duda
    # (incluido un fallo al leer la ACL) se rechaza.
    for location in _acl_chain(real, root):
        try:
            writable = _is_writable_by_untrusted(location)
        except Exception as exc:
            return reject(f"no se pudo leer la ACL de {location!r}: {exc}")
        if writable:
            return reject(f"modificable por usuarios sin privilegios: {location!r}")

    if ("signature", real) not in _warned:
        _warned.add(("signature", real))
        if _is_authenticode_signed(real) is False:
            log.warning(
                "El modulo PKCS#11 %s no tiene una firma Authenticode embebida valida "
                "(no se bloquea; puede estar firmado por catalogo o ser un modulo del fabricante sin firmar).",
                real,
            )
    return real
