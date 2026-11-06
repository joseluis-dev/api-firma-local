"""Pruebas unitarias pequenas (sin token)."""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

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


def test_new_security_error_codes() -> None:
    from localapi.core.errors import (
        AuthForbiddenError,
        AuthRequiredError,
        ErrorCode,
        HostNotAllowedError,
        OriginNotAllowedError,
        ReplayDetectedError,
        TokenExpiredError,
        TokenRevokedError,
    )
    assert ErrorCode.AUTH_REQUIRED.value == "AUTH_REQUIRED"
    assert ErrorCode.TOKEN_EXPIRED.value == "TOKEN_EXPIRED"
    assert ErrorCode.TOKEN_REVOKED.value == "TOKEN_REVOKED"
    assert ErrorCode.REPLAY_DETECTED.value == "REPLAY_DETECTED"
    assert ErrorCode.ORIGIN_NOT_ALLOWED.value == "ORIGIN_NOT_ALLOWED"
    assert ErrorCode.HOST_NOT_ALLOWED.value == "HOST_NOT_ALLOWED"
    assert AuthRequiredError("x").status_code == 401
    assert AuthForbiddenError("x").status_code == 403
    assert TokenExpiredError("x").status_code == 401
    assert TokenRevokedError("x").status_code == 401
    assert ReplayDetectedError("x").status_code == 409
    assert OriginNotAllowedError("x").status_code == 403
    assert HostNotAllowedError("x").status_code == 403


# ---------------------------------------------------------------------------
# Pairing + seguridad
# ---------------------------------------------------------------------------


def _isolated_pairing(tmp_path: Path):
    from localapi.core.security import pairing

    pm = pairing.PairingManager(path=tmp_path / "pairing.json")
    return pm


def test_pairing_full_flow(tmp_path: Path) -> None:
    pm = _isolated_pairing(tmp_path)
    req = pm.request_pairing("https://app.example.com", ["pdf:sign", "certificates:list"])
    assert req.status == "pending"

    tok = pm.approve_request(req.request_id)
    assert tok is not None
    assert tok.origin == "https://app.example.com"
    assert "pdf:sign" in tok.scopes

    ok, err, stored = pm.validate_bearer(tok.token, "pdf:sign")
    assert ok and err is None
    assert stored is not None
    assert stored.origin == "https://app.example.com"

    # Token sin scope requerido
    ok2, err2, _ = pm.validate_bearer(tok.token, "health:admin")
    assert not ok2
    assert err2 is not None


def test_pairing_revoke_and_invalid(tmp_path: Path) -> None:
    pm = _isolated_pairing(tmp_path)
    req = pm.request_pairing("https://app.example.com", ["pdf:sign"])
    tok = pm.approve_request(req.request_id)
    assert tok is not None

    n = pm.revoke_origin("https://app.example.com")
    assert n == 1
    ok, err, _ = pm.validate_bearer(tok.token, "pdf:sign")
    assert not ok
    assert err and "revocado" in err.lower()

    # Token malformado
    ok2, err2, _ = pm.validate_bearer("not.a.real.token", "pdf:sign")
    assert not ok2


def test_pairing_unknown_token_rejected(tmp_path: Path) -> None:
    """Tokens firmados validos pero no persistidos deben rechazarse."""
    pm = _isolated_pairing(tmp_path)
    # Generar un token con la misma estructura pero emitido por otra instalacion.
    other = _isolated_pairing(tmp_path / "other")
    req = other.request_pairing("https://app.example.com", ["pdf:sign"])
    tok = other.approve_request(req.request_id)
    assert tok is not None

    ok, err, _stored, code = pm.validate_bearer_detailed(tok.token, "pdf:sign")
    assert not ok
    assert code == "signature" or code == "unknown_token"


def test_pairing_detailed_codes(tmp_path: Path) -> None:
    pm = _isolated_pairing(tmp_path)
    req = pm.request_pairing("https://app.example.com", ["pdf:sign"])
    tok = pm.approve_request(req.request_id, ttl_seconds=60)
    assert tok is not None

    # Firma manipulada
    bad = tok.token[:-1] + ("A" if tok.token[-1] != "A" else "B")
    ok, err, _, code = pm.validate_bearer_detailed(bad, "pdf:sign")
    assert not ok and code == "signature"

    # Scope insuficiente
    ok2, err2, _, code2 = pm.validate_bearer_detailed(tok.token, "health:admin")
    assert not ok2 and code2 == "scope"

    # Revocado
    pm.revoke_origin("https://app.example.com")
    ok3, err3, _, code3 = pm.validate_bearer_detailed(tok.token, "pdf:sign")
    assert not ok3 and code3 in ("revoked", "expired")


def test_pairing_expiration(tmp_path: Path) -> None:
    pm = _isolated_pairing(tmp_path)
    req = pm.request_pairing("https://app.example.com", ["pdf:sign"])
    # TTL minimo 60s: simulamos expiracion manipulando el token persistido.
    tok = pm.approve_request(req.request_id, ttl_seconds=60)
    assert tok is not None
    # Forzamos expiracion modificando expires_at directamente en disco.
    data = pm._load()
    for t in data.tokens:
        if t.token == tok.token:
            t.expires_at = int(time.time()) - 5
    pm._data = data
    pm._save()
    ok, err, _ = pm.validate_bearer(tok.token, "pdf:sign")
    assert not ok
    assert err and ("expirado" in err.lower() or "desactualizado" in err.lower())


def test_pairing_deny(tmp_path: Path) -> None:
    pm = _isolated_pairing(tmp_path)
    req = pm.request_pairing("https://app.example.com", ["pdf:sign"])
    assert pm.deny_request(req.request_id) is True
    assert pm.approve_request(req.request_id) is None


def test_pairing_http_confirmation_requires_native_approval(tmp_path: Path) -> None:
    pm = _isolated_pairing(tmp_path)
    req = pm.request_pairing("https://app.example.com", ["pdf:sign"])

    # Sin respuesta de la UI nativa nadie puede finalizar la solicitud por HTTP.
    assert pm.approve_request_confirmed(req.request_id) is None
    assert pm.get_request(req.request_id).status == "pending"

    pm.set_approval_callback(lambda origin, scopes: True)
    assert pm.try_native_approve(req.request_id) is True
    tok = pm.approve_request_confirmed(req.request_id)
    assert tok is not None and tok.origin == "https://app.example.com"
    # La aprobacion es de un solo uso.
    assert pm.approve_request_confirmed(req.request_id) is None


def test_pairing_native_denial_or_error_never_marks_request_as_approved(tmp_path: Path) -> None:
    pm = _isolated_pairing(tmp_path)
    for answer in (False, None):
        req = pm.request_pairing("https://app.example.com", ["pdf:sign"])
        pm.set_approval_callback(lambda origin, scopes, a=answer: a)
        assert pm.try_native_approve(req.request_id) is answer
        assert pm.approve_request_confirmed(req.request_id) is None

    def broken(origin, scopes):
        raise RuntimeError("Tk no disponible")

    req = pm.request_pairing("https://app.example.com", ["pdf:sign"])
    pm.set_approval_callback(broken)
    assert pm.try_native_approve(req.request_id) is None
    assert pm.approve_request_confirmed(req.request_id) is None


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------


def test_replay_headers_blocks_reuse() -> None:
    from localapi.core.security.deps import check_replay_headers

    class _R:
        headers = {
            "x-localapi-timestamp": str(int(time.time())),
            "x-localapi-request-id": "fixed-nonce-1",
        }

    check_replay_headers(_R())  # primera vez: ok
    with pytest.raises(Exception) as excinfo:
        check_replay_headers(_R())
    assert "replay" in str(excinfo.value).lower() or "requestid" in str(excinfo.value).lower()


def test_replay_headers_skew() -> None:
    from localapi.core.security.deps import check_replay_headers

    class _R:
        headers = {
            "x-localapi-timestamp": str(int(time.time()) - 3600),
            "x-localapi-request-id": "skew-nonce-1",
        }

    with pytest.raises(Exception):
        check_replay_headers(_R())


# ---------------------------------------------------------------------------
# ConfigStore
# ---------------------------------------------------------------------------


def test_config_store_dev_mode_origins(tmp_path: Path) -> None:
    from localapi.core.config_store import ConfigStore, UserConfig

    cs = ConfigStore(path=tmp_path / "config.json")
    cfg = cs.get()
    # Produccion por defecto: solo el origen productivo
    assert "http://localhost:5173" not in cfg.effective_allowed_origins()
    # Dev mode
    cs.save(UserConfig(dev_mode=True, allowed_origins=[]))
    assert "http://localhost:5173" in cs.get().effective_allowed_origins()


# ---------------------------------------------------------------------------
# User data paths
# ---------------------------------------------------------------------------


def test_user_data_dir_creates(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPI_DATA_DIR", str(tmp_path / "data"))
    from localapi.core.user_paths import config_path, logs_dir, pairing_path, user_data_dir

    p = user_data_dir()
    assert p.exists()
    assert config_path().parent == p
    assert pairing_path().parent == p
    assert logs_dir().exists()



# ---------------------------------------------------------------------------
# Validacion de modulos PKCS#11 configurados por el usuario
# ---------------------------------------------------------------------------


@pytest.fixture
def guard(monkeypatch):
    from localapi.core.drivers import module_guard

    monkeypatch.setattr(module_guard, "_is_authenticode_signed", lambda path: True)
    # Las carpetas temporales pertenecen al usuario actual: la ACL real las
    # rechazaria. Las pruebas de ACL inyectan su propio comprobador.
    monkeypatch.setattr(module_guard, "_is_writable_by_untrusted", lambda path: False)
    monkeypatch.setattr(module_guard, "_warned", set())
    return module_guard


def _make_dll(directory: Path, name: str = "token.dll") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    dll = directory / name
    dll.write_bytes(b"MZ")
    return dll


def test_module_guard_accepts_dll_under_allowed_root(guard, tmp_path: Path) -> None:
    dll = _make_dll(tmp_path / "System32")
    result = guard.validate_module_path(str(dll), allowed_roots=[str(tmp_path / "System32")])
    assert result is not None
    assert Path(result).samefile(dll)


@pytest.mark.parametrize("bad,reason", [
    ("", None),
    ("eTPKCS11.dll", "ruta no absoluta"),
    (r"..\..\evil.dll", "ruta no absoluta"),
    (r"\\server\share\evil.dll", "ruta UNC o de dispositivo"),
    ("//server/share/evil.dll", "ruta UNC o de dispositivo"),
    (r"\\?\C:\Windows\System32\evil.dll", "ruta UNC o de dispositivo"),
    (r"\\.\pipe\evil.dll", "ruta UNC o de dispositivo"),
    ("C:\\Windows\\System32\\evil.dll\x00.txt", "caracter nulo"),
])
def test_module_guard_rejects_relative_unc_and_malformed_paths(guard, tmp_path: Path, caplog, bad, reason) -> None:
    _make_dll(tmp_path / "System32")
    with caplog.at_level("WARNING"):
        assert guard.validate_module_path(bad, allowed_roots=[str(tmp_path / "System32")]) is None
    if reason is not None:  # la rama exacta, no una rechazo incidental por otra causa
        assert reason in caplog.text


def test_module_guard_rejects_dll_outside_allowed_roots(guard, tmp_path: Path) -> None:
    _make_dll(tmp_path / "System32")
    evil = _make_dll(tmp_path / "Users" / "victim" / "AppData")
    assert guard.validate_module_path(str(evil), allowed_roots=[str(tmp_path / "System32")]) is None


def test_module_guard_prefix_match_respects_path_boundary(guard, tmp_path: Path) -> None:
    sibling = _make_dll(tmp_path / "Program Files Evil")
    assert guard.validate_module_path(str(sibling), allowed_roots=[str(tmp_path / "Program Files")]) is None
    # La propia raiz tampoco es un archivo valido.
    assert guard.validate_module_path(str(tmp_path / "Program Files"), allowed_roots=[str(tmp_path / "Program Files")]) is None


def test_module_guard_rejects_non_dll_missing_and_directories(guard, tmp_path: Path) -> None:
    root = tmp_path / "System32"
    exe = _make_dll(root, "token.exe")
    folder = root / "folder.dll"
    folder.mkdir()
    for candidate in (exe, root / "missing.dll", folder):
        assert guard.validate_module_path(str(candidate), allowed_roots=[str(root)]) is None


@pytest.mark.skipif(os.name != "nt", reason="Windows paths are case-insensitive")
def test_module_guard_compares_case_insensitively_on_windows(guard, tmp_path: Path) -> None:
    dll = _make_dll(tmp_path / "System32", "eTPKCS11.dll")
    shouted = str(dll).upper()
    assert guard.validate_module_path(shouted, allowed_roots=[str(tmp_path / "system32")]) is not None


def _link_directory(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":  # las uniones (junction) no requieren privilegios
        import subprocess

        done = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
        if done.returncode == 0:
            return
    pytest.skip("no se pueden crear enlaces simbolicos ni junctions")


def test_module_guard_resolves_links_pointing_outside_allowed_roots(guard, tmp_path: Path) -> None:
    root = tmp_path / "System32"
    root.mkdir()
    outside = tmp_path / "AppData" / "evil"
    _make_dll(outside, "token.dll")
    _link_directory(root / "innocent", outside)
    assert (root / "innocent" / "token.dll").is_file()
    assert guard.validate_module_path(str(root / "innocent" / "token.dll"), allowed_roots=[str(root)]) is None


def test_module_guard_unsigned_dll_only_warns(guard, monkeypatch, tmp_path: Path, caplog) -> None:
    monkeypatch.setattr(guard, "_is_authenticode_signed", lambda path: False)
    dll = _make_dll(tmp_path / "System32")
    with caplog.at_level("WARNING"):
        result = guard.validate_module_path(str(dll), allowed_roots=[str(tmp_path / "System32")])
    assert result is not None  # nunca bloquea: algunos fabricantes distribuyen DLL sin firmar
    assert "Authenticode" in caplog.text


def test_module_guard_default_roots_follow_windows_environment() -> None:
    from localapi.core.drivers.module_guard import _windows_roots

    roots = _windows_roots({
        "SystemRoot": r"D:\Win", "ProgramFiles": r"D:\PF", "ProgramFiles(x86)": r"D:\PF86",
    })
    assert roots.direct == [r"D:\Win\System32", r"D:\Win\SysWOW64"]
    assert roots.tree == [r"D:\PF", r"D:\PF86"]
    standard = _windows_roots({})
    assert standard.direct == [r"C:\Windows\System32", r"C:\Windows\SysWOW64"]
    assert standard.tree == [r"C:\Program Files", r"C:\Program Files (x86)"]


@pytest.mark.skipif(os.name != "nt", reason="Win32 known folders")
def test_module_guard_runtime_roots_come_from_win32_not_from_environment(monkeypatch, tmp_path: Path) -> None:
    from localapi.core.drivers import module_guard

    expected = module_guard.protected_roots()
    system32 = os.path.join(os.environ["SystemRoot"], "System32")
    spoof = str(tmp_path / "spoofed")
    for name in ("SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        monkeypatch.setenv(name, spoof)
    roots = module_guard.protected_roots()
    assert roots == expected
    assert roots.direct and roots.tree
    assert not any(spoof.lower() in root.lower() for root in roots.direct + roots.tree)
    assert any(os.path.normcase(r) == os.path.normcase(system32) for r in roots.direct)


@pytest.mark.skipif(os.name != "nt", reason="Win32 known folders")
def test_module_guard_without_win32_roots_rejects_everything(monkeypatch) -> None:
    from localapi.core.drivers import module_guard

    def broken(*args, **kwargs):
        raise OSError("API no disponible")

    monkeypatch.setattr(module_guard.ctypes, "WinDLL", broken)
    assert module_guard.protected_roots() == module_guard.RootSet(direct=[], tree=[])


def test_provider_catalog_windows_modules_live_under_protected_roots() -> None:
    import ntpath

    from localapi.core.drivers.factory import PROVIDER_CATALOG
    from localapi.core.drivers.module_guard import _windows_roots

    standard = _windows_roots({})
    roots = [ntpath.normcase(r) + "\\" for r in standard.direct + standard.tree]
    for provider in PROVIDER_CATALOG:
        for candidate in provider["module_candidates"]:
            if candidate.startswith("/"):
                continue  # candidatos Linux: fuera del alcance de las raices de Windows
            assert any(ntpath.normcase(candidate).startswith(root) for root in roots), candidate


def test_module_guard_system_roots_only_accept_direct_children(guard, tmp_path: Path, caplog) -> None:
    # System32 tiene subcarpetas escribibles por usuarios estandar (spool\drivers\color, Tasks).
    root = tmp_path / "System32"
    direct = _make_dll(root, "eTPKCS11.dll")
    nested = _make_dll(root / "spool" / "drivers" / "color", "evil.dll")
    assert guard.validate_module_path(str(direct), direct_roots=[str(root)]) is not None
    with caplog.at_level("WARNING"):
        assert guard.validate_module_path(str(nested), direct_roots=[str(root)]) is None
    assert "fuera de los directorios protegidos" in caplog.text
    # En Program Files las subcarpetas del fabricante siguen siendo validas.
    assert guard.validate_module_path(str(nested), allowed_roots=[str(root)]) is not None


def test_module_guard_rejects_when_file_or_any_folder_up_to_root_is_writable(guard, monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "Program Files"
    dll = _make_dll(root / "Vendor" / "bin", "token.dll")
    for unsafe in (dll, dll.parent, dll.parent.parent, root):
        monkeypatch.setattr(guard, "_warned", set())
        monkeypatch.setattr(
            guard, "_is_writable_by_untrusted", lambda path, unsafe=unsafe: os.path.samefile(path, unsafe)
        )
        assert guard.validate_module_path(str(dll), allowed_roots=[str(root)]) is None, unsafe
    # Lo que queda por encima de la raiz no forma parte de la cadena comprobada.
    monkeypatch.setattr(guard, "_warned", set())
    monkeypatch.setattr(guard, "_is_writable_by_untrusted", lambda path: os.path.samefile(path, root.parent))
    assert guard.validate_module_path(str(dll), allowed_roots=[str(root)]) is not None


def test_module_guard_direct_root_checks_file_and_root_acl(guard, monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "System32"
    dll = _make_dll(root, "eTPKCS11.dll")
    seen = []
    monkeypatch.setattr(guard, "_is_writable_by_untrusted", lambda path: seen.append(Path(path)) or False)
    assert guard.validate_module_path(str(dll), direct_roots=[str(root)]) is not None
    assert [p.samefile(q) for p, q in zip(seen, [dll, root])] == [True, True] and len(seen) == 2


def test_module_guard_fails_closed_when_the_acl_cannot_be_read(guard, monkeypatch, tmp_path: Path, caplog) -> None:
    dll = _make_dll(tmp_path / "System32")

    def unreadable(path):
        raise OSError(5, "Acceso denegado")

    monkeypatch.setattr(guard, "_is_writable_by_untrusted", unreadable)
    with caplog.at_level("WARNING"):
        assert guard.validate_module_path(str(dll), allowed_roots=[str(tmp_path / "System32")]) is None
    assert "ACL" in caplog.text


windows_only = pytest.mark.skipif(os.name != "nt", reason="DACL de Windows")


@windows_only
def test_real_acl_flags_a_folder_owned_by_the_current_user(tmp_path: Path) -> None:
    from localapi.core.drivers import module_guard

    assert module_guard._is_writable_by_untrusted(str(tmp_path)) is True


@windows_only
def test_real_acl_accepts_system_dll_and_flags_user_writable_system_folders() -> None:
    from localapi.core.drivers import module_guard

    system32 = os.path.join(os.environ["SystemRoot"], "System32")
    kernel32 = os.path.join(system32, "kernel32.dll")
    assert module_guard._is_writable_by_untrusted(kernel32) is False
    assert module_guard._is_writable_by_untrusted(system32) is False
    checked = 0
    for parts in (("spool", "drivers", "color"), ("Tasks",)):  # escribibles por usuarios estandar
        folder = os.path.join(system32, *parts)
        if os.path.isdir(folder):
            assert module_guard._is_writable_by_untrusted(folder) is True, folder
            checked += 1
    assert checked


@windows_only
def test_real_validation_on_this_machine_accepts_system32_child_and_rejects_nested_dll() -> None:
    from localapi.core.drivers import module_guard

    system32 = os.path.join(os.environ["SystemRoot"], "System32")
    kernel32 = os.path.join(system32, "kernel32.dll")
    assert module_guard.validate_module_path(kernel32) is not None
    nested = os.path.join(system32, "wbem", "wbemprox.dll")  # protegido, pero no es hijo directo
    if os.path.isfile(nested):
        assert module_guard.validate_module_path(nested) is None


def _sddl_dacl(sddl: str):
    """DACL de un descriptor SDDL (en memoria; no toca el sistema de archivos)."""
    import ctypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    get_dacl = advapi32.GetSecurityDescriptorDacl
    get_dacl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int),
    ]
    descriptor = ctypes.c_void_p()
    assert convert(sddl, 1, ctypes.byref(descriptor), None), sddl
    present, defaulted, dacl = ctypes.c_int(), ctypes.c_int(), ctypes.c_void_p()
    assert get_dacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted))
    return descriptor, (dacl.value if present.value else None)


@windows_only
@pytest.mark.parametrize("sddl,writable", [
    ("D:(A;;FA;;;S-1-5-32-545)", True),             # Users: control total
    ("D:(A;;0x2;;;S-1-1-0)", True),                 # Everyone: FILE_WRITE_DATA / ADD_FILE
    ("D:(A;;0x4;;;S-1-5-11)", True),                # Authenticated Users: FILE_APPEND_DATA
    ("D:(A;;0x10000;;;S-1-5-4)", True),             # INTERACTIVE: DELETE
    ("D:(A;;0x40000;;;S-1-5-32-545)", True),        # Users: WRITE_DAC
    ("D:(A;;0x80000;;;S-1-1-0)", True),             # Everyone: WRITE_OWNER
    ("D:(A;;GW;;;S-1-5-11)", True),                 # GENERIC_WRITE
    ("D:(A;;GA;;;S-1-5-32-545)", True),             # GENERIC_ALL
    ("D:NO_ACCESS_CONTROL", True),                  # DACL NULL = acceso total para todos
    ("D:(A;;FA;;;USER)", True),                     # el usuario actual
    ("D:(A;;FRFX;;;S-1-5-32-545)", False),          # Users: lectura y ejecucion
    ("D:(A;;FA;;;S-1-5-32-544)(A;;FRFX;;;S-1-5-32-545)(A;;FA;;;S-1-5-18)", False),  # tipico de System32
    ("D:(A;OICIIO;FA;;;S-1-5-32-545)", False),      # solo heredable: no afecta al objeto
    ("D:(D;;FA;;;S-1-5-32-545)", False),            # una denegacion no concede nada
    ("D:", False),                                  # DACL vacia: nadie accede
])
def test_dacl_walker_flags_write_rights_for_untrusted_sids(sddl, writable) -> None:
    import ctypes

    from localapi.core.drivers import module_guard

    descriptor, dacl = _sddl_dacl(sddl.replace("USER", module_guard._current_user_sid()))
    try:
        assert module_guard._dacl_allows_untrusted_write(dacl, module_guard._untrusted_sids()) is writable
    finally:
        ctypes.WinDLL("kernel32").LocalFree(descriptor)


class _FakeDriverConfig:
    pcsc_reader_index = 0

    def __init__(self, module_path: str = "", mock_driver: bool = False) -> None:
        self.pkcs11_module_path = module_path
        self.mock_driver = mock_driver


def _factory_with_config(monkeypatch, guard, module_path: str, roots, *, mock_driver: bool = False):
    from localapi.core.drivers import factory

    monkeypatch.setattr(factory, "_driver_config", lambda: _FakeDriverConfig(module_path, mock_driver))
    monkeypatch.setattr(
        guard, "protected_roots", lambda: guard.RootSet(direct=[], tree=[str(r) for r in roots])
    )
    return factory


def test_factory_ignores_configured_module_outside_protected_roots(monkeypatch, guard, tmp_path: Path) -> None:
    evil = _make_dll(tmp_path / "AppData")
    factory = _factory_with_config(monkeypatch, guard, str(evil), [tmp_path / "System32"])
    assert factory._resolve_module([]) is None
    assert factory._resolve_module([str(tmp_path / "nope.dll")]) is None


def test_factory_uses_configured_module_inside_protected_roots(monkeypatch, guard, tmp_path: Path) -> None:
    dll = _make_dll(tmp_path / "System32")
    factory = _factory_with_config(monkeypatch, guard, str(dll), [tmp_path / "System32"])
    resolved = factory._resolve_module([])
    assert resolved is not None and Path(resolved).samefile(dll)
    # El modo health (sin fallback global) nunca usa la ruta configurada.
    assert factory._resolve_module([], allow_global_fallback=False) is None


def test_factory_pkcs11_provider_refuses_untrusted_module_without_loading_it(monkeypatch, guard, tmp_path: Path) -> None:
    from localapi.core.errors import DriverNotFoundError

    evil = _make_dll(tmp_path / "AppData")
    factory = _factory_with_config(monkeypatch, guard, str(evil), [tmp_path / "System32"])

    def must_not_load(module_path):
        raise AssertionError("no debe construirse un driver con una ruta no confiable")

    monkeypatch.setattr(factory, "Pkcs11Driver", must_not_load)
    monkeypatch.setattr(factory, "has_real_driver", lambda: False)
    for provider in ("PKCS11", "AUTO", "SAFENET"):
        monkeypatch.setattr(factory, "_module_exists", lambda path: False)
        with pytest.raises(DriverNotFoundError):
            factory.get_driver(provider)


# ---------------------------------------------------------------------------
# Driver MOCK: deshabilitado por defecto y nunca en builds empaquetados
# ---------------------------------------------------------------------------


def _factory_without_hardware(monkeypatch, *, mock_driver: bool):
    from localapi.core.drivers import factory

    monkeypatch.setattr(factory, "_driver_config", lambda: _FakeDriverConfig(mock_driver=mock_driver))
    monkeypatch.setattr(factory, "has_real_driver", lambda: False)
    monkeypatch.setattr(factory, "_module_exists", lambda path: False)
    return factory


def test_settings_mock_driver_is_disabled_by_default(monkeypatch) -> None:
    from localapi.config import Settings

    monkeypatch.delenv("MOCK_DRIVER", raising=False)
    assert Settings(_env_file=None).mock_driver is False


def test_driver_config_fallback_to_settings_does_not_enable_mock(monkeypatch) -> None:
    from localapi.config import Settings
    from localapi.core.drivers import factory

    class BrokenStore:
        def get(self):
            raise RuntimeError("config ilegible")

    monkeypatch.delenv("MOCK_DRIVER", raising=False)
    monkeypatch.setattr(factory, "config_store", BrokenStore())
    monkeypatch.setattr(factory, "settings", Settings(_env_file=None))
    assert factory._driver_config().mock_driver is False


@pytest.mark.parametrize("provider", ["MOCK", "AUTO"])
def test_mock_is_never_used_unless_explicitly_enabled(monkeypatch, provider) -> None:
    from localapi.core.errors import DriverNotFoundError

    factory = _factory_without_hardware(monkeypatch, mock_driver=False)
    monkeypatch.setattr(factory, "_build_mock", lambda: pytest.fail("MOCK no debe construirse"))
    with pytest.raises(DriverNotFoundError):
        factory.get_driver(provider)


@pytest.mark.parametrize("provider", ["MOCK", "AUTO"])
def test_mock_is_available_in_source_builds_when_explicitly_enabled(monkeypatch, provider) -> None:
    from localapi.core.drivers.mock_driver import MockDriver

    factory = _factory_without_hardware(monkeypatch, mock_driver=True)
    monkeypatch.delattr("sys.frozen", raising=False)
    assert isinstance(factory.get_driver(provider), MockDriver)


def test_frozen_build_refuses_explicit_mock_even_if_enabled(monkeypatch, caplog) -> None:
    import sys

    from localapi.core.errors import DriverNotFoundError

    factory = _factory_without_hardware(monkeypatch, mock_driver=True)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    with caplog.at_level("ERROR"):
        with pytest.raises(DriverNotFoundError):
            factory.get_driver("MOCK")
    assert "MOCK" in caplog.text


def test_frozen_build_auto_ignores_stale_mock_flag_and_reaches_configured_module(
    monkeypatch, guard, tmp_path: Path, caplog
) -> None:
    import sys

    from localapi.core.errors import DriverNotFoundError

    dll = _make_dll(tmp_path / "System32")
    factory = _factory_with_config(monkeypatch, guard, str(dll), [tmp_path / "System32"], mock_driver=True)
    monkeypatch.setattr(factory, "has_real_driver", lambda: False)
    monkeypatch.setattr(factory, "_module_exists", lambda path: False)
    built = []
    monkeypatch.setattr(factory, "Pkcs11Driver", lambda module_path: built.append(module_path) or "pkcs11-driver")
    monkeypatch.setattr(sys, "frozen", True, raising=False)

    with caplog.at_level("WARNING"):
        assert factory.get_driver("AUTO") == "pkcs11-driver"  # _build_mock (real) would have raised
    assert len(built) == 1 and Path(built[0]).samefile(dll)
    assert "empaquetado" in caplog.text

    # Sin modulo valido AUTO falla como cualquier build sin hardware, nunca con MOCK.
    monkeypatch.setattr(factory, "_driver_config", lambda: _FakeDriverConfig("", True))
    with pytest.raises(DriverNotFoundError, match="PKCS#11"):
        factory.get_driver("AUTO")
