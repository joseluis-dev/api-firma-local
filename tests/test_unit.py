"""Pruebas unitarias pequenas (sin token)."""
from __future__ import annotations

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

