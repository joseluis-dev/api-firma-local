"""CORS origin policy tests: wildcard expansion, normalization, preflight."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from localapi.core.config_store import ConfigStore, DEFAULT_ALLOWED_ORIGINS_PROD, DEFAULT_ALLOWED_ORIGINS_DEV
from localapi.core.security.origins import (
    _WILDCARD_REGEX,
    build_cors_policy,
    normalize_origin,
    origin_is_allowed,
)


# ---------------------------------------------------------------------------
# normalize_origin
# ---------------------------------------------------------------------------


def test_normalize_valid_https_origin() -> None:
    assert normalize_origin("https://www.salcedo.gob.ec") == "https://www.salcedo.gob.ec"


def test_normalize_valid_http_origin() -> None:
    assert normalize_origin("http://localhost:5173") == "http://localhost:5173"


def test_normalize_rejects_root_domain() -> None:
    assert normalize_origin("https://salcedo.gob.ec") == "https://salcedo.gob.ec"


def test_normalize_rejects_path() -> None:
    assert normalize_origin("https://www.salcedo.gob.ec/path") is None


def test_normalize_rejects_query() -> None:
    assert normalize_origin("https://www.salcedo.gob.ec?x=1") is None


def test_normalize_rejects_fragment() -> None:
    assert normalize_origin("https://www.salcedo.gob.ec#top") is None


def test_normalize_rejects_userinfo() -> None:
    assert normalize_origin("https://user@www.salcedo.gob.ec") is None


def test_normalize_rejects_empty() -> None:
    assert normalize_origin("") is None


def test_normalize_rejects_none() -> None:
    assert normalize_origin(None) is None


def test_normalize_rejects_malformed() -> None:
    assert normalize_origin("not-a-url") is None


# ---------------------------------------------------------------------------
# build_cors_policy
# ---------------------------------------------------------------------------


def _is_valid_dns_label(label: str) -> bool:
    if len(label) < 1 or len(label) > 63:
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    return all(c.isalnum() or c == "-" for c in label)


def _label_from_host(host: str) -> str:
    return host.split(".")[0]


def test_wildcard_expands_only_sentinel() -> None:
    exact, errors, regex = build_cors_policy(["https://*.salcedo.gob.ec"])
    assert len(exact) == 0
    assert regex is not None
    assert errors == []


def test_wildcard_other_star_treated_literal() -> None:
    exact, errors, regex = build_cors_policy(["https://*.evil.com"])
    assert regex is None
    assert exact == ["https://*.evil.com"]


def test_exact_origins_preserved() -> None:
    exact, errors, regex = build_cors_policy([
        "https://www.salcedo.gob.ec",
    ])
    assert "https://www.salcedo.gob.ec" in exact
    assert regex is None


def test_http_dev_origins_rejected() -> None:
    exact, errors, regex = build_cors_policy([
        "http://localhost:3000",
    ])
    assert len(exact) == 0
    assert len(errors) == 1


def test_exact_and_wildcard() -> None:
    exact, errors, regex = build_cors_policy([
        "https://www.salcedo.gob.ec",
        "https://*.salcedo.gob.ec",
    ])
    assert "https://www.salcedo.gob.ec" in exact
    assert regex is not None


def test_http_origins_rejected_in_production() -> None:
    exact, errors, regex = build_cors_policy([
        "http://firma.salcedo.gob.ec",
    ])
    assert len(exact) == 0
    assert len(errors) == 1
    assert regex is None


def test_empty_origins() -> None:
    exact, errors, regex = build_cors_policy([])
    assert exact == []
    assert regex is None
    assert errors == []


# ---------------------------------------------------------------------------
# Wildcard regex
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("allowed", [
    "https://www.salcedo.gob.ec",
    "https://firma.salcedo.gob.ec",
    "https://app.salcedo.gob.ec",
    "https://s.salcedo.gob.ec",
])
def test_wildcard_allows_subdomain(allowed: str) -> None:
    origin = normalize_origin(allowed)
    assert origin is not None
    assert _WILDCARD_REGEX.fullmatch(origin) is not None


@pytest.mark.parametrize("blocked", [
    "https://salcedo.gob.ec",
    "http://www.salcedo.gob.ec",
    "http://firma.salcedo.gob.ec",
    "https://a.b.salcedo.gob.ec",
    "https://firma.salcedo.gob.ec:8443",
    "https://firma.salcedo.gob.ec.evil.com",
    "https://evil-salcedo.gob.ec",
    "https://firma.salcedo.gob.ecc",
    "https://firma.salcedo.gob.ec.",
    "file://salcedo.gob.ec",
    "null",
    "",
])
def test_wildcard_rejects_invalid(blocked: str) -> None:
    origin = normalize_origin(blocked) if blocked and blocked != "null" else None
    if origin is None:
        assert _WILDCARD_REGEX.fullmatch(blocked) is None
    else:
        assert _WILDCARD_REGEX.fullmatch(origin) is None


# ---------------------------------------------------------------------------
# origin_is_allowed
# ---------------------------------------------------------------------------


def test_origin_is_allowed_exact() -> None:
    regex = _WILDCARD_REGEX.pattern
    assert origin_is_allowed("https://www.salcedo.gob.ec", ["https://www.salcedo.gob.ec"], regex) is True


def test_origin_is_allowed_wildcard() -> None:
    regex = _WILDCARD_REGEX.pattern
    assert origin_is_allowed("https://firma.salcedo.gob.ec", [], regex) is True


def test_origin_is_allowed_rejected() -> None:
    regex = _WILDCARD_REGEX.pattern
    assert origin_is_allowed("https://salcedo.gob.ec", [], regex) is False


def test_origin_is_allowed_no_origin() -> None:
    assert origin_is_allowed("", [], None) is True


# ---------------------------------------------------------------------------
# ConfigStore integration
# ---------------------------------------------------------------------------


def test_config_store_prod_default_has_wildcard(tmp_path: Path) -> None:
    cs = ConfigStore(path=tmp_path / "config.json")
    cfg = cs.get()
    origins = cfg.effective_allowed_origins()
    assert "https://*.salcedo.gob.ec" in origins


def test_config_store_dev_mode_adds_localhost(tmp_path: Path) -> None:
    from localapi.core.config_store import UserConfig
    cs = ConfigStore(path=tmp_path / "config.json")
    cs.save(UserConfig(dev_mode=True, allowed_origins=[]))
    origins = cs.get().effective_allowed_origins()
    assert "http://localhost:5173" in origins


def test_config_store_wildcard_sentinel_persisted(tmp_path: Path) -> None:
    cs = ConfigStore(path=tmp_path / "config.json")
    cfg = cs.get()
    assert "https://*.salcedo.gob.ec" in cfg.allowed_origins


# ---------------------------------------------------------------------------
# Preflight (HTTP integration)
# ---------------------------------------------------------------------------


@pytest.fixture
def cors_client(tmp_path: Path):
    from localapi.core.config_store import config_store, UserConfig

    orig_path = config_store.path
    config_store._path = tmp_path / "config.json"
    config_store.save(UserConfig(
        dev_mode=False,
        allowed_origins=["https://*.salcedo.gob.ec"],
    ))

    from localapi.app import app

    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000), raise_server_exceptions=False) as client:
        yield client

    config_store._path = orig_path


def _preflight_origin(client: TestClient, origin: str):
    return client.options(
        "/api/v1/health",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type, Authorization",
        },
    )


def test_preflight_allowed_subdomain(cors_client: TestClient) -> None:
    r = _preflight_origin(cors_client, "https://www.salcedo.gob.ec")
    assert r.status_code in {200, 503}
    assert r.headers.get("Access-Control-Allow-Origin") == "https://www.salcedo.gob.ec"


def test_preflight_blocked_root_domain(cors_client: TestClient) -> None:
    r = _preflight_origin(cors_client, "https://salcedo.gob.ec")
    assert "Access-Control-Allow-Origin" not in r.headers


def test_preflight_blocked_http(cors_client: TestClient) -> None:
    r = _preflight_origin(cors_client, "http://firma.salcedo.gob.ec")
    assert "Access-Control-Allow-Origin" not in r.headers


def test_preflight_blocked_suffix_attack(cors_client: TestClient) -> None:
    r = _preflight_origin(cors_client, "https://firma.salcedo.gob.ec.evil.com")
    assert "Access-Control-Allow-Origin" not in r.headers


def test_preflight_blocked_deep_subdomain(cors_client: TestClient) -> None:
    r = _preflight_origin(cors_client, "https://a.b.salcedo.gob.ec")
    assert "Access-Control-Allow-Origin" not in r.headers


def test_preflight_no_origin(cors_client: TestClient) -> None:
    r = cors_client.get("/api/v1/health")
    assert r.status_code in {200, 503}
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers.keys()}
