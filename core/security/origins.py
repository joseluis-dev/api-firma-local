"""CORS origin policy: wildcard expansion, normalization, matching.

Parses ``https://*.salcedo.gob.ec`` into a regex that matches exactly
one subdomain label over HTTPS. Only this sentinel is expanded; any
other ``*`` is treated as a literal origin and will never match a
browser ``Origin`` header.
"""
from __future__ import annotations

import logging
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse

log = logging.getLogger(__name__)

# Sentinel kept in config.json; expanded only at runtime.
_WILDCARD_SENTINEL = "https://*.salcedo.gob.ec"

# Single DNS label: 1-63 chars, alphanumeric or hyphen, no leading/trailing hyphens.
_LABEL_RE = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"

# Pattern: exactly one label, then the fixed domain, HTTPS only, no port.
_WILDCARD_REGEX = re.compile(
    rf"(?i:https://{_LABEL_RE}\.salcedo\.gob\.ec)"
)

# Loopback hosts allowed over plain HTTP (dev servers: Vite, CRA, etc.).
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}

# Scheme-specific default ports; a URL on its default port omits it.
_DEFAULT_PORTS = {"http": 80, "https": 443}

# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def normalize_origin(origin: str) -> Optional[str]:
    """Return a clean ``scheme://host[:port]`` or None if malformed."""
    if not origin or not isinstance(origin, str):
        return None
    try:
        parsed = urlparse(origin.strip())
        port = parsed.port  # raises ValueError on malformed/out-of-range ports
    except Exception:
        return None
    if parsed.scheme not in {"http", "https"}:
        return None
    host = (parsed.hostname or "").lower()
    if not host or host.startswith(".") or host.endswith("."):
        return None
    if host.count("..") or " " in host:
        return None
    if port == 0:
        return None
    port_part = ""
    if port is not None and port != _DEFAULT_PORTS.get(parsed.scheme):
        port_part = f":{port}"
    if parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
        return None
    if ":" in host:  # IPv6 literal: restore brackets
        host = f"[{host}]"
    return f"{parsed.scheme}://{host}{port_part}"


# ---------------------------------------------------------------------------
# Build allowlists from UserConfig origins
# ---------------------------------------------------------------------------


def build_cors_policy(
    config_origins: List[str],
) -> Tuple[List[str], List[str], Optional[str]]:
    """Split UserConfig origins into exact origins and an optional regex.

    Returns ``(exact, errors, regex_str)``.
    """
    exact: List[str] = []
    errors: List[str] = []
    seen_regex = False

    for raw in config_origins:
        raw = raw.strip()
        if not raw:
            continue
        if raw == _WILDCARD_SENTINEL:
            if not seen_regex:
                seen_regex = True
            continue
        normalized = normalize_origin(raw)
        if normalized is None:
            errors.append(raw)
            log.warning("CORS: ignoring malformed origin %r", raw)
            continue
        if normalized.startswith("http://"):
            http_host = urlparse(normalized).hostname or ""
            if http_host not in _LOOPBACK_HOSTS:
                errors.append(raw)
                log.warning("CORS: ignoring non-loopback HTTP origin %r", raw)
                continue
        exact.append(normalized)

    regex_str = _WILDCARD_REGEX.pattern if seen_regex else None
    return exact, errors, regex_str


# ---------------------------------------------------------------------------
# Match
# ---------------------------------------------------------------------------


def origin_is_allowed(
    raw_origin: Optional[str],
    exact_origins: List[str],
    wildcard_regex: Optional[str],
) -> bool:
    """Check if a browser ``Origin`` header value is allowed."""
    if not raw_origin:
        return True  # same-origin or curl — handled by caller
    origin = normalize_origin(raw_origin)
    if origin is None:
        return False
    if origin in exact_origins:
        return True
    if wildcard_regex:
        return bool(re.compile(wildcard_regex).fullmatch(origin))
    return False
