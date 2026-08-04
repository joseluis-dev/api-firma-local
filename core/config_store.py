"""Runtime user configuration.

Persists only in ``%LOCALAPPDATA%\\GadSign\\LocalAPI\\config.json``.
Sensitive values (PIN, certs) are NEVER stored here.

Schema is intentionally simple and additive. Unknown keys are kept
on disk for forward-compat.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

from .user_paths import config_path


log = logging.getLogger(__name__)


# Production default: devMode OFF. CORS dev origins only when devMode=true.
DEFAULT_ALLOWED_ORIGINS_PROD: List[str] = [
    "https://*.salcedo.gob.ec",
]
DEFAULT_ALLOWED_ORIGINS_DEV: List[str] = [
    "https://*.salcedo.gob.ec",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]


@dataclass
class UserConfig:
    host: str = "127.0.0.1"
    port: int = 44113
    allowed_origins: List[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_ORIGINS_PROD))
    dev_mode: bool = False
    require_pairing: bool = True
    require_user_confirmation: bool = True
    pin_cache_ttl_seconds: int = 120
    max_pdf_mb: int = 25
    log_level: str = "INFO"
    sign_timeout_seconds: int = 120
    request_timeout_seconds: int = 30
    pkcs11_module_path: str = r"C:\Windows\System32\eTPKCS11.dll"
    default_provider: str = "SAFENET"
    mock_driver: bool = False
    pcsc_reader_index: int = 0

    def effective_allowed_origins(self) -> List[str]:
        if self.dev_mode:
            # En dev_mode, fusionar origines del usuario con los dev por defecto
            # para que localhost:5173/3000 siempre esten disponibles.
            merged: List[str] = []
            seen: set = set()
            for o in list(self.allowed_origins) + list(DEFAULT_ALLOWED_ORIGINS_DEV):
                k = o.strip().rstrip("/").lower()
                if k and k not in seen:
                    seen.add(k)
                    merged.append(o.strip().rstrip("/"))
            return merged
        # Produccion: solo origines del usuario (filtrar dev por seguridad).
        if self.allowed_origins:
            return [o.strip().rstrip("/") for o in self.allowed_origins if o.strip()]
        return list(DEFAULT_ALLOWED_ORIGINS_PROD)


class ConfigStore:
    """Atomic JSON read/write of UserConfig in user data dir."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or config_path()
        self._lock = threading.Lock()
        self._data: UserConfig = self._load()

    @property
    def path(self) -> Path:
        return self._path

    def _load(self) -> UserConfig:
        if not self._path.exists():
            cfg = UserConfig()
            self._save_unlocked(cfg)
            return cfg
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("Config corrupta en %s, regenerando defaults: %s", self._path, exc)
            cfg = UserConfig()
            self._save_unlocked(cfg)
            return cfg
        # Merge con defaults para tolerar archivos viejos.
        defaults = asdict(UserConfig())
        defaults.update({k: v for k, v in raw.items() if k in defaults})
        return UserConfig(**defaults)

    def _save_unlocked(self, cfg: UserConfig) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(asdict(cfg), indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, self._path)
        except Exception as exc:
            log.error("No se pudo guardar config: %s", exc)

    def get(self) -> UserConfig:
        with self._lock:
            return self._data

    def update(self, **kwargs) -> UserConfig:
        with self._lock:
            current = asdict(self._data)
            current.update({k: v for k, v in kwargs.items() if k in current})
            self._data = UserConfig(**current)
            self._save_unlocked(self._data)
            return self._data

    def save(self, cfg: UserConfig) -> None:
        with self._lock:
            self._data = cfg
            self._save_unlocked(cfg)


config_store = ConfigStore()
