"""Configuracion de la API local.

Lee variables de entorno y .env. No se persisten secretos.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List

from dotenv import load_dotenv
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=False)


class Settings(BaseSettings):
    """Configuracion inmutable por proceso."""

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    host: str = Field(default="127.0.0.1")
    port: int = Field(default=44113)
    log_level: str = Field(default="INFO")
    request_timeout_seconds: int = Field(default=30)
    sign_timeout_seconds: int = Field(default=120)
    touch_sense_message: bool = Field(default=True)
    pin_max_attempts: int = Field(default=3)
    pin_backoff_seconds: int = Field(default=2)
    pin_cache_ttl_seconds: int = Field(default=120)
    rate_limit_per_minute: int = Field(default=30)
    allowed_origin: str = Field(default="http://localhost:3000")
    allowed_origins_extra: str = Field(
        default="http://localhost:5173,http://localhost:5174,http://127.0.0.1:5173,http://127.0.0.1:3000"
    )
    default_provider: str = Field(default="AUTO")
    default_pin_mode: str = Field(default="LOCAL_PROMPT")
    mock_driver: bool = Field(default=True)
    pkcs11_module_path: str = Field(default="")
    pcsc_reader_index: int = Field(default=0)

    @field_validator("host")
    @classmethod
    def _solo_loopback(cls, value: str) -> str:
        if value not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError(
                "La API local SOLO puede escuchar en loopback (127.0.0.1, localhost, ::1)."
            )
        return value

    @field_validator("port")
    @classmethod
    def _puerto_valido(cls, value: int) -> int:
        if not (1 <= value <= 65535):
            raise ValueError("Puerto fuera de rango.")
        if value in {80, 443, 22, 21, 25, 3306, 5432, 6379, 8080, 8000}:
            raise ValueError(f"Puerto {value} reservado, elige otro.")
        return value

    @field_validator("log_level")
    @classmethod
    def _nivel_log(cls, value: str) -> str:
        v = value.upper()
        if v not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("Nivel de log invalido.")
        return v

    @field_validator("default_pin_mode")
    @classmethod
    def _pin_mode_valido(cls, value: str) -> str:
        v = value.upper()
        if v not in {"LOCAL_PROMPT", "INLINE", "NONE"}:
            raise ValueError("pinMode invalido.")
        return v

    @property
    def cors_origins(self) -> List[str]:
        extras = [o.strip() for o in self.allowed_origins_extra.split(",") if o.strip()]
        all_origins = [self.allowed_origin, *extras]
        # dedupe preservando orden
        seen: set = set()
        return [o for o in all_origins if not (o in seen or seen.add(o))]


settings = Settings()
