"""
Application configuration.

This module is the ONLY place environment variables are read. Every other
module that needs a configuration value must import `get_settings()` from
here rather than calling `os.getenv` directly.

Boundary note (core/ vs config/):
    - config/  -> WHAT the configuration values are (typed, validated).
    - core/    -> HOW the app uses those values at startup (logging setup,
                  exception handlers, lifespan wiring).
"""

import os
import tempfile
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _is_cloud_environment() -> bool:
    return bool(
        os.environ.get("VERCEL")
        or os.environ.get("VERCEL_ENV")
        or os.environ.get("VERCEL_URL")
        or os.environ.get("VERCEL_REGION")
        or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        or os.environ.get("AWS_EXECUTION_ENV")
        or os.environ.get("LAMBDA_TASK_ROOT")
        or os.environ.get("NOW_REGION")
    )


def _get_temp_sqlite_url() -> str:
    db_path = Path(tempfile.gettempdir()).resolve() / "asoc.db"
    return f"sqlite:///{db_path.as_posix()}"


class Environment(str, Enum):
    """Supported application environments."""

    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """
    Typed application settings, populated from environment variables / .env file.

    See `.env.example` at the repository root for the full list of supported
    variables and their meaning.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # --- Application ---
    APP_NAME: str = "ASOC"
    APP_ENV: Environment = Environment.DEVELOPMENT
    APP_DEBUG: bool = True
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    API_V1_PREFIX: str = "/api/v1"

    # --- Logging ---
    LOG_LEVEL: str = "INFO"

    # --- CORS ---
    CORS_ALLOWED_ORIGINS: List[AnyHttpUrl] = Field(default_factory=list)

    # --- Security / JWT (values only — logic lives in app/security) ---
    JWT_SECRET_KEY: str = "changeme"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 30

    # --- Administrator Account Provisioning ---
    ADMIN_USERNAME: str = "chaitu"
    ADMIN_PASSWORD: str | None = "412065"
    ADMIN_ROLE: str = "super_admin"
    ADMIN_EMAIL: str = "chaitu@asoc.io"

    # --- Database ---
    POSTGRES_USER: str = "asoc_user"
    POSTGRES_PASSWORD: str = "changeme"
    POSTGRES_DB: str = "asoc_db"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str | None = None

    # --- AI Layer ---
    AI_PROVIDER: str = "ollama"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3"

    # --- Log Upload (Part 5) ---
    UPLOAD_DIRECTORY: str = "uploads/security_logs"
    MAX_UPLOAD_SIZE_MB: int = 50
    ALLOWED_UPLOAD_EXTENSIONS: List[str] = Field(
        default_factory=lambda: ["csv", "json", "log", "txt"]
    )

    @property
    def MAX_UPLOAD_SIZE_BYTES(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    # --- Sigma Rule Engine (Part 8) ---
    SIGMA_RULES_DIRECTORY: str = "sigma_rules"

    @field_validator("SIGMA_RULES_DIRECTORY", mode="before")
    @classmethod
    def assemble_sigma_rules_dir(cls, value: str | None) -> str:
        if value:
            p = Path(value)
            if p.is_dir():
                return str(p)
        base_dir = Path(__file__).resolve().parent.parent.parent
        candidate = base_dir / (value or "sigma_rules")
        if candidate.is_dir():
            return str(candidate)
        return value or "sigma_rules"

    @field_validator("UPLOAD_DIRECTORY", mode="before")
    @classmethod
    def assemble_upload_dir(cls, value: str | None) -> str:
        if _is_cloud_environment():
            tmp_upload = Path(tempfile.gettempdir()).resolve() / "uploads" / "security_logs"
            tmp_upload.mkdir(parents=True, exist_ok=True)
            return str(tmp_upload)
        return value or "uploads/security_logs"

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_database_url(cls, value: str | None, info) -> str:
        """Build DATABASE_URL from discrete Postgres settings if not explicitly set."""
        temp_sqlite = _get_temp_sqlite_url()
        if value:
            if value.startswith("postgres://"):
                value = value.replace("postgres://", "postgresql://", 1)
            if _is_cloud_environment() and value.startswith("sqlite:///") and not value.startswith("sqlite:////tmp/"):
                return temp_sqlite
            return value

        if _is_cloud_environment():
            return temp_sqlite

        data = info.data
        host = data.get("POSTGRES_HOST", "localhost")
        if _is_cloud_environment() and host in ("localhost", "127.0.0.1", "0.0.0.0"):
            return temp_sqlite

        return (
            f"postgresql://{data.get('POSTGRES_USER')}:{data.get('POSTGRES_PASSWORD')}"
            f"@{host}:{data.get('POSTGRES_PORT')}/{data.get('POSTGRES_DB')}"
        )

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == Environment.DEVELOPMENT

    @property
    def is_test(self) -> bool:
        return self.APP_ENV == Environment.TEST


@lru_cache
def get_settings() -> Settings:
    """
    Return a cached Settings instance.

    Cached via lru_cache so environment variables are parsed once per process,
    not on every import/request.
    """
    return Settings()
