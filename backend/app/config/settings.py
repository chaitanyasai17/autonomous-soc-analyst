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

from enum import Enum
from functools import lru_cache
from typing import List

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str | None = None
    ADMIN_ROLE: str = "super_admin"
    ADMIN_EMAIL: str = "admin@asoc.io"

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

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_database_url(cls, value: str | None, info) -> str:
        """Build DATABASE_URL from discrete Postgres settings if not explicitly set."""
        if value:
            return value
        data = info.data
        return (
            f"postgresql://{data.get('POSTGRES_USER')}:{data.get('POSTGRES_PASSWORD')}"
            f"@{data.get('POSTGRES_HOST')}:{data.get('POSTGRES_PORT')}/{data.get('POSTGRES_DB')}"
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
