"""Environment-driven configuration only, via Pydantic Settings. Reads .env and exposes typed settings objects consumed by core/ and other layers."""

from app.config.settings import Environment, Settings, get_settings

__all__ = ["Environment", "Settings", "get_settings"]

