"""
AEGIS 2.0 Backend — Configuration

Loads settings from environment variables with sensible defaults.
"""

from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application-wide configuration sourced from environment variables."""

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False

    # Paths
    base_dir: Path = Path(__file__).resolve().parent

    # Gemini API Configuration
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    gemini_timeout_seconds: float = 12.0

    # SSRF & Inspection Security Limits
    max_redirects: int = 5
    url_request_timeout_seconds: float = 4.0
    max_response_bytes: int = 250_000  # 250 KB max landing page read

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


settings = Settings()
