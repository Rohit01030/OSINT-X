"""
Core application configuration.

All settings are read from environment variables (see .env.example at the
project root). Nothing here should ever be hardcoded with a real secret —
defaults exist only so the app can boot in local dev without a .env file.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # App
    APP_NAME: str = "OSINT-X"
    APP_ENV: str = "development"
    LOG_LEVEL: str = "INFO"

    # Database
    DATABASE_URL: str = "postgresql://osintx:osintx@postgres:5432/osintx"

    # Auth (used starting Step 6, defined now so config is stable going forward)
    SECRET_KEY: str = "change-me-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Redis / Celery
    REDIS_URL: str = "redis://redis:6379/0"

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173"]

    # AI — local only via Ollama, no API key required
    OLLAMA_BASE_URL: str = "http://ollama:11434"
    OLLAMA_MODEL: str = "llama3:8b"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
