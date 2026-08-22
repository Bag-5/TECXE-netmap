from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database (Neon Postgres)
    DATABASE_URL: str = "postgresql+asyncpg://neondb_owner:pass@host/neondb?ssl=require"

    # AI (OpenRouter)
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_PRIMARY_MODEL: str = "stealth/ox-alpha"
    OPENROUTER_FALLBACK_MODEL: str = "openai/gpt-oss-120b:free"
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"

    # Vulnerability intel
    NVD_API_KEY: str = ""
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_CACHE_TTL_HOURS: int = 24

    # Scanning
    TARGET_CIDR: str = "192.168.1.0/24"
    SCAN_PROFILE: str = "quick"
    NMAP_PATH: str = r"C:\Program Files (x86)\Nmap\nmap.exe"

    # CORS
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:4173",
        "https://tecxe-netmap.vercel.app",
    ]

    LOG_LEVEL: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
