"""
Exchange Automation Service Configuration
"""
import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Service
    PORT: int = int(os.getenv("PORT", "4000"))

    # Database (same as main app)
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/cryptohub"
    )

    # Encryption (same key as main app)
    ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY", "your-32-byte-encryption-key-here!!")

    # Browser settings
    BROWSER_MEMORY_LIMIT_MB: int = 800
    BROWSER_MAX_UPTIME_HOURS: int = 8
    SESSION_HEARTBEAT_INTERVAL_SEC: int = 300  # 5 minutes
    KEEPALIVE_INTERVAL_SEC: int = 60

    # IMAP Email settings
    IMAP_SERVER: str = ""
    IMAP_PORT: int = 993
    IMAP_EMAIL: str = ""
    IMAP_PASSWORD: str = ""
    IMAP_ENABLED: bool = False

    # Service-to-service auth
    SERVICE_API_KEY: str = ""

    # Shared credentials user (matches main app PRIMARY_USER_ID)
    PRIMARY_USER_ID: int = 1

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


settings = Settings()
