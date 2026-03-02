import secrets

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    mode: str = "local"  # "local" (desktop app, QR pairing) or "cloud" (Google OAuth)

    # Google OAuth — required only in cloud mode
    auth_email: str = ""
    google_client_id: str = ""

    # Agent key — legacy single-agent auth (maps to auth_email)
    agent_key: str = ""

    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expire_days: int = 7
    cors_origins: str = ""  # Comma-separated allowed origins; empty = same-origin only
    cookie_name: str = "session"
    cookie_secure: bool = False  # False for local HTTP; True for cloud HTTPS

    # Keystore — separate secret for encrypting user API keys
    keystore_secret: str = ""

    # Local mode settings
    port: int = 19840

    class Config:
        env_file = ".env"


settings = Settings()

# Auto-detect cloud mode when Google OAuth credentials are present
if settings.mode == "local" and settings.google_client_id and settings.auth_email:
    settings.mode = "cloud"
    settings.cookie_secure = True

# Auto-generate secrets for local mode if not provided
if not settings.jwt_secret:
    settings.jwt_secret = secrets.token_urlsafe(32)
if not settings.agent_key:
    settings.agent_key = secrets.token_urlsafe(32)

# Keystore secret is mandatory in cloud mode
if settings.mode == "cloud" and not settings.keystore_secret:
    raise RuntimeError("KEYSTORE_SECRET environment variable is required in cloud mode")
