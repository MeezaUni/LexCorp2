"""Application configuration loaded from environment variables."""

from pathlib import Path
from typing import List, Union
from pydantic_settings import BaseSettings
from pydantic import model_validator

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_FILE = BASE_DIR / "lexcorp_demo.db"


class Settings(BaseSettings):
    """Central config — all secrets come from env vars, never hardcoded."""

    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Database — PostgreSQL for production, SQLite fallback for local dev
    DATABASE_URL: str = "postgresql+asyncpg://lexcorp:lexcorp_dev@localhost:5432/lexcorp_sih"
    DATABASE_URL_SYNC: str = "postgresql://lexcorp:lexcorp_dev@localhost:5432/lexcorp_sih"

    # CORS & WebAuthn
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    RP_ID: str = "localhost"
    WEBAUTHN_ORIGINS: List[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # JWT / session
    JWT_SECRET: str = "development-secret-key-replace-in-production-1234567890"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 30

    # Blockchain
    RPC_URL: str = "http://127.0.0.1:8545"
    CHAIN_ID: int = 13371
    CONTRACT_DEPLOYMENT_PATH: str = str(BASE_DIR.parent / "contracts" / "deployments" / "localhost.json")

    # Public base URL of the LexCorp web app; QR codes point to its /verify pages.
    PUBLIC_BASE_URL: str = "http://localhost:5173"

    # Off-chain document vault (original uploads are immutable; derived copies are generated per action)
    OFFCHAIN_STORAGE_DIR: str = str(BASE_DIR / "offchain_storage")

    # IPFS
    IPFS_GATEWAY: str = "http://127.0.0.1:5001"

    # Nonce
    NONCE_EXPIRY_SECONDS: int = 300  # 5 minutes per NIST SP 800-63-4

    # Session hardening
    INACTIVITY_TIMEOUT_MINUTES: int = 15
    # Only these peers may supply X-Forwarded-For; anyone else's header is ignored.
    TRUSTED_PROXIES: List[str] = ["127.0.0.1/32", "::1/128"]

    # Purpose-bound step-up (Factor 2 / Factor 3) grant lifetime
    STEP_UP_TTL_SECONDS: int = 300
    WEBAUTHN_CHALLENGE_TTL_SECONDS: int = 300

    # Controlled downloads: how long an approved download stays fetchable, and whether a
    # requester who is not the owner also needs the owner's consent.
    DOWNLOAD_APPROVAL_TTL_HOURS: int = 24
    DOWNLOAD_REQUIRES_OWNER_APPROVAL: bool = True

    # Wallet provisioning PIN
    PROVISIONING_PIN_TTL_HOURS: int = 3

    # Key for encrypting TOTP secrets at rest. If unset, one is derived from JWT_SECRET.
    DATA_ENCRYPTION_KEY: str = ""

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        if not self.DEBUG:
            if "development" in self.JWT_SECRET or "CHANGE-ME" in self.JWT_SECRET or len(self.JWT_SECRET) < 32:
                raise ValueError("In production, JWT_SECRET must be set to a secure value (min 32 chars) via environment variables.")
            if "*" in self.CORS_ORIGINS:
                raise ValueError("Wildcard '*' is not allowed in CORS_ORIGINS in production.")
            for origin in self.WEBAUTHN_ORIGINS:
                if origin.startswith("http://") and not (origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1")):
                    raise ValueError(f"Insecure origin {origin} not allowed for WebAuthn in production. Use HTTPS.")
        return self

    model_config = {
        "env_file": [str(BASE_DIR / ".env"), str(BASE_DIR.parent / ".env")],
        "case_sensitive": True,
        "extra": "ignore"
    }


settings = Settings()
