"""Application configuration loaded from environment variables."""

from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_FILE = BASE_DIR / "lexcorp_demo.db"


class Settings(BaseSettings):
    """Central config — all secrets come from env vars, never hardcoded."""

    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False

    # Postgres (or SQLite for demo)
    DATABASE_URL: str = f"sqlite+aiosqlite:///{DB_FILE.as_posix()}"
    DATABASE_URL_SYNC: str = f"sqlite:///{DB_FILE.as_posix()}"

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # JWT / session
    JWT_SECRET: str = "CHANGE-ME-IN-PRODUCTION"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 30

    # Blockchain
    RPC_URL: str = "http://127.0.0.1:8545"
    CHAIN_ID: int = 13371
    CONTRACT_DEPLOYMENT_PATH: str = str(BASE_DIR.parent / "contracts" / "deployments" / "localhost.json")

    # IPFS
    IPFS_GATEWAY: str = "http://127.0.0.1:5001"

    # Nonce
    NONCE_EXPIRY_SECONDS: int = 300  # 5 minutes per NIST SP 800-63-4

    model_config = {"env_file": ".env", "case_sensitive": True}


settings = Settings()
