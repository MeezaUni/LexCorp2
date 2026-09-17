import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle manager.

    On startup: create tables and launch the event indexer as a background task.
    On shutdown: stop the indexer cleanly.
    """
    logger.info("Application startup")

    # Ensure tables exist
    from app.core.database import engine
    from app.models.base import Base
    import app.models.domain  # Register models

    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            # Safe schema update for SQLite if newly added columns are missing
            from sqlalchemy import text
            for col_sql in [
                "ALTER TABLE users ADD COLUMN contact_number VARCHAR(255)",
                "ALTER TABLE users ADD COLUMN organization VARCHAR(255) DEFAULT 'Bharat Electronics Limited (BEL)'",
                "ALTER TABLE users ADD COLUMN department VARCHAR(255)",
                "ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64)",
                "ALTER TABLE users ADD COLUMN is_totp_enabled BOOLEAN DEFAULT 0",
                "ALTER TABLE assets ADD COLUMN custodian_id CHAR(32)",
                "ALTER TABLE assets ADD COLUMN custodian_did VARCHAR",
                "ALTER TABLE assets ADD COLUMN custodian_department VARCHAR",
                "ALTER TABLE assets ADD COLUMN lifecycle_status VARCHAR(30) DEFAULT 'CREATED'",
                "ALTER TABLE assets ADD COLUMN name VARCHAR(255)",
                "ALTER TABLE assets ADD COLUMN asset_type VARCHAR(50) DEFAULT 'EQUIPMENT'",
                "ALTER TABLE assets ADD COLUMN metadata_cid VARCHAR",
                "ALTER TABLE assets ADD COLUMN file_hash VARCHAR(64)",
                "ALTER TABLE audit_events ADD COLUMN risk_factors JSON",
            ]:
                try:
                    await conn.execute(text(col_sql))
                except Exception:
                    pass  # Column already exists
        logger.info("Database tables verified/created successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database tables: {e}")

    # Initialize AI Risk Engine model
    from app.services.ai import ai_engine
    try:
        if hasattr(ai_engine, 'load_model'):
            ai_engine.load_model()
            logger.info("Local AI Risk Engine initialized.")
    except Exception as e:
        logger.error(f"Failed to initialize AI Risk Engine: {e}")

    # Start the event indexer (background, non-blocking)
    from app.indexer.event_indexer import get_indexer
    try:
        indexer = await get_indexer()
        await indexer.start_background()
    except Exception as e:
        logger.warning(f"Indexer could not start (DB or RPC unavailable): {e}")

    yield

    logger.info("Application shutdown")
    from app.indexer.event_indexer import get_indexer
    try:
        indexer = await get_indexer()
        indexer.stop()
    except Exception:
        pass


from app.api import auth, assets, users
from app.api.audit import router as audit_router
from app.api.indexer import router as indexer_router

app = FastAPI(
    title="LexCorp SIH 2026 - Blockchain Identity & Asset Platform",
    description="Decentralized identity, NFT asset management, and RBAC",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins so your phone on WiFi can connect
    allow_credentials=False, # Must be False if origins is "*"
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routers
app.include_router(auth.router, prefix="/api")
app.include_router(assets.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(audit_router, prefix="/api")
app.include_router(indexer_router, prefix="/api")

@app.api_route("/health", methods=["GET", "HEAD"])
async def health_check():
    """Health check endpoint."""
    from app.indexer.event_indexer import get_indexer
    try:
        indexer = await get_indexer()
        indexer_status = "running" if indexer and indexer._running else "stopped"
    except Exception:
        indexer_status = "unavailable"

    return {
        "status": "ok",
        "version": "1.0.0",
        "indexer": indexer_status,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
