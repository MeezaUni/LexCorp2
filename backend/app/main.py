import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.config import settings
from app.core.limiter import limiter

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
        logger.info("Database tables verified/created successfully.")

        # DID format check is report-only; historical DIDs are never rewritten silently.
        from app.core.database import async_session_factory
        from app.services.auth import report_legacy_dids
        async with async_session_factory() as db:
            legacy = await report_legacy_dids(db)
            if legacy:
                logger.warning(f"{legacy} user DID(s) do not match did:ethr:{settings.CHAIN_ID}:<wallet>; review before any migration.")
    except Exception as e:
        logger.error(f"Failed to initialize database tables or check DIDs: {e}")

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
from app.api.verify import router as verify_router
from app.api.alerts import router as alerts_router

app = FastAPI(
    title="LexCorp SIH 2026 - Blockchain Identity & Asset Platform",
    description="Decentralized identity, NFT asset management, and RBAC",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)

@app.get("/api/auth/test")
async def test_auth():
    return {"message": "auth router test"}

# API Routers
app.include_router(auth.router, prefix="/api")

app.include_router(assets.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(audit_router, prefix="/api")
app.include_router(indexer_router, prefix="/api")
app.include_router(verify_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")

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
