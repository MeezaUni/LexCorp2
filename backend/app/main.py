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

    # Schema is owned by Alembic migrations; the app never creates tables itself.
    from app.core.database import async_session_factory
    from sqlalchemy import text
    try:
        from alembic.config import Config as _AlembicConfig
        from alembic.script import ScriptDirectory
        import os as _os
        cfg = _AlembicConfig(_os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "alembic.ini"))
        cfg.set_main_option("script_location", _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "migrations"))
        head = ScriptDirectory.from_config(cfg).get_current_head()
        async with async_session_factory() as db:
            current = (await db.execute(text("SELECT version_num FROM alembic_version"))).scalar_one_or_none()
        if current != head:
            msg = f"Database schema is at {current}, expected {head}. Run: alembic upgrade head"
            if settings.is_production:
                raise RuntimeError(msg)
            logger.error(msg)
        from app.services.auth import report_legacy_dids
        async with async_session_factory() as db:
            legacy = await report_legacy_dids(db)
            if legacy:
                logger.warning(f"{legacy} user DID(s) do not match did:ethr:{settings.CHAIN_ID}:<wallet>; review before any migration.")
    except RuntimeError:
        raise
    except Exception as e:
        if settings.is_production:
            raise
        logger.error(f"Database check failed: {e}")

    # Verify the configured chain and contract (chain id, bytecode, registrar role).
    import asyncio
    from app.services import chain as chain_service
    status = await asyncio.to_thread(chain_service.verify_deployment)
    app.state.chain_status = status
    if status.ok:
        logger.info(f"Chain verified: chain {status.chain_id}, AssetNFT v3 at {status.address}, head {status.head}")
    else:
        msg = f"Chain/contract verification FAILED: {status.checks}"
        if settings.is_production:
            raise RuntimeError(msg)
        logger.error(msg)

    # Periodic safety net: on-chain roles always converge to the identity registry.
    reconciler_task = None
    if settings.CHAIN_OPERATOR_PRIVATE_KEY and settings.ENVIRONMENT != "test":
        async def _reconcile_loop():
            while True:
                try:
                    async with async_session_factory() as db:
                        result = await chain_service.reconcile_all(db)
                    if result["failed"]:
                        logger.error(f"On-chain role reconciliation: {result}")
                except Exception as e:
                    logger.error(f"On-chain role reconciliation error: {e}")
                await asyncio.sleep(300)
        reconciler_task = asyncio.create_task(_reconcile_loop())

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
    if reconciler_task:
        reconciler_task.cancel()
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
from app.api.chain import router as chain_router

app = FastAPI(
    title="LexCorp - Digital & Physical Asset Management",
    description="Wallet identity, purpose-bound MFA, RBAC, controlled documents, physical asset registry, Besu anchoring",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    # Interactive API docs only outside production.
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/openapi.json",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS: explicit origins and headers only (credentials are cookies).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Step-Up-Token"],
    expose_headers=["Content-Disposition", "X-LexCorp-Action-Id"],
)


@app.middleware("http")
async def security_headers(request, call_next):
    """Defence-in-depth response headers for every API response."""
    response = await call_next(request)
    h = response.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    h.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    if request.url.path.startswith("/api/"):
        h.setdefault("Cache-Control", "no-store")
    if settings.is_production:
        h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response

# API Routers
app.include_router(auth.router, prefix="/api")

app.include_router(assets.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(audit_router, prefix="/api")
app.include_router(indexer_router, prefix="/api")
app.include_router(verify_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(chain_router, prefix="/api")

@app.api_route("/health", methods=["GET", "HEAD"])
async def health_check():
    """Liveness plus coarse integrity flags (no configuration details)."""
    from app.indexer.event_indexer import get_indexer
    try:
        indexer = await get_indexer()
        indexer_status = "running" if indexer and indexer._running else "stopped"
    except Exception:
        indexer_status = "unavailable"
    chain = getattr(app.state, "chain_status", None)
    return {
        "status": "ok",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "indexer": indexer_status,
        "chain_verified": bool(chain and chain.ok),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
