"""Indexer control API — manual catch-up, status, and history backfill endpoints.

These endpoints allow the audit trail to be backfilled on demand, e.g. after
an indexer restart or for the initial sync from a freshly-deployed contract.
"""

import logging

from fastapi import APIRouter, HTTPException, Query

from app.indexer.event_indexer import get_indexer

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/indexer", tags=["indexer"])


@router.get("/status")
async def indexer_status():
    """Report indexer state."""
    indexer = await get_indexer()
    return {
        "running": indexer._running,
        "last_indexed_block": indexer._last_indexed_block,
        "contract_loaded": indexer.contract is not None,
    }


@router.post("/catch-up")
async def catch_up(
    from_block: int = Query(0, ge=0, description="Block to start indexing from (inclusive)"),
    to_block: int = Query(0, ge=0, description="Block to stop at (inclusive, 0 = chain head)"),
):
    """Trigger an on-demand backfill of events from `from_block` to `to_block` (or chain head).

    Idempotent: any tx_hash already in the audit trail is skipped.
    """
    indexer = await get_indexer()
    try:
        result = await indexer.catch_up(
            from_block=from_block,
            to_block=to_block if to_block > 0 else None,
        )
        return result
    except ConnectionError as e:
        raise HTTPException(status_code=503, detail=f"Chain unreachable: {e}")
    except Exception as e:
        logger.error(f"Catch-up failed: {e}")
        raise HTTPException(status_code=500, detail=f"Catch-up failed: {e}")
