"""Backend-generated action identifiers: <PREFIX>-YYYYMMDD-XXXX.

  CRT  creation      VW   view      DL   download      MOD  modification
  ACR  delegated access request

The counter is advanced with a single INSERT ... ON CONFLICT ... RETURNING, so
concurrent requests can never receive the same number. XXXX is the per-day
sequence, zero-padded to 4 digits (it widens past 9999 rather than wrapping).
"""

from datetime import datetime, UTC

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

PREFIXES = ("CRT", "VW", "DL", "MOD", "ACR")


async def next_action_id(db: AsyncSession, prefix: str) -> str:
    if prefix not in PREFIXES:
        raise ValueError(f"Unknown action ID prefix {prefix}")
    day = datetime.now(UTC).date()
    value = (await db.execute(text(
        "INSERT INTO action_id_counters (prefix, day, last_value) VALUES (:p, :d, 1) "
        "ON CONFLICT (prefix, day) DO UPDATE SET last_value = action_id_counters.last_value + 1 "
        "RETURNING last_value"
    ), {"p": prefix, "d": day})).scalar_one()
    return f"{prefix}-{day:%Y%m%d}-{value:04d}"


async def next_token_id(db: AsyncSession) -> int:
    """Token IDs come from a DB sequence (was random.randint): unique, never reused."""
    return int((await db.execute(text("SELECT nextval('asset_token_id_seq')"))).scalar_one())
