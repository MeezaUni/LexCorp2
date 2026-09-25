"""Physical asset identifiers: normalisation, global uniqueness and duplicate auditing.

Every physical asset has a Serial Number plus EITHER a MAC address OR a Unique
Address. All three are globally unique across the whole registry (not per
department). Uniqueness is decided deterministically here and by the database's
normalised unique indexes (migration 0008) - never by AI.

Duplicate attempts are audited without writing the identifier values themselves:
only a short SHA-256 fingerprint of the normalised value is recorded.
"""

import hashlib
import re
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.domain import Asset

_MAC_HEX = re.compile(r"^[0-9a-f]{12}$")


def normalize_serial(serial: Optional[str]) -> str:
    value = (serial or "").strip()
    if not value or len(value) > 128:
        raise HTTPException(status_code=400, detail="Serial Number is required (max 128 characters).")
    return value


def normalize_mac(mac: Optional[str]) -> str:
    """Accepts aa:bb:cc:dd:ee:ff, AA-BB-..., aabb.ccdd.eeff or aabbccddeeff -> aa:bb:cc:dd:ee:ff."""
    hexdigits = re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()
    if not _MAC_HEX.match(hexdigits) or (mac and re.search(r"[^0-9a-fA-F:.\-\s]", mac)):
        raise HTTPException(status_code=400, detail="MAC Address must be 12 hexadecimal digits (e.g. 00:1A:2B:3C:4D:5E).")
    return ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2))


def normalize_unique_address(value: Optional[str]) -> str:
    v = (value or "").strip()
    if not v or len(v) > 128:
        raise HTTPException(status_code=400, detail="Unique Address is required when the asset has no MAC address (max 128 characters).")
    return v


def fingerprint(value: str) -> str:
    """Non-reversible reference for audit records (values themselves are not logged)."""
    return hashlib.sha256(value.lower().encode()).hexdigest()[:16]


def resolve_identifiers(has_mac_address: Optional[bool], mac: Optional[str], unique_address: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Apply the form rule: YES -> MAC required; NO -> Unique Address required."""
    if has_mac_address is None:  # older clients: infer from what was sent
        has_mac_address = bool(mac and mac.strip())
    if has_mac_address:
        if unique_address and unique_address.strip():
            raise HTTPException(status_code=400, detail="An asset with a MAC address must not also carry a Unique Address.")
        return normalize_mac(mac), None
    if mac and mac.strip():
        raise HTTPException(status_code=400, detail="MAC Address was given but 'has MAC address' is NO.")
    return None, normalize_unique_address(unique_address)


async def find_duplicate(db: AsyncSession, serial: str, mac: Optional[str], unique_address: Optional[str]) -> Optional[str]:
    """Return which identifier already exists anywhere in the registry: 'serial', 'mac' or 'unique_address'."""
    if (await db.execute(select(Asset.id).where(func.lower(func.btrim(Asset.serial_number)) == serial.strip().lower()))).first():
        return "serial"
    if mac:
        norm = re.sub(r"[^0-9a-f]", "", mac.lower())
        expr = func.lower(func.regexp_replace(Asset.mac_address, "[^0-9a-fA-F]", "", "g"))
        if (await db.execute(select(Asset.id).where(Asset.mac_address.is_not(None), expr == norm))).first():
            return "mac"
    if unique_address:
        if (await db.execute(select(Asset.id).where(Asset.device_unique_address.is_not(None),
                                                    func.lower(func.btrim(Asset.device_unique_address)) == unique_address.strip().lower()))).first():
            return "unique_address"
    return None


DUPLICATE_EVENTS = {
    "serial": ("DUPLICATE_SERIAL_ATTEMPT", "Asset serial number already exists."),
    "mac": ("DUPLICATE_MAC_ATTEMPT", "MAC address is already registered to an asset."),
    "unique_address": ("DUPLICATE_UNIQUE_ADDRESS_ATTEMPT", "Device unique address is already registered to an asset."),
}
