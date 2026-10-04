"""What verification checks, and how much of it each viewer is told.

Every check is one row: what was compared, what the record says, what the copy (or the ledger)
shows, the result, and in words why. The public verify page gets a reduced view (field results
and the file-hash result, never the invisible mark). Auditors get every row, and every
verification is written to the audit trail with all of its rows under details["verification"],
which only Auditors are shown (app.api.audit).

Results: "match", "differs" (a contradiction: the copy or ledger disagrees with the record),
"not_on_record" (the copy shows something the record doesn't have: also a contradiction) and
"unavailable" (nothing to compare against; not a contradiction).
"""

from __future__ import annotations

import hashlib
from typing import Optional

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.domain import Asset, DocumentAction, User
from app.services import hidden_mark

CONTRADICTIONS = ("differs", "not_on_record")

# Fields that appear on a protected copy's watermark, keyed by their label.
FIELDS = ("Viewed by", "Downloaded by", "Wallet", "IP", "Date", "View ID", "Download ID", "Owner")


def check(key: str, group: str, label: str, result: str, *, expected=None, found=None, reason: str = "") -> dict:
    return {"key": key, "group": group, "label": label, "expected": expected, "found": found, "result": result, "reason": reason}


def recorded_fields(action: DocumentAction) -> dict[str, str]:
    """The authoritative watermark block stored on the action when the copy was made."""
    out = {}
    for line in (action.watermark_text or "").splitlines():
        if ": " in line:
            label, value = line.split(": ", 1)
            if label in FIELDS and label not in out:
                out[label] = value.strip()
    return out


def normalize_hash(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = "".join(value.split()).lower()
    return v[2:] if v.startswith("0x") else v


async def _user(db: AsyncSession, user_id) -> Optional[User]:
    return (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none() if user_id else None


async def describe_action(db: AsyncSession, action: DocumentAction) -> dict:
    """Who a copy was issued to, when and where (for Auditors)."""
    actor = await _user(db, action.actor_id)
    return {
        "action_id": action.action_id, "action_type": action.action_type, "asset_serial": action.asset_serial,
        "asset_version": action.asset_version, "issued_to": actor.name if actor else None,
        "issued_to_wallet": actor.wallet_address if actor else None, "issued_to_did": action.actor_did,
        "issued_at": action.created_at.isoformat() if action.created_at else None, "client_ip": action.client_ip,
        "status": action.status,
    }


async def evaluate_copy(db: AsyncSession, action: DocumentAction, asset: Asset, *, method: str,
                        claimed: Optional[dict] = None, serial: Optional[str] = None, version: Optional[int] = None,
                        typed_hash: Optional[str] = None, file_bytes: Optional[bytes] = None,
                        filename: Optional[str] = None) -> dict:
    """Run every check for a copy that claims to be `action`. Returns the full (Auditor) result."""
    checks = [check("record", "record", "Reference exists in the LexCorp record", "match",
                    expected=action.action_id, found=action.action_id,
                    reason=f"{action.action_type.title()} of {asset.serial_number} version {asset.version_number}.")]

    # 1. The visible watermark, field by field
    recorded = recorded_fields(action)
    for label, value in (claimed or {}).items():
        label, value = label.strip(), (value or "").strip()
        if label not in FIELDS or not value:
            continue
        expected = recorded.get(label)
        if expected is None:
            checks.append(check(label, "watermark", label, "not_on_record", found=value,
                                reason=f"The copy shows a '{label}' line, but the copy issued under this reference had none."))
        elif expected == value:
            checks.append(check(label, "watermark", label, "match", expected=expected, found=value,
                                reason="Same as the watermark recorded when the copy was issued."))
        else:
            checks.append(check(label, "watermark", label, "differs", expected=expected, found=value,
                                reason=f"The copy shows “{value}”; the copy issued under this reference said “{expected}”."))
    if serial is not None:
        ok = serial == asset.serial_number
        checks.append(check("asset_serial", "watermark", "Asset ID", "match" if ok else "differs", expected=asset.serial_number,
                            found=serial, reason="" if ok else "The copy names a different asset than this reference."))
    if version is not None:
        ok = version == asset.version_number
        checks.append(check("version", "watermark", "Document version", "match" if ok else "differs", expected=asset.version_number,
                            found=version, reason="" if ok else "The copy names a different version than this reference."))

    # 2. The file's SHA-256 (typed, or computed from the uploaded file)
    shown_hash = hashlib.sha256(file_bytes).hexdigest() if file_bytes is not None else normalize_hash(typed_hash)
    if shown_hash:
        checks.append(await _hash_check(db, action, asset, shown_hash))

    # 3. The invisible mark (uploaded files only)
    hidden = None
    if file_bytes is not None:
        hidden = await _hidden_check(db, action, file_bytes)
        checks.append(hidden)

    contradictions = [c for c in checks if c["result"] in CONTRADICTIONS]
    compared = [c for c in checks if c["group"] != "record" and c["result"] != "unavailable"]
    verdict = "MISMATCH" if contradictions else ("MATCH" if compared else "NOTHING_TO_COMPARE")
    return {
        "action_id": action.action_id, "record_found": True, "method": method, "verdict": verdict,
        "checks": checks, "contradictions": [c["key"] for c in contradictions],
        "file": {"name": filename, "size": len(file_bytes), "sha256": shown_hash} if file_bytes is not None else None,
        "issued_copy": await describe_action(db, action) | {"copy_sha256": action.copy_sha256,
                                                            "hidden_mark_recorded": bool(action.hidden_mark)},
    }


async def _hash_check(db: AsyncSession, action: DocumentAction, asset: Asset, shown: str) -> dict:
    expected = action.copy_sha256 or asset.file_hash
    base = dict(expected=expected, found=shown)
    if action.copy_sha256 and shown == action.copy_sha256:
        return check("file_hash", "hash", "File SHA-256", "match", **base,
                     reason="Byte-for-byte identical to the copy issued under this reference.")
    if shown == normalize_hash(asset.file_hash):
        if action.action_type in ("CREATION", "MODIFICATION"):
            return check("file_hash", "hash", "File SHA-256", "match", **base,
                         reason="Identical to the document version this reference records.")
        return check("file_hash", "hash", "File SHA-256", "differs", **base,
                     reason="This is the original document without any watermark, not the copy issued under this reference.")
    other = (await db.execute(select(DocumentAction).where(DocumentAction.copy_sha256 == shown)
                              .where(DocumentAction.id != action.id))).scalars().first()
    if other is not None:
        who = await describe_action(db, other)
        return check("file_hash", "hash", "File SHA-256", "differs", **base,
                     reason=f"This file is the copy issued under {other.action_id} to {who['issued_to'] or 'an unnamed identity'}, "
                            f"not under this reference.")
    version = (await db.execute(select(Asset).where(or_(Asset.root_asset_id == (asset.root_asset_id or asset.id),
                                                        Asset.id == (asset.root_asset_id or asset.id)))
                                .where(Asset.file_hash == shown))).scalars().first()
    if version is not None:
        return check("file_hash", "hash", "File SHA-256", "differs", **base,
                     reason=f"This is version {version.version_number} of the document without a watermark, not the copy issued under this reference.")
    if action.copy_sha256:
        return check("file_hash", "hash", "File SHA-256", "differs", **base,
                     reason="The file was changed after it was issued: its SHA-256 is not the issued copy's.")
    return check("file_hash", "hash", "File SHA-256", "unavailable", **base,
                 reason="This reference was issued before copy fingerprints were recorded, so the file's hash can't be compared.")


async def _hidden_check(db: AsyncSession, action: DocumentAction, data: bytes) -> dict:
    marks = hidden_mark.read_marks(data)
    owners = {}
    if marks:
        rows = (await db.execute(select(DocumentAction).where(DocumentAction.hidden_mark.in_(marks)))).scalars().all()
        owners = {r.hidden_mark: r for r in rows}
    found = ", ".join(marks) or None
    if action.hidden_mark and marks == [action.hidden_mark]:
        return check("hidden_mark", "hidden", "Invisible mark", "match", expected=action.hidden_mark, found=found,
                     reason="The invisible mark inside the file belongs to this copy.")
    foreign = [owners[m] for m in marks if m in owners and owners[m].id != action.id]
    if foreign:
        who = await describe_action(db, foreign[0])
        return check("hidden_mark", "hidden", "Invisible mark", "differs", expected=action.hidden_mark, found=found,
                     reason=f"The invisible mark belongs to {foreign[0].action_id}, issued to {who['issued_to'] or 'an unnamed identity'} "
                            f"({who['issued_to_wallet'] or 'no wallet'}) on {(who['issued_at'] or '')[:10]}: the visible watermark "
                            f"was changed to point at this reference.")
    if marks and not owners:
        return check("hidden_mark", "hidden", "Invisible mark", "differs", expected=action.hidden_mark, found=found,
                     reason="The file carries an invisible mark that no LexCorp copy was issued with (forged or corrupted).")
    if action.hidden_mark:
        return check("hidden_mark", "hidden", "Invisible mark", "differs", expected=action.hidden_mark, found=None,
                     reason="The invisible mark this copy was issued with is missing: the file was rebuilt, converted or edited.")
    return check("hidden_mark", "hidden", "Invisible mark", "unavailable", found=found,
                 reason="This reference was issued before invisible marks were added.")


async def identify_file(db: AsyncSession, data: bytes) -> dict:
    """Which issued copy (if any) a file is, from its hash and its invisible mark (Auditors)."""
    sha = hashlib.sha256(data).hexdigest()
    by_hash = (await db.execute(select(DocumentAction).where(DocumentAction.copy_sha256 == sha))).scalars().first()
    marks = hidden_mark.read_marks(data)
    by_mark = (await db.execute(select(DocumentAction).where(DocumentAction.hidden_mark.in_(marks)))).scalars().all() if marks else []
    original = (await db.execute(select(Asset).where(Asset.file_hash == sha))).scalars().first()
    return {
        "sha256": sha, "size": len(data), "marks_found": marks,
        "exact_copy_of": await describe_action(db, by_hash) if by_hash else None,
        "hidden_mark_of": [await describe_action(db, a) for a in by_mark],
        "unwatermarked_original_of": {"serial": original.serial_number, "version": original.version_number} if original else None,
    }


def public_view(result: dict) -> dict:
    """What the public verify page is told: field results and the hash result, no expected
    values beyond the field itself, and nothing about the invisible mark."""
    visible = [c for c in result["checks"] if c["group"] in ("watermark", "hash")]
    fields = [c for c in visible if c["group"] == "watermark"]
    hash_check = next((c for c in visible if c["group"] == "hash"), None)
    out = {
        "action_id": result["action_id"], "record_found": True, "verdict": result["verdict"],
        "fields_checked": len(fields),
        "results": [{"field": c["label"], "shown": c["found"], "matches_record": c["result"] == "match"} for c in fields],
        "mismatches": [c["key"] for c in visible if c["result"] in CONTRADICTIONS],
    }
    if hash_check:
        out["hash"] = {"shown": hash_check["found"], "result": hash_check["result"], "message": {
            "match": "The file is identical to the record.",
            "differs": "The file is not the copy issued under this reference.",
            "unavailable": "No file fingerprint was recorded for this reference.",
        }[hash_check["result"]]}
    return out


def audit_summary(result: dict) -> dict:
    """The audit row for a verification: a summary anyone with the row can read, plus every
    check under "verification" (shown to Auditors only)."""
    return {"action_id": result["action_id"], "verdict": result["verdict"], "method": result["method"],
            "verification": {k: result[k] for k in ("checks", "contradictions", "file", "issued_copy") if result.get(k) is not None}}


async def evaluate_asset(db: AsyncSession, serial: str, asset: Optional[Asset], token_id: Optional[int], on_chain: Optional[dict]) -> dict:
    """Registry and ledger cross-checks behind an asset (QR / label / card) verification."""
    checks = []
    checks.append(check("registry", "record", "Asset in the LexCorp registry", "match" if asset else "differs",
                        expected=serial, found=asset.serial_number if asset else None,
                        reason="" if asset else "The ledger knows this serial, but the registry has no record of it."))
    checks.append(check("ledger_token", "ledger", "Token on the ledger", "match" if token_id is not None else "differs",
                        expected=asset.token_id if asset else None, found=token_id,
                        reason="" if token_id is not None else "No token is minted on the ledger for this serial."))
    if asset and token_id is not None and asset.token_id is not None and asset.token_id != token_id:
        checks.append(check("token_id", "ledger", "Token ID", "differs", expected=asset.token_id, found=token_id,
                            reason="The registry and the ledger name different tokens for this serial."))
    if on_chain:
        ok = on_chain.get("serial_number") == serial
        checks.append(check("ledger_serial", "ledger", "Serial on the token", "match" if ok else "differs",
                            expected=serial, found=on_chain.get("serial_number"),
                            reason="" if ok else "The token on the ledger carries a different serial."))
        if asset:
            owner = await _user(db, asset.owner_id)
            want = (owner.wallet_address if owner else "") or ""
            got = on_chain.get("owner_address") or ""
            if want and got:
                ok = want.lower() == got.lower()
                checks.append(check("owner", "ledger", "Owner wallet", "match" if ok else "differs", expected=want, found=got,
                                    reason="" if ok else "The ledger's token holder is not the registry's owner."))
            if on_chain.get("is_digital") and asset.file_hash:
                want, got = normalize_hash(asset.file_hash), normalize_hash(on_chain.get("file_hash"))
                ok = want == got
                checks.append(check("file_hash", "ledger", "Document SHA-256 on the ledger", "match" if ok else "differs",
                                    expected=want, found=got,
                                    reason="" if ok else "The document hash anchored on the ledger is not the registry's."))
    if asset:
        status = f"{asset.approval_status or '-'} / {asset.lifecycle_status or '-'}"
        bad = (asset.lifecycle_status or "").upper() in ("REVOKED", "BURNED", "DISPOSED")
        checks.append(check("status", "record", "Approval and lifecycle", "differs" if bad else "match", found=status,
                            reason="The asset is no longer in service." if bad else ""))
    contradictions = [c for c in checks if c["result"] in CONTRADICTIONS]
    return {"serial": serial, "verdict": "MISMATCH" if contradictions else "MATCH", "method": "asset",
            "checks": checks, "contradictions": [c["key"] for c in contradictions]}
