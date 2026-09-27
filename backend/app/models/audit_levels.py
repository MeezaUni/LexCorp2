"""Baseline risk levels for audit events that neither the AI nor a rule scores.

Behaviour the local risk model understands (sign-ins, views, downloads, registrations, approvals,
delegations, failures) is scored by the model, and integrity or security rules (tampering,
duplicates, denied access, ledger events) set their own level. Every other event is labelled here
by its nature, so no audit row is left without a level, and it is marked as such
(risk_factors.risk_basis). Baselines never reach HIGH, so they don't raise alerts.
"""

BASIS = "event type (not scored by the AI)"

MEDIUM = {
    # changes to who can do what, or to how people prove who they are
    "USER_PROVISIONED", "ROLE_CHANGED", "MANAGER_DEPARTMENTS_UPDATED", "IDENTITY_REVOKED",
    "ALERT_IDENTITY_REVOKED", "ACCESS_REVOKED",
    "PROVISIONING_PIN_REISSUED", "LOGIN_RESET_REQUESTED", "ADMIN_LOGIN_RESET_APPROVED",
    "ADMIN_LOGIN_RESET_BY_OPERATOR", "TOTP_RESET", "PASSKEY_DISABLED",
    "FACTOR_USES_LOGIN_ENABLED", "FACTOR_USES_LOGIN_DISABLED",
    # a registration that duplicates an existing asset (the specific attempt is scored HIGH separately)
    "DUPLICATE_PHYSICAL_ASSET_ATTEMPT",
    # one account in use from two places
    "SESSION_REPLACED_BY_NEW_LOGIN", "SESSION_ENDED_REPLACED",
    # looking at another person's tamper evidence, re-reading the ledger
    "ALERT_EVIDENCE_VIEWED", "INDEXER_RESCAN",
}

SCORES = {"LOW": 0.1, "MEDIUM": 0.4}


def baseline(event_type: str) -> str:
    """LOW for routine events (enrolling a factor, signing out, role sync, alert decisions, asset
    record keeping), MEDIUM for the sensitive ones above."""
    return "MEDIUM" if event_type in MEDIUM else "LOW"
