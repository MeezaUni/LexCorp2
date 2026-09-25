"""Dedicated high-risk security alerts with an escalation history.

Chain: AI/RULE -> AUDITOR_REVIEW -> (DISMISSED | MANAGER_REVIEW) -> (DISMISSED |
ADMIN_REVIEW) -> (DISMISSED | IDENTITY_REVOKED). Every step is an append-only row in
security_alert_actions.

Backfill (scoped, idempotent): every existing HIGH/CRITICAL audit event gets an alert
whose state mirrors its current alert_status (OPEN->AUDITOR_REVIEW,
FORWARDED_TO_MANAGER->MANAGER_REVIEW, ESCALATED_TO_ADMIN->ADMIN_REVIEW,
DISMISSED/RESOLVED->DISMISSED), with a history row marking it as a legacy import.
The source audit events are not modified.

Revision ID: 0009_security_alerts
Revises: 0008_physical_uniqueness
"""
import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009_security_alerts"
down_revision: Union[str, None] = "0008_physical_uniqueness"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_STATE = {"OPEN": "AUDITOR_REVIEW", "FORWARDED_TO_MANAGER": "MANAGER_REVIEW",
          "ESCALATED_TO_ADMIN": "ADMIN_REVIEW", "DISMISSED": "DISMISSED", "RESOLVED": "DISMISSED"}


def upgrade() -> None:
    op.execute("""
    CREATE TABLE IF NOT EXISTS security_alerts (
        id UUID PRIMARY KEY,
        alert_id VARCHAR(32) NOT NULL,
        source VARCHAR(10) NOT NULL,
        source_event_id UUID REFERENCES audit_events(id),
        subject_user_id UUID REFERENCES users(id),
        subject_did VARCHAR,
        subject_role VARCHAR(20),
        subject_wallet VARCHAR(42),
        department VARCHAR(255),
        risk_level VARCHAR(10) NOT NULL,
        risk_score DOUBLE PRECISION,
        reason TEXT,
        event_type VARCHAR,
        asset_serial VARCHAR,
        related_action_id VARCHAR(64),
        client_ip VARCHAR(64),
        state VARCHAR(20) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    )""")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_security_alerts_alert_id ON security_alerts (alert_id)")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_security_alerts_source_event_id ON security_alerts (source_event_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_security_alerts_state ON security_alerts (state)")
    op.execute("""
    CREATE TABLE IF NOT EXISTS security_alert_actions (
        id UUID PRIMARY KEY,
        alert_id UUID NOT NULL REFERENCES security_alerts(id),
        actor_user_id UUID REFERENCES users(id),
        actor_did VARCHAR,
        actor_role VARCHAR(20),
        action VARCHAR(30) NOT NULL,
        from_state VARCHAR(20),
        to_state VARCHAR(20) NOT NULL,
        note TEXT,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    )""")
    op.execute("CREATE INDEX IF NOT EXISTS ix_security_alert_actions_alert_id ON security_alert_actions (alert_id)")

    bind = op.get_bind()
    rows = bind.execute(sa.text("""
        SELECT e.id, e.event_type, e.actor_did, e.asset_serial, e.client_ip, e.risk_label, e.risk_score,
               e.risk_factors, e.alert_status, e.created_at, u.id, u.role, u.wallet_address, u.department
        FROM audit_events e LEFT JOIN users u ON u.did = e.actor_did
        WHERE e.risk_label IN ('HIGH', 'CRITICAL')
          AND NOT EXISTS (SELECT 1 FROM security_alerts s WHERE s.source_event_id = e.id)
        ORDER BY e.created_at""")).fetchall()
    for (eid, etype, did, serial, ip, label, score, factors, status, created, uid, role, wallet, dept) in rows:
        day = created.date()
        n = bind.execute(sa.text(
            "INSERT INTO action_id_counters (prefix, day, last_value) VALUES ('ALT', :d, 1) "
            "ON CONFLICT (prefix, day) DO UPDATE SET last_value = action_id_counters.last_value + 1 RETURNING last_value"
        ), {"d": day}).scalar_one()
        alert_uuid = uuid.uuid4()
        state = _STATE.get((status or "OPEN").upper(), "AUDITOR_REVIEW")
        reason = factors.get("reason") if isinstance(factors, dict) else None
        bind.execute(sa.text("""
            INSERT INTO security_alerts (id, alert_id, source, source_event_id, subject_user_id, subject_did, subject_role,
                subject_wallet, department, risk_level, risk_score, reason, event_type, asset_serial, client_ip, state,
                created_at, updated_at)
            VALUES (:id, :aid, 'LEGACY', :eid, :uid, :did, :role, :wallet, :dept, :label, :score, :reason, :etype, :serial,
                    :ip, :state, :created, now())"""),
            {"id": alert_uuid, "aid": f"ALT-{day:%Y%m%d}-{n:04d}", "eid": eid, "uid": uid, "did": did, "role": role,
             "wallet": wallet, "dept": dept, "label": label, "score": score, "reason": reason or f"{etype} flagged {label}",
             "etype": etype, "serial": serial, "ip": ip, "state": state, "created": created})
        bind.execute(sa.text("""
            INSERT INTO security_alert_actions (id, alert_id, action, from_state, to_state, note, created_at, updated_at)
            VALUES (:id, :aid, 'IMPORTED', NULL, :state, :note, now(), now())"""),
            {"id": uuid.uuid4(), "aid": alert_uuid, "state": state,
             "note": f"Imported from audit event triage status '{status}' (migration 0009)"})


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS security_alert_actions")
    op.execute("DROP TABLE IF EXISTS security_alerts")
