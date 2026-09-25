"""Secret management: fail-closed configuration, key separation, key migration."""

import base64
import secrets
import uuid

import pytest
from sqlalchemy import select

from app.core.config import Settings
from app.core.crypto import build_keyring, decrypt_secret, encrypt_secret, legacy_jwt_derived_key
from app.models.domain import User
from app.services.key_rotation import rotate_encryption


def fkey() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def good(**over):
    base = dict(
        ENVIRONMENT="development",
        DATABASE_URL="postgresql+asyncpg://u:p@localhost/db",
        JWT_SECRET=secrets.token_urlsafe(48),
        VC_SIGNING_SECRET=secrets.token_urlsafe(48),
        DATA_ENCRYPTION_KEYS=fkey(),
    )
    base.update(over)
    return base


def prod(**over):
    return good(
        ENVIRONMENT="production",
        DATABASE_URL=f"postgresql+asyncpg://lexcorp:{secrets.token_urlsafe(24)}@db/lexcorp",
        CHAIN_OPERATOR_PRIVATE_KEY="0x" + secrets.token_hex(32),
        CORS_ORIGINS=["https://lexcorp.example.org"],
        WEBAUTHN_ORIGINS=["https://lexcorp.example.org"],
        PUBLIC_BASE_URL="https://lexcorp.example.org",
        **over,
    )


def test_valid_development_and_production_settings_load():
    assert Settings(_env_file=None, **good()).ENVIRONMENT == "development"
    assert Settings(_env_file=None, **prod()).is_production


def test_environment_defaults_to_production_so_missing_config_fails_closed(monkeypatch):
    for k in ("ENVIRONMENT", "JWT_SECRET", "VC_SIGNING_SECRET", "DATA_ENCRYPTION_KEYS", "DATABASE_URL", "DEBUG"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(ValueError) as e:
        Settings(_env_file=None)
    msg = str(e.value)
    assert "production" in msg
    for needle in ("JWT_SECRET", "DATA_ENCRYPTION_KEYS", "VC_SIGNING_SECRET", "DATABASE_URL", "CHAIN_OPERATOR_PRIVATE_KEY"):
        assert needle in msg


@pytest.mark.parametrize("missing", ["JWT_SECRET", "DATA_ENCRYPTION_KEYS", "VC_SIGNING_SECRET", "CHAIN_OPERATOR_PRIVATE_KEY"])
def test_missing_production_secret_fails_closed(missing):
    cfg = prod()
    cfg[missing] = ""
    with pytest.raises(ValueError, match=missing):
        Settings(_env_file=None, **cfg)


@pytest.mark.parametrize("value", ["weak", "development-secret-key-replace-in-production-1234567890", "x" * 40])
def test_weak_or_published_jwt_secret_rejected_everywhere(value):
    for cfg in (good(JWT_SECRET=value), prod(JWT_SECRET=value)):
        with pytest.raises(ValueError, match="JWT_SECRET"):
            Settings(_env_file=None, **cfg)


def test_development_database_password_and_debug_rejected_in_production():
    with pytest.raises(ValueError, match="database password"):
        Settings(_env_file=None, **{**prod(), "DATABASE_URL": "postgresql+asyncpg://lexcorp:lexcorp_dev@localhost/x"})
    with pytest.raises(ValueError, match="DEBUG"):
        Settings(_env_file=None, **prod(DEBUG=True))


def test_production_requires_https_and_no_cors_wildcard():
    with pytest.raises(ValueError, match="wildcard"):
        Settings(_env_file=None, **{**prod(), "CORS_ORIGINS": ["*", "https://a.example"]})
    with pytest.raises(ValueError, match="HTTPS"):
        Settings(_env_file=None, **{**prod(), "PUBLIC_BASE_URL": "http://lexcorp.example.org"})
    with pytest.raises(ValueError, match="HTTPS"):
        Settings(_env_file=None, **{**prod(), "WEBAUTHN_ORIGINS": ["https://a.example", "http://malicious.com"]})


def test_insecure_webauthn_origin_rejected_in_development():
    with pytest.raises(ValueError, match="WebAuthn"):
        Settings(_env_file=None, **good(WEBAUTHN_ORIGINS=["http://malicious.com"]))


def test_cryptographic_purposes_are_separated():
    shared = secrets.token_urlsafe(48)
    with pytest.raises(ValueError, match="different keys"):
        Settings(_env_file=None, **good(JWT_SECRET=shared, VC_SIGNING_SECRET=shared))
    with pytest.raises(ValueError, match="valid Fernet"):
        Settings(_env_file=None, **good(DATA_ENCRYPTION_KEYS="not-a-key"))


def test_plaintext_secrets_are_refused_by_decrypt():
    assert decrypt_secret("JBSWY3DPEHPK3PXP") is None
    assert decrypt_secret(encrypt_secret("JBSWY3DPEHPK3PXP")) == "JBSWY3DPEHPK3PXP"


@pytest.mark.asyncio
async def test_encrypted_records_survive_key_migration(db_session):
    """Records written under the legacy JWT-derived key, under a retired Fernet key and
    as legacy plaintext are all readable under the new key alone after rotation."""
    old_jwt = secrets.token_urlsafe(48)
    legacy_ring = build_keyring([legacy_jwt_derived_key(old_jwt)])
    retired = fkey()
    from app.core.config import settings
    new = settings.data_encryption_keys[0]  # the active key; every other user stays readable
    wallet = "0x" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
    u = User(
        wallet_address=wallet, did=f"did:ethr:13371:{wallet}", role="USER", name="Key Migration",
        totp_secret=encrypt_secret("LEGACYDERIVEDSECRET", legacy_ring),
        totp_factor2_secret=encrypt_secret("RETIREDKEYSECRET", build_keyring([retired])),
        totp_factor3_secret="PLAINTEXTLEGACY",
        wallet_wrap_secret=encrypt_secret("wrap-secret-value", build_keyring([retired])),
    )
    db_session.add(u)
    await db_session.commit()

    # A rotation that lacks an old key must not commit anything.
    report = await rotate_encryption(db_session, [new], [retired])
    assert not report.ok and report.unreadable
    fresh = (await db_session.execute(select(User).where(User.wallet_address == wallet))).scalar_one()
    await db_session.refresh(fresh)
    assert fresh.totp_factor3_secret == "PLAINTEXTLEGACY"

    report = await rotate_encryption(db_session, [new], [retired, legacy_jwt_derived_key(old_jwt)])
    assert report.ok and report.plaintext_migrated >= 1 and report.reencrypted >= 3
    fresh = (await db_session.execute(select(User).where(User.wallet_address == wallet))).scalar_one()
    await db_session.refresh(fresh)
    only_new = build_keyring([new])
    assert decrypt_secret(fresh.totp_secret, only_new) == "LEGACYDERIVEDSECRET"
    assert decrypt_secret(fresh.totp_factor2_secret, only_new) == "RETIREDKEYSECRET"
    assert decrypt_secret(fresh.totp_factor3_secret, only_new) == "PLAINTEXTLEGACY"
    assert decrypt_secret(fresh.wallet_wrap_secret, only_new) == "wrap-secret-value"
    assert decrypt_secret(fresh.totp_secret, legacy_ring) is None  # old key no longer needed
