"""Verifiable Credential (VC) issuance using W3C VC 2.0 JWT-VC format.

Implements JWT-VC (JWT Verifiable Credentials) per W3C VC 2.0 spec.
VC is issued by a verifier role to the user's DID as cryptographic proof of KYC.
"""

import uuid
from datetime import datetime, timedelta, UTC
from typing import Optional

from jose import jwt
from pydantic import BaseModel

from app.core.config import settings
from app.models.domain import VerifiableCredential


class VCPayload(BaseModel):
    """JWT-VC payload per W3C VC 2.0."""
    iss: str          # Issuer DID
    sub: str          # Subject (holder) DID
    aud: str          # Audience (typically the platform DID)
    jti: str          # Unique VC ID
    vc: dict          # VerifiableCredential JSON-LD structure
    iat: datetime
    exp: datetime
    nbf: datetime     # Not before


def create_kyc_vc(
    issuer_did: str,
    subject_did: str,
    verification_level: str = "STANDARD_KYC",
) -> tuple[str, VerifiableCredential]:
    """Create a KYC Verifiable Credential JWT-VC.

    Args:
        issuer_did: DID of the verifier issuing the credential
        subject_did: DID of the holder receiving the credential
        verification_level: Level of KYC performed (default: STANDARD_KYC)

    Returns:
        Tuple of (jwt_string, VerifiableCredential model for DB storage)
    """
    now = datetime.now(UTC)
    vc_id = f"urn:uuid:{uuid.uuid4()}"

    # JWT header
    header = {
        "alg": "ES256K",
        "typ": "JWT",
        "kid": issuer_did,
    }

    # JWT payload with W3C VC 2.0 structure
    payload = {
        "iss": issuer_did,
        "sub": subject_did,
        "aud": "lexcorp-sih-platform",
        "jti": vc_id,
        "iat": now,
        "exp": now + timedelta(days=365),  # VC valid for 1 year
        "nbf": now,
        "vc": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://lexcorp-sih.example.com/credentials/v1",
            ],
            "id": vc_id,
            "type": ["VerifiableCredential", "KYCCredential"],
            "issuer": {
                "id": issuer_did,
            },
            "credentialSubject": {
                "id": subject_did,
                "kycVerification": {
                    "level": verification_level,
                    "verifiedAt": now.isoformat(),
                    "status": "VERIFIED",
                },
            },
            "issuanceDate": now.isoformat(),
            "expirationDate": (now + timedelta(days=365)).isoformat(),
        },
    }

    # Sign the JWT (in production, the issuer's wallet would sign this)
    # For prototype: use a symmetric key derived from JWT_SECRET
    vc_jwt = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM, headers=header)

    # Create DB model for storage (not for verification — verification is done via JWT)
    db_model = VerifiableCredential(
        id=uuid.UUID(vc_id.replace("urn:uuid:", "")),
        vc_jwt=vc_jwt,
        issuer_did=issuer_did,
        subject_did=subject_did,
        type="KYCCredential",
    )

    return vc_jwt, db_model


def verify_vc_jwt(vc_jwt: str) -> Optional[dict]:
    """Verify and decode a VC JWT.

    Returns the payload if valid, None if invalid or expired.
    In production, verification would:
      1. Resolve the issuer DID to get their public key
      2. Verify the JWT signature against that key
      3. Check nbf, exp timestamps
    """
    try:
        # In production, would use issuer's public key from DID resolution
        # For prototype, we verify with our signing key (one-way trust)
        payload = jwt.decode(
            vc_jwt,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            audience="lexcorp-sih-platform",
        )
        return payload
    except jwt.JWTError:
        return None