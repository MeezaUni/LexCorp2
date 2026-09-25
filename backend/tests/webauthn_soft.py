"""A minimal software WebAuthn authenticator for tests.

Produces genuine "none"-attestation registration responses and ECDSA P-256
(ES256) signed assertions, so passkey tests exercise py_webauthn's real
cryptographic verification rather than a mock.
"""

import base64
import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ORIGIN = "http://localhost:5173"
RP_ID = "localhost"

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SoftPasskey:
    def __init__(self, rp_id: str = RP_ID, origin: str = ORIGIN):
        self.rp_id = rp_id
        self.origin = origin
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0

    @property
    def credential_id_hex(self) -> str:
        return self.credential_id.hex()

    def _cose_public_key(self) -> bytes:
        numbers = self.private_key.public_key().public_numbers()
        return cbor2.dumps({
            1: 2,    # kty: EC2
            3: -7,   # alg: ES256
            -1: 1,   # crv: P-256
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        })

    def _client_data(self, typ: str, challenge: str) -> bytes:
        return json.dumps({
            "type": typ, "challenge": challenge, "origin": self.origin, "crossOrigin": False,
        }).encode()

    def register(self, options: dict) -> dict:
        """Respond to server registration options (PublicKeyCredentialCreationOptions JSON)."""
        client_data = self._client_data("webauthn.create", options["challenge"])
        rp_hash = hashlib.sha256(self.rp_id.encode()).digest()
        attested = (
            b"\x00" * 16
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + self._cose_public_key()
        )
        auth_data = rp_hash + bytes([FLAG_UP | FLAG_UV | FLAG_AT]) + struct.pack(">I", self.sign_count) + attested
        attestation_object = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "attestationObject": b64url(attestation_object),
            },
        }

    def assert_(self, options: dict, *, flags: int = FLAG_UP | FLAG_UV, tamper: bool = False) -> dict:
        """Sign an authentication challenge (PublicKeyCredentialRequestOptions JSON)."""
        self.sign_count += 1
        client_data = self._client_data("webauthn.get", options["challenge"])
        rp_hash = hashlib.sha256(self.rp_id.encode()).digest()
        auth_data = rp_hash + bytes([flags]) + struct.pack(">I", self.sign_count)
        signature = self.private_key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        if tamper:
            signature = signature[:-1] + bytes([signature[-1] ^ 0x01])
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "authenticatorData": b64url(auth_data),
                "signature": b64url(signature),
                "userHandle": None,
            },
        }
