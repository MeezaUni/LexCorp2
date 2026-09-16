"""Web3 contract integration — read contract state and prepare calldata.

The backend NEVER holds a private key capable of minting, transferring, or revoking.
It only reads on-chain state and prepares unsigned transaction data for the frontend.
"""

from typing import Optional
from web3 import Web3
from web3.contract import Contract
import json

from app.core.config import settings


import os

class ContractService:
    """Interface to deployed AssetNFT contract."""

    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(settings.RPC_URL))
        self.deployment_path = r"C:\Users\MAK\Desktop\LexCorp-SIH-V2\contracts\deployments\localhost.json"
        self._last_mtime = 0
        self._contract_address = ""
        self._contract = None
        self._ensure_loaded()

    def _ensure_loaded(self):
        """Reload contract ABI & address if localhost.json has been updated on disk."""
        try:
            if not os.path.exists(self.deployment_path):
                return
            mtime = os.path.getmtime(self.deployment_path)
            if mtime != self._last_mtime or self._contract is None:
                with open(self.deployment_path, "r") as f:
                    deployment = json.load(f)
                self._contract_address = deployment["address"]
                self._contract = self.w3.eth.contract(
                    address=Web3.to_checksum_address(self._contract_address),
                    abi=deployment["abi"],
                )
                self._last_mtime = mtime
        except Exception:
            pass

    @property
    def contract_address(self) -> str:
        self._ensure_loaded()
        return self._contract_address

    @property
    def contract(self) -> Contract:
        self._ensure_loaded()
        return self._contract

    def get_manager_role(self) -> str:
        """Get the MANAGER_ROLE bytes32 constant."""
        return self.contract.functions.MANAGER_ROLE().call()

    def has_role(self, role: str, account: str) -> bool:
        """Check if an account has a specific role."""
        return self.contract.functions.hasRole(
            Web3.to_bytes(hexstr=role),
            Web3.to_checksum_address(account),
        ).call()

    def get_asset(self, token_id: int) -> Optional[dict]:
        """Fetch on-chain asset metadata."""
        try:
            serial, owner_did = self.contract.functions.getAsset(token_id).call()
            owner_address = self.contract.functions.ownerOf(token_id).call()
            return {
                "token_id": token_id,
                "serial_number": serial,
                "owner_did": owner_did,
                "owner_address": owner_address,
            }
        except Exception:
            return None

    def get_token_by_serial(self, serial: str) -> Optional[int]:
        """Look up token ID by serial number."""
        try:
            token_id = self.contract.functions.getTokenBySerial(serial).call()
            return token_id if token_id != 0 else None
        except Exception:
            return None

    def prepare_mint_calldata(
        self,
        to_address: str,
        token_id: int,
        serial_number: str,
        owner_did: str,
    ) -> dict:
        """Prepare unsigned mint transaction data for frontend signing.

        Returns dict with 'to', 'data', 'value' ready for MetaMask.
        """
        tx_data = self.contract.functions.mint(
            Web3.to_checksum_address(to_address),
            token_id,
            serial_number,
            owner_did,
        ).build_transaction({
            "from": "0x0000000000000000000000000000000000000000",  # Placeholder — frontend replaces
            "gas": 300000,
            "gasPrice": self.w3.eth.gas_price,
            "nonce": 0,  # Frontend fetches the real nonce
        })

        return {
            "to": self.contract_address,
            "data": tx_data["data"],
            "value": "0x0",
            "gas": hex(tx_data["gas"]),
            "gasPrice": hex(tx_data["gasPrice"]),
        }

    def prepare_transfer_calldata(
        self,
        to_address: str,
        token_id: int,
        new_owner_did: str,
    ) -> dict:
        """Prepare unsigned transferAsset transaction."""
        tx_data = self.contract.functions.transferAsset(
            Web3.to_checksum_address(to_address),
            token_id,
            new_owner_did,
        ).build_transaction({
            "from": "0x0000000000000000000000000000000000000000",
            "gas": 200000,
            "gasPrice": self.w3.eth.gas_price,
            "nonce": 0,
        })

        return {
            "to": self.contract_address,
            "data": tx_data["data"],
            "value": "0x0",
            "gas": hex(tx_data["gas"]),
            "gasPrice": hex(tx_data["gasPrice"]),
        }

    def prepare_update_digital_asset_calldata(
        self,
        token_id: int,
        requester_did: str,
        new_file_hash: str,
        new_offchain_uri: str
    ) -> dict:
        """Prepare unsigned updateDigitalAsset transaction for frontend signing."""
        tx_data = self.contract.functions.updateDigitalAsset(
            token_id,
            requester_did,
            new_file_hash,
            new_offchain_uri
        ).build_transaction({
            "from": "0x0000000000000000000000000000000000000000",
            "gas": 250000,
            "gasPrice": self.w3.eth.gas_price,
            "nonce": 0,
        })
        return {
            "to": self.contract_address,
            "data": tx_data["data"],
            "value": "0x0",
            "gas": hex(tx_data["gas"]),
            "gasPrice": hex(tx_data["gasPrice"]),
        }

    def prepare_revoke_calldata(self, token_id: int) -> dict:
        """Prepare unsigned revoke transaction."""
        tx_data = self.contract.functions.revoke(token_id).build_transaction({
            "from": "0x0000000000000000000000000000000000000000",
            "gas": 150000,
            "gasPrice": self.w3.eth.gas_price,
            "nonce": 0,
        })

        return {
            "to": self.contract_address,
            "data": tx_data["data"],
            "value": "0x0",
            "gas": hex(tx_data["gas"]),
            "gasPrice": hex(tx_data["gasPrice"]),
        }


# Singleton instance

    def get_digital_asset(self, token_id: int) -> Optional[dict]:
        """Fetch on-chain digital asset metadata (hash, URI)."""
        try:
            # Returns (serialNumber, ownerDID, fileHash, offchainURI, isDigital)
            res = self.contract.functions.getDigitalAsset(token_id).call()
            owner_address = self.contract.functions.ownerOf(token_id).call()
            return {
                "token_id": token_id,
                "serial_number": res[0],
                "owner_did": res[1],
                "file_hash": res[2],
                "offchain_uri": res[3],
                "is_digital": res[4],
                "owner_address": owner_address,
            }
        except Exception:
            return None

    def check_asset_access(self, token_id: int, requester_did: str, caller_address: str) -> dict:
        """Check if a specific DID is authorized to access a token."""
        try:
            authorized, level = self.contract.functions.checkAssetAccess(
                token_id, requester_did, Web3.to_checksum_address(caller_address)
            ).call()
            return {"authorized": authorized, "level": level}
        except Exception:
            return {"authorized": False, "level": 0}

    def prepare_mint_digital_calldata(
        self,
        to_address: str,
        token_id: int,
        serial_number: str,
        owner_did: str,
        file_hash: str,
        offchain_uri: str,
    ) -> dict:
        """Prepare unsigned transaction data for minting a digital asset."""
        tx_data = self.contract.functions.mintDigitalAsset(
            Web3.to_checksum_address(to_address),
            token_id,
            serial_number,
            owner_did,
            file_hash,
            offchain_uri
        ).build_transaction({
            "from": "0x0000000000000000000000000000000000000000",
            "gas": 400000,
            "gasPrice": self.w3.eth.gas_price,
            "nonce": 0,
        })
        return {
            "to": self.contract_address,
            "data": tx_data["data"],
            "value": "0x0",
            "gas": hex(tx_data["gas"]),
            "gasPrice": hex(tx_data["gasPrice"]),
        }

    def prepare_record_access_attempt_calldata(
        self,
        token_id: int,
        actor_did: str,
        granted: bool,
        reason: str
    ) -> dict:
        tx_data = self.contract.functions.recordAccessAttempt(
            token_id,
            actor_did,
            granted,
            reason
        ).build_transaction({
            "from": "0x0000000000000000000000000000000000000000",
            "gas": 150000,
            "gasPrice": self.w3.eth.gas_price,
            "nonce": 0,
        })
        return {
            "to": self.contract_address,
            "data": tx_data["data"],
            "value": "0x0"
        }

contract_service = ContractService()
