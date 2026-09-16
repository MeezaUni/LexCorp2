# Architecture Overview

## Problem Statement 26125 Implementation
**Blockchain-Based Secure Platform for Identity, Access Control, and Digital Asset Management**

This document maps each requirement from the problem statement to its implementation in the codebase.

## Core Requirements → Implementation

| Requirement | Implementation | Location |
|-------------|----------------|----------|
| Decentralized Identity (DID) | `did:ethr` identifiers using ERC-1056 lineage | Phase 3 |
| NFT Asset Tokenization | ERC-721 tokens via OpenZeppelin | `/contracts/AssetNFT.sol` |
| Role-Based Access Control | Smart contract-enforced via AccessControl | `/contracts/AssetNFT.sol` |
| Immutable Audit Trail | Event indexer writes from on-chain events | `/backend/app/indexer/` |
| Verifiable Credentials | W3C VC 2.0 JWT-VC for KYC proof | `/backend/app/services/did.py` |
| Smart Contract Governance | All privileged ops (mint/transfer/revoke) on-chain | `/contracts/` |
| No Backend Key Custody | Client-side signing via MetaMask for all privileged txs | `/frontend/src/services/web3.js` |

## Standards Compliance

- **W3C DID v1.1**: `did:ethr:<chainId>:<address>` method
- **W3C VC 2.0**: JWT-VC issuance for identity verification
- **ERC-721**: Asset tokenization standard
- **OpenZeppelin Contracts 5.x**: AccessControl, ERC721, ReentrancyGuard
- **OWASP SCSVS**: Checks-effects-interactions, reentrancy guards, custom errors
- **NIST SP 800-63-4**: Nonce expiry, short-lived sessions

## Workflow Implementation

1. **Registration** → `/backend/app/api/auth.py` — wallet connection
2. **DID Issuance** → `/backend/app/services/did.py` — `did:ethr` creation
3. **Identity Verification** → `/backend/app/services/vc.py` — JWT-VC issuance
4. **NFT Minting** → `/contracts/AssetNFT.sol` — manager role mints, client signs
5. **Role Assignment** → `/contracts/AssetNFT.sol` — `grantRole()` by admin
6. **Access Request** → `/backend/app/api/access.py` — signed request
7. **Authorization** → Smart contract validation of roles
8. **Asset Access** → `/frontend/src/pages/Assets.jsx` — view/transfer UI
9. **Audit Logging** → `/backend/app/indexer/event_indexer.py` — event → DB
10. **Risk & Anomaly Detection** → `/backend/app/ml/risk_model.py` — K-Means + RandomForest

## Security Architecture

- **No private keys in backend**: All privileged transactions signed client-side
- **On-chain RBAC**: Roles enforced by smart contracts, not UI-only
- **Event-sourced audit**: Truth originates from chain events, not API calls
- **PII off-chain**: Only hashes/CIDs/VC references on-chain
- **Short-lived sessions**: JWT expires in 30 minutes per NIST guidance

## Prototype-vs-Production Gaps

Documented honestly per the task requirements:
- No formal smart contract audit
- Local chain (Hardhat), not mainnet/testnet
- No HSM for any key material
- AI model trains on synthetic data generated in-repo
- Single indexer instance (no HA)
