# LexCorp2 infrastructure rebuild record (2026-09-26)

This file records a controlled rebuild of the development infrastructure. It covers
why each component was replaced, what was backed up, what was preserved or discarded,
and how the result was verified. No secret value appears in this file.

## 1. Why a rebuild was required

The findings below come from inspection on 2026-09-26, not from earlier reports.

| Finding | Evidence | Impact |
|---|---|---|
| Contract admin was Hardhat account #0 (`0xf39F…2266`), whose private key is public | `hasRole(DEFAULT_ADMIN_ROLE)` and `hasRole(MANAGER_ROLE)` were true for `0xf39F…2266`. These were the only 2 `RoleGranted` events on the old contract `0x0165…Eb8F`. | Anyone could administer the contract and mint. |
| `mintDigitalAsset` had no role check | Contract source | Anyone with gas could mint digital asset NFTs. |
| `updateDigitalAsset` trusted a DID supplied by the caller | Contract source | Anyone could pass the owner's DID and rewrite a document hash. |
| `recordAccessAttempt` was public, and holders could make raw ERC-721 transfers or approvals | Contract source | Audit events could be forged and custody could be bypassed. |
| The genesis pre-funded Hardhat #0 | `genesis.json` alloc | A well-known key held funds on the chain. |
| QBFT validator node private keys were committed to git | `network/besu/networkFiles/keys/*/key` tracked | Consensus keys were public. The chain could not be trusted. |
| Besu RPC exposed ADMIN, DEBUG, TXPOOL and PERM APIs with CORS `*` and host allow-list `*`, published on 0.0.0.0 | `docker-compose-active.yml` | Node administration was reachable from the LAN and from any browser origin. |
| Postgres used the password `lexcorp_dev`, published on 0.0.0.0:5432 | `docker-compose.yml`; the container was created from another project folder (`LexCorp-SIH-V2`) | A known credential was exposed on the LAN. |
| `JWT_SECRET` used its development default, the data encryption key was derived from it, and `DEBUG=True` | `config.py`; no `.env` existed | Session forgery and TOTP decryption were possible with a published string. |

A new contract is required because deployed bytecode cannot be changed. The validator
keys were public, so the chain itself had to be regenerated. Every on-chain reference
in the database (token IDs, transaction hashes, audit rows) pointed at the retired
chain, and every database row was test data created on 2026-09-25. The database was
therefore rebuilt instead of migrated.

## 2. State before the rebuild (recorded, then backed up)

- **Chain:** 13371, head block ~18 004. Old contract `0x0165878A594ca255338adfa4d48449f69242Eb8F`, runtime code 14 352 bytes, keccak prefix `79bba6da8a82e519`.
- **Old contract role holders:** only `0xf39F…2266` (ADMIN, MANAGER).
- **Database `lexcorp_sih`:** 22 users (all created 2026-09-25 by automated tests or earlier sessions), 60 assets, 79 audit events, 17 alerts and 40 document actions. Schema was at migration 0010.
- **Secret columns:** 1 user had legacy plaintext TOTP secrets (all three factors). No user had a new-style wallet wrap secret.

## 3. Backups (git-ignored, under `db_backups/`)

| File | Content |
|---|---|
| `pre_rebuild_20260926/lexcorp_sih.dump` | Full `pg_dump -Fc` of the old database. 17 table-data entries were verified with `pg_restore -l`. |
| `pre_rebuild_20260926/offchain_storage.tgz` | The document vault (31 entries). |
| `pre_rebuild_20260926/besu_chain_data.tgz` | Old chain data, old genesis, old validator keys and the old compose file (Besu was stopped for a consistent copy). |
| `pre_rebuild_20260926/old_deployment_localhost.json` | Old contract address and ABI. |
| `pre_rebuild_20260926/chain_state_before.txt`, `db_counts_before.txt` | The evidence in section 2. |
| `pre_container_move_20260926/lexcorp_sih_fresh.dump` | The rebuilt database before it moved to the project-owned Postgres container. |

Old chain data directories were moved aside (to `network/besu/data_retired_20260926` and
`data_corrupted_retired`), not deleted.

**Discarded on purpose:**
- Three older dumps (`pre_0003`, `pre_0009`, `pre_0010`). They contained plaintext provisioning PINs and are superseded by the full dump above.
- The old Postgres container was stopped and renamed `lexcorp_postgres_legacy_sihv2`, not removed. Its volume `lexcorp-sih-v2_postgres_data` is untouched.

**Sensitive content in backups:** the pre-rebuild dump still contains one legacy
plaintext TOTP secret and the uploaded test documents, all belonging to retired test
identities. Delete `db_backups/pre_rebuild_20260926/` once manual validation is
complete.

## 4. What was rebuilt

| Component | New state |
|---|---|
| Secrets | `python scripts/init_secrets.py` writes `secrets/chain.env` (governance key), `backend/.env` (JWT, VC signing, data encryption and chain-operator keys; DB URL) and `.env` (Postgres password). All three are git-ignored and no value is ever printed. |
| Besu | `python scripts/generate_besu_network.py`: fresh validators `0x5020a9f5…3226`, `0xb783ca76…9dfa`, `0xc0df6e5d…7528`. The genesis alloc is empty and `zeroBaseFee` is true. RPC is on 127.0.0.1 only with ETH/NET/WEB3/QBFT APIs. There are no CORS origins, the host allow-list is localhost, and the image is pinned to `hyperledger/besu:26.8.1`. |
| Contract | AssetNFT v3 at `0x113904450c2E72A1E1602F733D9140eAB9Db35aD` (block 13). Admin is `0x7679…94E3` (governance key) and registrar is `0x4631…830F` (backend chain operator). Runtime code hash is `0x78faa541…b8ef`. |
| Postgres | A project-owned container `lexcorp_postgres` with volume `lexcorp2_postgres_data`, published on 127.0.0.1:5432. The generated password is required; `lexcorp_dev` is rejected. |
| Database | `alembic upgrade head` (0012), then `python backend/scripts/bootstrap_admin.py`: 1 bootstrap administrator and 5 departments. |
| On-chain roles | These follow the identity registry through the registrar (see `backend/app/services/chain.py`). The bootstrap admin wallet holds MINTER, ANCHOR and MANAGER. An administrator wallet from an intermediate rebuild was later found by the orphan sweep and its roles were revoked on-chain. |

## 5. Verification evidence

- `npx hardhat run scripts/verify_deployment.js --network besu`: 14/14 PASS. Checks cover chain ID, code present, bytecode matching both the record and the compiled source, admin and registrar roles, admin and registrar holding no operational role, no public dev account holding any role, and a successful deployment receipt.
- `LEXCORP_LIVE_BESU=1 pytest tests/test_besu_live.py`: 3 passed (real transactions):
  - an unauthorized wallet's `mintDigitalAsset`, `mint` and `updateDigitalAsset` transactions to the deployed contract are mined with status 0;
  - on a throwaway instance, an authorized minter mints (status 1, state verified); the holder cannot transfer or anchor; after revocation the same minter is rejected.
- The Besu RPC probe returned:
  - `admin_peers`, `debug_*`, `txpool_*`, `perm_*` → "Method not enabled";
  - a foreign `Origin` → `403 CORS Rejected`;
  - a foreign `Host` → 403.
- Postgres: a connection with the old `lexcorp_dev` password fails with `InvalidPasswordError`, and the app connects with the generated credentials.
- Backend startup log: `Chain verified: chain 13371, AssetNFT v3 at 0x1139…35aD`. `/health` reports `chain_verified: true`.

## 6. Side effects the owner should know about

- The old Postgres container was shared with other LexCorp copies on this machine (it was created from `LexCorp-SIH-V2`). Those copies used `lexcorp:lexcorp_dev`. That container is now stopped and renamed, and the role password inside it was rotated. Those other copies will no longer connect until they are reconfigured.
- Old commits in git history still contain the retired validator keys and the public Hardhat keys in configuration files. Nothing was pushed, and history was not rewritten. Rewriting published history needs the owner's decision.
