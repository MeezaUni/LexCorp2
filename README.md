# LexCorp — Asset Assurance & Custody

LexCorp manages controlled digital documents and registered physical equipment for an
organisation. Every sensitive action is tied to a verified wallet identity, approved by a
responsible officer, recorded in an append-only audit trail and anchored to a permissioned
Hyperledger Besu ledger.

> Status: development build. Automated tests and browser verification pass. The human
> manual checklist (`backend/Final_Manual_Test_Checklist.md`) has **not** been executed yet.
> See `docs/Requirements_Verification_Matrix.md` for the evidence-backed status of every
> requirement. Nothing here is certified or claimed as production-ready.

## What it does

- **Identity.** An administrator registers an identity (wallet address, role, department)
  and hands over a single-use provisioning PIN that expires after 3 hours. The person
  provisions the wallet on their device, then must enrol a login authenticator (TOTP 1) and
  a login passkey (Passkey 1) before anything else is reachable.
- **Purpose-bound factors.** Sensitive actions need a separate factor for that purpose, and
  the proof is valid only for the one action it was issued for:
  - Factor 2: view and submit.
  - Factor 3: approve, mint, modify, download and administer.
- **Roles.** User, Manager, Auditor and Administrator, scoped by department. The backend
  enforces this; the UI only hides what a role cannot use.
- **Digital documents.**
  - The server computes each file's SHA-256.
  - Every view produces a new copy watermarked with the viewer's identity.
  - Delegated access can carry view limits and expiry.
  - A controlled download needs the owner's consent, a Manager or Administrator approval
    and the requester's Factor 3, and can be fetched once.
  - Modification copies lead to revisions that must be approved.
  - Every action gets an ID (`CRT-`, `VW-`, `DL-`, `MOD-`, `ACR-`) and a verification QR.
- **Physical assets.**
  - Each asset has a serial number plus a MAC address or a unique device address, all
    unique across the registry.
  - Once approved it is minted as an NFT, and its card shows only five permitted fields.
  - The public QR page shows only minimal data; employees see what their role allows.
- **Security alerts.**
  - Deterministic rules and an AI model (local Isolation Forest, calibrated) raise alerts.
  - People decide: an Auditor, then the department Manager, then an Administrator.
  - Only an Administrator can revoke an identity, with Factor 3; revocation ends the
    person's sessions and removes their ledger roles.
- **Ledger.**
  - The AssetNFT v3 contract enforces MINTER, ANCHOR, MANAGER, AUDITOR and REGISTRAR roles
    on-chain.
  - The backend holds only the registrar key, which cannot mint.
  - Ledger transactions are signed by the approving officer's wallet and recorded only
    after the receipt and the resulting contract state have been verified.

## Layout

| Path | Contents |
|---|---|
| `backend/` | FastAPI app, Alembic migrations, scripts, pytest suite |
| `frontend/` | React/Vite UI with the LexCorp design system in `src/styles/app.css` |
| `contracts/` | AssetNFT v3 (Solidity), Hardhat tests, deploy, verify and registrar-rotation scripts |
| `network/besu/` | Generated 3-validator QBFT network (chain 13371). Keys and data are git-ignored |
| `scripts/` | `init_secrets.py`, `generate_besu_network.py`, `e2e_fixture_server.py` (development only) |
| `e2e/playwright/` | Browser verification harness |
| `docs/` | Requirements matrix, rebuild record, Playwright report, evidence |

## First-time setup (development)

You need **Docker Desktop** (running), **Python 3.11 or newer**, **Node 20 or newer** and git.
Then, in the project folder:

```bash
npm run setup
```

That one command takes a fresh clone to a running app:
1. checks the prerequisites;
2. installs all dependencies;
3. creates this machine's secrets (git-ignored; values never printed);
4. starts PostgreSQL;
5. generates this machine's own 3-validator blockchain and waits until it produces blocks;
6. deploys and verifies the smart contract;
7. prepares the database;
8. creates the first administrator, then starts the backend (127.0.0.1:8000) and the frontend
   (http://localhost:5173).

It is safe to run again: what already exists is kept. After the first time, `npm start` is
enough. Useful options:

| Command | What it does |
|---|---|
| `npm run setup -- --no-start` | Prepare everything, but don't start the app |
| `npm run setup -- --skip-install` | Skip the npm and pip installs |
| `npm run setup -- --reset-db` | Recreate a local database left over from an older LexCorp copy (deletes that local database) |
| `npm run stop` | Stop the app and the ledger |

The first administrator's recovery phrase is in `secrets/bootstrap_admin_wallet.json` and the
single-use PIN is in `secrets/bootstrap_admin_pin.txt`. If the PIN expires before use, run
`python backend/scripts/bootstrap_admin.py --reissue-pin`. Then follow
`backend/Final_Manual_Test_Checklist.md`.

**Files that change on your machine.** The setup writes this machine's
`contracts/deployments/besu.json` (the address of the contract it deployed). Don't commit it.
Its network keys, genesis and `network/besu/.env` are already git-ignored.

### If setup stops

The setup explains what went wrong and what to run. The usual cases:
- **The database rejects the password.** An older LexCorp copy created the local database with
  another password.
  - Run `npm run setup -- --reset-db` if you don't need that old local database.
  - To keep a copy first, run `docker exec lexcorp_postgres pg_dumpall -U lexcorp > old_db_backup.sql`.
- **A container named `lexcorp_postgres` belongs to another folder.** Stop and rename it:
  `docker stop lexcorp_postgres` then `docker rename lexcorp_postgres lexcorp_postgres_old`.
- **Docker says a network pool overlaps.** Run `docker network prune -f`, which removes only
  unused networks, then run the setup again.
- **The ledger doesn't produce blocks.** Check `docker logs besu_node1`. For a clean new ledger,
  run `npm run besu:down`, then `python scripts/generate_besu_network.py --force`, then
  `npm run setup` again. The old chain data is moved to `network/besu/data_archived_<time>/`,
  not deleted.

## AI risk model (local)

Security alerts combine deterministic rules with a local risk model: no paid APIs and no
internet. To train and evaluate it (a few minutes), run:

```bash
cd backend
python ml/simulate.py
python ml/train.py
python ml/evaluate.py
```

Then restart the app. See `backend/ml/README.md` for how it works, the simulated scenarios,
learning from Auditor feedback, and its honest limits.

## Tests

```bash
cd backend && python -m pytest -q                                          # API, security, workflow, DB (isolated *_test database)
cd backend && LEXCORP_LIVE_BESU=1 python -m pytest -q tests/test_besu_live.py  # real transactions on the running Besu
npm --prefix contracts test                                                # contract authorization tests
npm --prefix frontend run lint && npm --prefix frontend run build
```

## Production notes

- Set `ENVIRONMENT=production`. It is also the default when unset.
- In production the app refuses to start if any secret is missing, weak or shared between
  purposes, if `DEBUG` is on, if an origin is not HTTPS, or if the database password is a
  development value.
- Supply secrets from a secret manager. See `backend/.env.example` for the variables.
- Put the app behind a TLS reverse proxy listed in `TRUSTED_PROXIES`, and set
  `PUBLIC_BASE_URL`, `CORS_ORIGINS`, `WEBAUTHN_ORIGINS` and `RP_ID` to the public HTTPS origin.
- Rotate keys:
  - data encryption: `init_secrets.py --rotate DATA_ENCRYPTION_KEYS`, then
    `backend/scripts/rotate_encryption_keys.py`;
  - registrar: `init_secrets.py --rotate CHAIN_OPERATOR_PRIVATE_KEY`, then
    `contracts/scripts/rotate_registrar.js`.
