# Contributing to LexCorp

Thank you for helping improve LexCorp's asset assurance and custody workflows.
Read the [README](README.md) and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

Search existing issues before opening a bug report or feature request. For larger
changes, discuss the proposed behavior and scope in an issue first. Report
vulnerabilities privately using [SECURITY.md](SECURITY.md).

## Development setup

Use Python 3.11+, Node.js 20+, Git, and a running Docker installation. From the
repository root, follow the README's `npm run setup` instructions. For dependency
installation with existing lockfiles, use `npm ci`, `npm ci --prefix frontend`,
and `npm ci --prefix contracts`. Install Python development dependencies with
`python -m pip install -r backend/requirements-dev.txt` in a virtual environment.

Use generated local development secrets. Never commit `.env` files, wallet keys,
recovery phrases, provisioning PINs, database dumps, or document vault contents.
Keep machine-specific contract deployment records out of pull requests.

## Validation

Run the checks relevant to your change:

```bash
npm --prefix frontend run lint
npm --prefix frontend run build
npm --prefix contracts test
cd backend
python -m pytest -q
```

Backend tests require local PostgreSQL and compiled contract artifacts. They use
an isolated database whose name ends in `_test`; never point tests at production.
For ledger changes, also run the README's live Besu test against your local chain.
Record skipped or unavailable checks explicitly. UI and sensitive workflow changes
should include relevant manual checks from `backend/Final_Manual_Test_Checklist.md`.

## Pull requests

Use a focused branch and describe the problem, resulting behavior, linked issues,
and validation results. Include screenshots for visible UI changes. Add regression
coverage for behavior changes and update relevant documentation. Preserve role,
department, MFA, consent, audit, and ledger authorization boundaries. Do not weaken
security controls merely to make tests pass. Request review before merging.

## Rights and permissions

This project is all rights reserved; it is not released under an open-source
license. Read [LICENSE](LICENSE) and request written permission before copying,
modifying, redistributing, or using the project beyond rights provided by GitHub's
terms. By submitting a contribution, you confirm you have the right to submit it
and grant the maintainers permission to incorporate and distribute it as part of
LexCorp under the repository's stated terms. Third-party code must retain its
applicable license notices.
