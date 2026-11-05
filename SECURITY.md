# Security policy

## Supported versions

LexCorp is a development project. Security investigation currently focuses on the
latest `main` branch; Beta builds are evaluation releases and are not certified
for production or sensitive real-world data. Older snapshots do not have a
promised security maintenance window.

## Reporting a vulnerability

Email **azeemulla555@gmail.com**, the maintainer contact listed in the project's
Code of Conduct. Use a subject such as “LexCorp security report”. Do not disclose
vulnerabilities through public issues or pull requests.

Include the affected commit or version, component, prerequisites, reproducible
steps, expected and observed behavior, and likely impact. Use synthetic examples;
exclude credentials, wallet private keys, recovery phrases, personal information,
and confidential documents. Ask the maintainer for an appropriate secure transfer
method before sending sensitive evidence.

The maintainer will assess the report and coordinate any fix and disclosure.
Response times and release dates are not guaranteed. Please allow coordination
before public disclosure and avoid testing against systems without authorization.

For an exposed credential, revoke or rotate it immediately; deleting it from the
latest commit alone does not remove it from Git history or downloaded copies.
