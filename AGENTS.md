# Repository guidance

## Secret gate before publication

Before every push and PR creation/update, commit the complete candidate and run
`python3 scripts/secret_gate.py` (native Windows: `python`). Require exit 0;
missing tooling/authentication, scan errors and skipped scans block publication.
Then run the existing repository gates. Repeat after changing outgoing commits.
See [secret scanning](SECRET-SCANNING.md) for base selection, new branches,
pre-push input and prerequisites. Preserve GitGuardian App, CI and Gitleaks checks.

Local tooling: `make pre-push`.
