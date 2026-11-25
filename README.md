# SOC Copilot

Security operations case management and evidence-linked investigation with optional local AI. A single-organisation, single-instance application with analyst and supervisor roles.

## Start locally

Requires Node.js 24 LTS. No third-party npm dependencies.

```bash
git clone https://github.com/pg-thirion/SOC-Copilot.git
cd SOC-Copilot
npm test
npm run provision -- supervisor supervisor
npm run provision -- analyst analyst
npm run key
```

Store the generated 64-character key securely and reuse it on every restart. Losing it makes the encrypted cases unrecoverable. Never commit the key or user configuration.

PowerShell:
```powershell
$env:SOC_DATA_KEY = "<your saved key>"
npm start
```

Linux/macOS:
```bash
export SOC_DATA_KEY='<your saved key>'
npm start
```

Open http://localhost:3000 and sign in. Select a demo, investigate, review the evidence and save your disposition. Reopen cases from the case queue. Analysts access their own cases. Supervisors access all cases and the audit trail. User provisioning is an operator-only CLI, not a web signup. Restart after updating the user file. Remove a user from the file to revoke access.

## Features

- Six defensive rule families including time-window authentication correlation.
- Synthetic scenarios, bounded JSON import, evidence timeline, indicative ATT&CK mappings.
- Encrypted case persistence in SQLite, revision-checked review updates and paginated case queue.
- Passwords hashed with scrypt, opaque hashed sessions, eight-hour expiry, bounded login attempts, role and ownership checks.
- HMAC-chained audit trail for login, logout, case creation, views and reviews. An operator with the key can rewrite the chain, and truncation of a valid suffix is not detected without external checkpoints.
- Optional local Ollama commentary. Fixed rule summaries and evidence IDs only, never raw event fields. The model cannot execute actions or override rule severity.
- JSON export of the saved review and original evidence. Exported files require separate protection.

## Local AI

Install Ollama separately, run its loopback service, and set OLLAMA_MODEL to an installed chat model before starting the app. No external AI endpoint is accepted. Model output may be wrong and must be reviewed.

## Deployment and assurance

See [deployment runbook](docs/OPERATIONS.md) and [security model](docs/SECURITY.md). This is a hardened reference implementation, not certified production-ready. Independent security review, backup/restore rehearsal, load testing, monitoring and integration acceptance are required before processing real incident data.

## Event schema

JSON array of 1 to 500 objects. Each object requires a string `type`; optional strings are `timestamp`, `user`, `host`, `ip`, `outcome`, `detail`. Use ISO 8601 timestamps with offsets. Supported types: authentication, malware_detection, privilege_change, phishing_report, data_transfer_alert, defence_tamper. Other types remain unclassified. Authentication correlation requires timestamp, user, ip and failure/success outcome.

Rule matches are hypotheses, not confirmed incidents. No match does not imply safety. Remediation recommendations require analyst approval.

## Tests

`npm test` runs rule, security, persistence and HTTP integration tests. GitHub Actions runs the same suite on Node 24.


## Version 3.0: expanded investigation and case management

Additional alert types: MFA fatigue, suspicious PowerShell, persistence, ransomware, cloud policy changes, suspicious DNS, lateral movement and web attack alerts. These classify reported telemetry, not independently validated malicious activity. Password-spraying and distributed-authentication correlations require five distinct identities/sources within ten minutes. Identical normalised events do not inflate authentication correlation counts.

Evidence intelligence includes SHA-256 per-event and case fingerprints (normalised evidence only), quality checks, duplicate counts, observed users/hosts/IPs/hash-like strings/domains, time range, event type counts, rule coverage and technique rollup. Observed indicators are not automatically malicious. Raw original byte-stream preservation is outside scope.

Workflow adds case title, priority (P1–P4), lifecycle, tags, response checklist, due targets, overdue indicators and bounded workflow history. Closing or reopening a closed case requires supervisor approval; closing also requires a saved disposition. Due times are policy defaults of 4/24/72/168 hours from case creation, not regulatory or contractual SLAs. Queue search, filters and metrics respect ownership; global metrics and filtered search are limited to the latest 5,000 accessible cases and flag truncation. Timeline filtering and executive JSON summaries are available. Executive summaries exclude raw event data and notes but may include sensitive analyst titles. Existing cases retain their evidence and receive default workflow metadata when opened; fingerprints are unavailable for legacy reports.

See docs/FEATURES.md for the feature/test matrix.
