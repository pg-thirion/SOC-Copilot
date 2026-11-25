# Security model

Assets: raw alert telemetry, review notes, user password hashes, sessions, audit metadata and data key. Trust boundaries: browser to HTTP service through configured HTTPS proxy, service to local database, service to fixed local Ollama endpoint.

Controls: exact Host and Origin validation, origin required for state changes, same-site HttpOnly cookies, secure cookies on HTTPS, scrypt password hashing, hashed bearer sessions, session revocation on user config changes, rate-limited password checks, strict CSP and text-only DOM rendering, bounded JSON bodies and evidence fields. Analyst case ownership and supervisor-wide access are enforced on server routes. Case payloads use AES-256-GCM with case metadata as associated data; database metadata and audit actor/action/target remain visible to filesystem operators. Sessions expire after eight hours. The server refuses to start with a mismatched database key or invalid audit chain.

Audit entries are HMAC chained and mutation audit records commit in the same database transaction. This detects modification, insertion or internal deletion without the key but does not prevent tampering by a privileged operator, or detect removal of a valid suffix without an independently retained checkpoint. Case revisions prevent lost updates but are not an immutable revision archive.

Untrusted telemetry is never included in model prompts. Model output is text-only and advisory; no tools or execution are attached. Deterministic classifications are triage hypotheses. The AI model still may hallucinate or produce unsafe advice.

Residual risks: single instance, in-memory login limits reset on restart, global throttling can cause denial of service, no MFA or SSO built in, no SIEM integration, no automatic key rotation/retention, no distributed rate limiting, no tamper-proof audit sink, no full compliance assessment. Host administrators and compromised browser sessions can access sensitive data. Exports leave the encryption boundary. Require an access gateway, host hardening and independent validation for production.

Report security concerns privately to the repository maintainer. Do not include real telemetry or secrets in public issues.
