# Operations runbook

## Deployment boundary

Single organisation, one Node process and a local SQLite database on a supported Linux host. Run as a dedicated unprivileged OS user. Do not expose port 3000; the process binds to IPv4 loopback. Use an HTTPS reverse proxy (for example Caddy) with a certificate, request size and rate limits, and network-level access restrictions. Use organisation-approved SSO/MFA at the access gateway for real deployments; the app does not implement MFA.

Set SOC_ORIGIN to the exact public HTTPS origin, for example https://soc.example.test. Forward the original Host header unchanged; do not rewrite Origin. Do not trust arbitrary forwarded identity headers. Require TLS externally and restrict access to the host. The app sets secure cookies and HSTS when configured for HTTPS. HTTP is supported only for localhost development.

Configuration: PORT (default 3000), SOC_ORIGIN, SOC_USERS_FILE, SOC_DATA_KEY (required), SOC_DB_PATH, OLLAMA_MODEL (optional). Keep the data key in a managed secret store or protected service environment, separate from database backups. User file and data directory must be private. Use a durable local filesystem, not NFS. Do not use multiple app replicas. Pin and patch Node 24 and the OS.

## Example service

Install the application at /opt/soc-copilot, provision a service account soc, and place private data in /var/lib/soc-copilot. Configure /etc/soc-copilot.env (root-readable only) with SOC_DATA_KEY, SOC_USERS_FILE, SOC_DB_PATH and SOC_ORIGIN. Set ownership of users.json and the data directory to the service account.

Example systemd unit:

    [Unit]
    Description=SOC Copilot
    After=network.target
    [Service]
    User=soc
    Group=soc
    WorkingDirectory=/opt/soc-copilot
    EnvironmentFile=/etc/soc-copilot.env
    ExecStart=/usr/bin/node /opt/soc-copilot/server.mjs
    Restart=on-failure
    NoNewPrivileges=yes
    PrivateTmp=yes
    ProtectSystem=strict
    ProtectHome=yes
    ReadWritePaths=/var/lib/soc-copilot
    UMask=0077
    TimeoutStopSec=75
    [Install]
    WantedBy=multi-user.target

Example Caddy configuration (replace the host with your real DNS name):

    soc.example.test {
        request_body {
            max_size 256KB
        }
        reverse_proxy 127.0.0.1:3000
    }

Apply network/access gateway controls separately. Verify HTTPS, login, role separation and proxy body limits after deployment.

## Backups, retention and recovery

Stop the service gracefully before copying the SQLite database and any accompanying WAL/SHM files. Back up users.json separately. Encrypt backups, store the data key separately and test restoring into an isolated environment with the original key. Verify audit integrity and case access after restoring. Do not copy a live SQLite database without SQLite's backup mechanism. There is no automated key rotation or retention deletion in this release; implement an approved retention and key migration procedure before real data ingestion.

## Monitoring

Monitor /healthz via the configured Host header, HTTP error rates, disk space, process restarts, login failures and model availability. Export and independently protect audit head checkpoints periodically. The app intentionally does not log raw events or passwords to stdout. Configure log collection and alerting in the deployment environment. Establish incident response, patching and recovery ownership.

## Release gates

Run CI, perform browser and accessibility testing, test the real Ollama model with adversarial inputs, verify TLS and access gateway, rehearse backups/restores, conduct load and security testing, and document retention and legal requirements. No production environment or live telemetry has been validated by this repository alone.
