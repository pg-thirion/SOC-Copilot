# SOC Copilot

A local-first security operations investigation workspace. Designed as a defensive cybersecurity portfolio project with deterministic triage and optional local AI commentary.

## Quick start

Requires Node.js 20 or newer. No npm packages, credentials or cloud services are required.

```bash
git clone https://github.com/pg-thirion/SOC-Copilot.git
cd SOC-Copilot
npm test
npm start
```

Open http://localhost:3000. Select a synthetic scenario, investigate it, review evidence and record an analyst disposition. Export the investigation as JSON.

### Optional local AI

Install Ollama separately, start its local service and pull a suitable installed chat model (for example, qwen2.5:3b if available). Set the model name to match your installation.

PowerShell:

```powershell
$env:OLLAMA_MODEL="qwen2.5:3b"
npm start
```

Linux/macOS:

```bash
OLLAMA_MODEL=qwen2.5:3b npm start
```

Enable the AI checkbox before investigating. Only fixed rule summaries, possible technique mappings and evidence IDs are sent to the loopback Ollama endpoint. No raw log content, usernames, hostnames or IP addresses are sent. AI output is separately labelled, advisory and never used to change deterministic severity or execute actions. If the model fails, the rules remain available.

## Capabilities

- JSON alert intake, four synthetic scenarios and 500-event limit.
- Ten-minute correlation of failed and successful authentication events by user and source IP.
- Classification of reported malware, phishing, privilege changes, possible data transfer and defence tampering.
- Evidence IDs, ordered event timeline, indicative MITRE ATT&CK technique references and conditional remediation guidance.
- Human review, disposition, notes and explicit JSON export.
- Responsive browser UI without external assets.

## Event schema

Each event is an object with required string type and optional string timestamp, user, host, ip, outcome and detail. Use ISO 8601 timestamps with offsets. For authentication correlation, provide timestamp, user, ip and outcome (failure or success).

```json
[
  {
    "timestamp": "2026-11-25T08:00:00Z",
    "type": "authentication",
    "user": "analyst@example.test",
    "ip": "192.0.2.44",
    "outcome": "failure"
  }
]
```

Supported types: authentication, malware_detection, privilege_change, phishing_report, data_transfer_alert, defence_tamper. Other types are retained as evidence but do not trigger a rule.

## Security model and limitations

The server binds only to IPv4 loopback, validates Host and Origin, limits JSON input, uses a restrictive CSP, renders untrusted data as text, and does not store investigations on disk. Exports deliberately contain raw evidence and must be protected. There is no live SIEM, authentication, multi-user persistence, threat intelligence integration or automated remediation. Do not expose this prototype directly to the internet.

A rule match is not proof of compromise. ATT&CK mappings are hypotheses. No match means unclassified, not safe. Model output may be incorrect and needs review. This is a demonstrator, not a production incident response platform.

## Architecture

Browser dashboard → local HTTP API → deterministic analysis engine → optional local Ollama commentary. The analyst retains control of classification disposition and response decisions.

Run `npm test` to execute the rule regression suite. The project has no external Node dependencies.
