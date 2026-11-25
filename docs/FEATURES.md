# Feature and verification matrix

Version 3.0 adds the following independently usable capabilities.

| Capability | Verification |
|---|---|
| MFA fatigue alert classification | analysis tests |
| Suspicious PowerShell alert classification | analysis tests |
| Persistence alert classification | analysis tests |
| Ransomware alert classification | analysis tests |
| Cloud policy alert classification | analysis tests |
| Suspicious DNS alert classification | analysis tests |
| Lateral movement alert classification | analysis tests |
| Web attack alert classification | analysis tests |
| Password-spraying correlation | analysis tests |
| Distributed authentication failure correlation | analysis tests |
| Duplicate-event-resistant authentication rules | analysis tests |
| UTC normalisation | analysis tests |
| Evidence quality assessment | analysis tests |
| Per-event SHA-256 digests | analysis tests |
| Evidence fingerprint verification | analysis / HTTP tests |
| Observed indicator extraction | analysis tests |
| Rule coverage and technique rollup | analysis tests |
| Event type statistics and time bounds | analysis tests |
| Analyst-defined case titles | workflow / HTTP tests |
| Case lifecycle | workflow / HTTP tests |
| Supervisor closure/reopening | workflow / HTTP tests |
| Priority and response targets | workflow tests |
| Case tags | workflow tests |
| Response checklist | workflow tests |
| Workflow change history | workflow tests |
| Overdue cases | workflow tests |
| Scoped queue search and filtering | workflow / HTTP tests |
| Scoped queue metrics | workflow / HTTP tests |
| Executive summary export | workflow / HTTP tests |
| Evidence timeline filtering | Chromium workflow / UI source checks |
| Three new synthetic scenarios | analysis tests |

The automated suite does not establish real-world detection performance, live-model accuracy or security certification. The CI browser job exercises the core end-to-end flow in Chromium. Other browsers, assistive technology, production infrastructure and the real Ollama model still require independent acceptance testing.
