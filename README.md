# Cybersecurity

Practical, defensive security auditing, log analysis, and monitoring scripts built in Python.

> **Authorized use only.** Run these tools solely against systems you own or
> have explicit written permission to test. See [SCOPE.md](SCOPE.md) and
> [SECURITY.md](SECURITY.md).

## Structure

- `scanners/web/web_audit.py` — Audits HTTP security headers, TLS/certificate details, cookie flags, and server banners.
- `scanners/net/net_audit.py` — Multi-threaded TCP port/banner checker with baseline drift tracking.
- `monitors/logs/log_guard.py` — Analyzes logs for repeated auth failures, high-volume IPs, and suspicious path probes.
- `monitors/integrity/file_guard.py` — SHA-256 directory baselines with added/modified/removed detection.
- `monitors/android/android_guard.py` — Workspace permission and secret-pattern checks.
- `tools/report_summary.py` — Summarizes the latest report from every module.
- `tools/incident_plan.py` — Generates defensive incident and hardening checklists.
- `common.py` — Shared CLI and JSON report helpers used by all modules.
- `skills/` — Short objective-to-tool playbooks; `index.json` is their machine-readable catalog.
- `reports/` — Generated JSON reports (gitignored).
- `tests/smoke_test.py` — Offline smoke tests for the CLI and report workflow.

## Usage

Use the `secguard` launcher (or `python3 cyber_toolkit.py` directly):

```bash
secguard --help                       # list modules
secguard web example.com
secguard net 127.0.0.1 22 443
secguard log /var/log/auth.log 10
secguard integrity /etc
secguard android ./app
secguard report
secguard plan ssh-bruteforce
secguard plan --list
```

Every module also supports `--help`, `-o/--output-dir DIR`, and `--json` for
machine-readable stdout. Reports default to `<repo>/reports/` and include a
consistent metadata envelope: `tool`, `timestamp_utc`, `status`, and `summary`.

Modules can be run directly as well, for example:

```bash
python3 tools/incident_plan.py android-risk --json
```

## Smoke test

Run the lightweight, offline smoke test suite (artifacts are isolated in `/tmp`):

```bash
python3 tests/smoke_test.py
```

It verifies `secguard` help output, module help, incident plan generation, log
triage, file integrity baseline/modification detection, Android workspace
scanning, report summarization, and CLI exit-code propagation.

## Documentation

- [CHANGELOG.md](CHANGELOG.md) — toolkit modules, CLI, skills structure, and recent upgrades
- [SCOPE.md](SCOPE.md) — authorization and scope policy
- [SECURITY.md](SECURITY.md) — credential and report-handling guidelines
- [index.json](index.json) — machine-readable skills catalog
