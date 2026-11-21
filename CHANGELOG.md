# Changelog

All notable changes to the Cybersecurity Toolkit are documented here. Dates use
UTC and entries follow the spirit of [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased] - 2026-11-21

### Added
- `common.py` — shared CLI and reporting helpers that give every module the same
  JSON metadata envelope, output-directory option, `--json` option, and error format.
- `monitors/logs/log_guard.py` — offline log anomaly triage for repeated
  authentication failures, high-volume source IPs, and suspicious path probes.
  This restores the tool already referenced by `README.md`, `index.json`, and the
  `log-anomaly-triage` skill.
- `tests/smoke_test.py` — lightweight, offline smoke tests for the launcher,
  dispatcher, all module help screens, and the full report workflow. Temporary
  artifacts are created under `/tmp` and removed automatically.
- This `CHANGELOG.md`, plus documentation links in `README.md`.

### Changed
- All seven modules (`web_audit`, `net_audit`, `log_guard`, `file_guard`,
  `android_guard`, `report_summary`, `incident_plan`) now write reports with a
  consistent metadata envelope: `tool`, `timestamp_utc`, `status`, `summary`.
- Every module uses `argparse` for clear `--help` output, consistent validation,
  and an optional `-o/--output-dir` and `--json` flag.
- Report filenames include microseconds, so rapid successive runs (for example
  baseline then drift check) no longer overwrite each other.
- `secguard` now resolves its own directory instead of hardcoding `/root/Cybersecurity`
  and uses `exec` so the module's exit code is propagated unchanged.
- `cyber_toolkit.py` launches modules with `sys.executable`, from the repository
  root, and returns the child's exit code for unknown modules, missing scripts,
  and module errors.
- `report_summary.py` now also summarizes `incident_plan_*.json` reports and
  includes each source report's metadata in its JSON output.
- `file_guard.py` records `is_baseline: true` with an empty change set on the
  first run and matches later baselines by target directory, avoiding drift
  comparisons against unrelated folders.
- `index.json` now catalogs the `incident-response-playbook` skill as well.

### Fixed
- `secguard log` failed because `log_guard.py` did not exist; it now works.
- Malformed or unreadable baseline/report JSON is skipped instead of crashing a run.
- Invalid ports, thresholds, and missing paths are rejected with clear errors
  and non-zero exit codes.

## Toolkit modules

| Module | Script | `secguard` command | JSON report prefix |
| --- | --- | --- | --- |
| Web audit | `scanners/web/web_audit.py` | `secguard web <url>` | `web_audit_` |
| Network drift | `scanners/net/net_audit.py` | `secguard net <host> [ports...]` | `net_audit_` |
| Log triage | `monitors/logs/log_guard.py` | `secguard log <logfile> [threshold]` | `log_guard_` |
| File integrity | `monitors/integrity/file_guard.py` | `secguard integrity <dir>` | `integrity_` |
| Workspace guard | `monitors/android/android_guard.py` | `secguard android [path]` | `android_guard_` |
| Report summary | `tools/report_summary.py` | `secguard report [dir]` | `report_summary_` |
| Incident plan | `tools/incident_plan.py` | `secguard plan <scenario>` | `incident_plan_` |

## `secguard` CLI

`secguard` is a thin Bash launcher for `cyber_toolkit.py`, which dispatches to
the modules above.

```bash
secguard --help                 # list modules and usage
secguard web example.com
secguard net 127.0.0.1 22 443
secguard log /var/log/auth.log 10
secguard integrity /etc
secguard android ./app
secguard report
secguard plan ssh-bruteforce
secguard plan --list
```

Arguments after the module name are forwarded verbatim; `--help` shows each
module's own options. Errors are printed to stderr and the module's exit code
is propagated.

## Skills structure

`skills/` holds short, human-readable playbooks that map a defensive objective
to a toolkit module and its JSON output:

- `web-header-tls-audit.md`
- `network-drift-monitoring.md`
- `log-anomaly-triage.md`
- `file-integrity-baseline.md`
- `android-workspace-guard.md`
- `incident-response-playbook.md`

`index.json` is the machine-readable catalog of these skills (id, file path,
and script path).

## Earlier releases

### [0.1.0] - Initial toolkit

- Added the web, network, log, integrity, and Android monitors, plus the
  `reports/` output directory.
- Added `cyber_toolkit.py`, `secguard`, `tools/report_summary.py`,
  `tools/incident_plan.py`, the skills library, `index.json`, `SCOPE.md`, and
  `SECURITY.md`.
