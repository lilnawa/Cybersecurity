# Cybersecurity

Practical security auditing, log analysis, and network monitoring scripts built in Python.

## Structure
- `scanners/web/web_audit.py` — Audits HTTP security headers, TLS/certificate details, cookie flags, and server banners; saves JSON reports.
- `scanners/net/net_audit.py` — Multi-threaded TCP port/banner checker with baseline drift tracking across scans.
- `monitors/logs/log_guard.py` — Analyzes log files for repeated auth failures, high-volume IPs, and suspicious path probes.
- `reports/` — Generated JSON audit and monitoring reports.

## Usage Note
Use these tools strictly on systems, networks, or applications you own or have explicit authorization to test.
