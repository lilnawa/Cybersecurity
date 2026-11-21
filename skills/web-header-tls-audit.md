# Skill: Web Header, TLS & Cookie Audit

- **Tool:** `scanners/web/web_audit.py` (`secguard web <url>`)
- **Objective:** Inspect HTTP response headers, TLS version/cipher/certificate expiration, cookie flags (`HttpOnly`, `Secure`, `SameSite`), and exposed server banners.
- **Output:** Console summary + JSON report in `reports/`.
