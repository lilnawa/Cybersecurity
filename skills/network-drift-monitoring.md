# Skill: Network Port & Banner Drift Monitoring

- **Tool:** `scanners/net/net_audit.py` (`secguard net <host> [ports...]`)
- **Objective:** Check TCP ports and service banners, then compare against previous scan baselines to detect newly opened/closed ports or banner changes.
- **Output:** Console summary + JSON baseline/report in `reports/`.
