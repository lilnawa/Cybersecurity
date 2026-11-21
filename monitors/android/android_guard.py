import json
import os
import re
import stat
import sys
from datetime import datetime, timezone

SENSITIVE_PATTERNS = {
    "github_classic_token": re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    "github_fine_grained": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    "private_key_header": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "bearer_or_api_secret": re.compile(r"(?i)\b(?:api_key|secret_key|password|passwd|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
}

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules"}


def check_world_writable(target_path: str) -> list[str]:
    risky = []
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            full = os.path.join(root, name)
            try:
                mode = os.stat(full).st_mode
                if mode & stat.S_IWOTH:
                    risky.append(os.path.relpath(full, target_path))
            except OSError:
                continue
    return sorted(risky)


def scan_secret_leaks(target_path: str) -> list[dict]:
    findings = []
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in sorted(files):
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, target_path)
            try:
                if os.path.getsize(full) > 1_000_000:
                    continue
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        for label, pat in SENSITIVE_PATTERNS.items():
                            if pat.search(line):
                                findings.append({
                                    "file": rel,
                                    "line": line_no,
                                    "type": label,
                                })
            except OSError:
                continue
    return findings


def audit_workspace(target_path: str) -> dict:
    world_writable = check_world_writable(target_path)
    secret_hits = scan_secret_leaks(target_path)

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "target_path": os.path.abspath(target_path),
        "world_writable_files": world_writable,
        "potential_secret_exposures": secret_hits,
    }


def save_report(report: dict, output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"android_guard_{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return path


def print_summary(report: dict, report_path: str):
    print("\n================ ANDROID / WORKSPACE GUARD ================")
    print(f"Target Path          : {report['target_path']}")

    ww = report["world_writable_files"]
    print(f"World-Writable Files : {len(ww)}")
    for item in ww[:10]:
        print(f"  [!] Writable by others: {item}")

    secrets = report["potential_secret_exposures"]
    print(f"Potential Secret Hits: {len(secrets)}")
    for hit in secrets[:10]:
        print(f"  [!] {hit['file']}:{hit['line']} -> {hit['type']}")

    print(f"\nReport saved         : {report_path}")
    print("===========================================================\n")


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    if not os.path.exists(target):
        print(f"[ERROR] Path not found: {target}")
        sys.exit(1)

    report = audit_workspace(target)
    report_path = save_report(report)
    print_summary(report, report_path)


if __name__ == "__main__":
    main()
