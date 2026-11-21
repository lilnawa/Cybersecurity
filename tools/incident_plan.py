import json
import os
import sys
from datetime import datetime, timezone

PLAYBOOKS = {
    "ssh-bruteforce": {
        "title": "SSH / Auth Brute-Force Response",
        "steps": [
            "Check recent auth/login logs and identify repeated failed source IPs.",
            "Block or rate-limit offending IPs at firewall/reverse-proxy level.",
            "Disable password login where SSH keys are used; enforce strong passwords and 2FA.",
            "Rotate any potentially exposed credentials and audit active sessions.",
        ],
    },
    "web-exposure": {
        "title": "Web Header / TLS / Cookie Hardening",
        "steps": [
            "Enable HTTPS redirect and HSTS where TLS is properly configured.",
            "Add missing security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).",
            "Set HttpOnly, Secure, and SameSite flags on sensitive session cookies.",
            "Remove or suppress verbose server/framework version banners.",
        ],
    },
    "file-tamper": {
        "title": "File / Config Integrity Drift Response",
        "steps": [
            "Review added, modified, and removed files from the latest integrity snapshot.",
            "Verify whether changes match an authorized deployment or maintenance window.",
            "Restore unauthorized config/script changes from a clean trusted backup.",
            "Re-run integrity baseline snapshot after remediation.",
        ],
    },
    "android-risk": {
        "title": "Android & Workspace Security Hardening",
        "steps": [
            "Review installed apps and revoke unnecessary Accessibility, Device Admin, or unknown-source permissions.",
            "Remove any hardcoded tokens, passwords, or private keys from code and workspace files.",
            "Tighten file/directory permissions and verify .gitignore excludes secrets and reports.",
            "Update OS security patches and core apps.",
        ],
    },
}


def generate_plan(scenario: str) -> dict:
    key = scenario.lower().strip()
    book = PLAYBOOKS.get(key)
    if not book:
        raise ValueError(f"Unknown scenario '{scenario}'. Available: {', '.join(PLAYBOOKS.keys())}")

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "scenario": key,
        "title": book["title"],
        "steps": book["steps"],
    }


def save_plan(plan: dict, output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"incident_plan_{plan['scenario']}_{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(plan, f, indent=2)
    return path


def print_plan(plan: dict, report_path: str):
    print("\n================ INCIDENT & HARDENING PLAN ================")
    print(f"Scenario : {plan['scenario']}")
    print(f"Title    : {plan['title']}\n")
    for idx, step in enumerate(plan["steps"], start=1):
        print(f"  {idx}. {step}")
    print(f"\nSaved    : {report_path}")
    print("===========================================================\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 incident_plan.py <scenario>")
        print("Scenarios: " + ", ".join(PLAYBOOKS.keys()))
        sys.exit(1)

    try:
        plan = generate_plan(sys.argv[1])
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)

    report_path = save_plan(plan)
    print_plan(plan, report_path)


if __name__ == "__main__":
    main()
