"""Generate defensive incident-response and hardening checklists."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = next(
    (parent for parent in Path(__file__).resolve().parents if (parent / "common.py").is_file()),
    Path(__file__).resolve().parent,
)
sys.path.insert(0, str(_REPO_ROOT))

from common import (  # noqa: E402
    add_json_arg,
    add_output_dir_arg,
    build_report,
    print_error,
    save_report as write_report,
)

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

    return build_report(
        "incident_plan",
        summary=f"Generated {len(book['steps'])}-step response plan for '{key}'",
        scenario=key,
        title=book["title"],
        steps=list(book["steps"]),
    )


def save_plan(plan: dict, output_dir: str | None = None) -> str:
    return write_report(
        plan,
        output_dir,
        prefix=f"incident_plan_{plan['scenario']}",
    )


def print_plan(plan: dict, report_path: str) -> None:
    print("\n================ INCIDENT & HARDENING PLAN ================")
    print(f"Scenario : {plan['scenario']}")
    print(f"Title    : {plan['title']}\n")
    for idx, step in enumerate(plan["steps"], start=1):
        print(f"  {idx}. {step}")
    print(f"\nSaved    : {report_path}")
    print("===========================================================\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="incident_plan.py",
        description="Generate a structured containment, investigation and hardening checklist.",
        epilog="Example: python3 incident_plan.py ssh-bruteforce",
    )
    parser.add_argument(
        "scenario",
        nargs="?",
        help="playbook to generate: " + ", ".join(PLAYBOOKS),
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="list available scenarios and exit",
    )
    add_output_dir_arg(parser)
    add_json_arg(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list:
        for key, book in PLAYBOOKS.items():
            print(f"  {key:<16} {book['title']}")
        return 0
    if not args.scenario:
        parser.error("a scenario is required (use --list to see available scenarios)")

    try:
        plan = generate_plan(args.scenario)
        report_path = save_plan(plan, args.output_dir)
    except ValueError as exc:
        print_error(str(exc))
        return 1
    except OSError as exc:
        print_error(f"could not write plan: {exc}")
        return 1

    if args.json:
        print(json.dumps(plan, indent=2))
    else:
        print_plan(plan, report_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
