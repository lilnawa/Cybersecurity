"""Unified command-line entry point for the Cybersecurity Toolkit."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from common import print_error

REPO_ROOT = Path(__file__).resolve().parent

MODULES = {
    "web": "scanners/web/web_audit.py",
    "net": "scanners/net/net_audit.py",
    "log": "monitors/logs/log_guard.py",
    "integrity": "monitors/integrity/file_guard.py",
    "android": "monitors/android/android_guard.py",
    "report": "tools/report_summary.py",
    "plan": "tools/incident_plan.py",
}

MODULE_HELP = {
    "web": "Audit HTTP headers, TLS, cookies and banners",
    "net": "Port/banner scan with baseline drift check",
    "log": "Analyze logs for auth failures, floods and probes",
    "integrity": "SHA-256 directory integrity monitor",
    "android": "Workspace permission and secret-pattern check",
    "report": "Summarize the latest reports from reports/",
    "plan": "Generate an incident/hardening checklist",
}


def show_menu(stream=None) -> None:
    """Print the top-level help text."""
    out = stream or sys.stdout
    print("\n================ CYBERSECURITY TOOLKIT ================", file=out)
    for name, description in MODULE_HELP.items():
        print(f"  {name:<10} -> {description}", file=out)
    print("\nUsage:", file=out)
    print("  secguard <module> [args...]", file=out)
    print("  python3 cyber_toolkit.py <module> [args...]", file=out)
    print("  secguard <module> --help    (module-specific options)", file=out)
    print("\nExamples:", file=out)
    print("  secguard plan android-risk", file=out)
    print("  secguard report", file=out)
    print("=======================================================\n", file=out)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if not args or args[0] in ("-h", "--help", "help"):
        show_menu()
        return 0

    name = args[0].lower()
    if name not in MODULES:
        print_error(f"unknown module '{name}'. Run 'secguard --help' to list available modules.")
        return 1

    script = REPO_ROOT / MODULES[name]
    if not script.is_file():
        print_error(f"module '{name}' is not installed (missing {script}).")
        return 1

    try:
        completed = subprocess.run(
            [sys.executable, str(script), *args[1:]],
            cwd=REPO_ROOT,
            check=False,
        )
    except OSError as exc:
        print_error(f"could not launch module '{name}': {exc}")
        return 1
    return completed.returncode


if __name__ == "__main__":
    sys.exit(main())
