"""Analyze logs for repeated auth failures, high-volume IPs and path probes."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
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
    positive_int,
    save_report,
)

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
AUTH_FAILURE_PATTERN = re.compile(
    r"(?:failed|invalid|incorrect|rejected)\s+(?:password|login|auth|authentication|publickey|user)"
    r"|authentication failure|auth fail|failed publickey|invalid user|permission denied",
    re.IGNORECASE,
)
SUSPICIOUS_PATH_PATTERNS = {
    "/wp-login.php": re.compile(r"/wp-login\.php\b", re.IGNORECASE),
    "/wp-admin": re.compile(r"/wp-admin\b", re.IGNORECASE),
    "/phpmyadmin": re.compile(r"/phpmyadmin\b", re.IGNORECASE),
    "/.env": re.compile(r"/\.env(?:\b|$)", re.IGNORECASE),
    "/.git": re.compile(r"/\.git(?:/|\b)", re.IGNORECASE),
    "/xmlrpc.php": re.compile(r"/xmlrpc\.php\b", re.IGNORECASE),
    "/admin": re.compile(r"/admin(?:er)?(?:/|\b)", re.IGNORECASE),
    "/etc/passwd": re.compile(r"/etc/passwd\b", re.IGNORECASE),
}


def _ranked(counter: Counter, minimum: int = 1) -> dict[str, int]:
    """Return counts above *minimum*, sorted by frequency then key."""
    return dict(
        sorted(
            ((key, count) for key, count in counter.items() if count >= minimum),
            key=lambda item: (-item[1], item[0]),
        )
    )


def analyze_log(log_path: str | Path, threshold: int = 5) -> dict:
    """Scan a log file and return a report with triage findings."""
    path = Path(log_path).expanduser()
    total_lines = 0
    ip_counts: Counter = Counter()
    auth_failures: Counter = Counter()
    path_probes: Counter = Counter()

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            total_lines += 1
            ip_match = IP_PATTERN.search(line)
            ip = ip_match.group(0) if ip_match else None
            if ip:
                ip_counts[ip] += 1
                if AUTH_FAILURE_PATTERN.search(line):
                    auth_failures[ip] += 1
            for label, pattern in SUSPICIOUS_PATH_PATTERNS.items():
                if pattern.search(line):
                    path_probes[label] += 1

    high_volume = _ranked(ip_counts, threshold)
    repeat_auth = _ranked(auth_failures, threshold)
    suspicious = _ranked(path_probes)
    summary = (
        f"Analyzed {total_lines} line(s) from {path.name}: "
        f"{len(high_volume)} high-volume IP(s), "
        f"{len(repeat_auth)} repeat auth-failure source(s), "
        f"{len(suspicious)} suspicious path type(s)"
    )

    return build_report(
        "log_guard",
        summary=summary,
        log_file=str(path.resolve()),
        total_lines=total_lines,
        threshold=threshold,
        unique_ips=len(ip_counts),
        high_volume_ips=high_volume,
        repeat_auth_failures=repeat_auth,
        suspicious_paths=suspicious,
    )


def save_report_to(report: dict, output_dir: str | None = None) -> str:
    return save_report(report, output_dir, prefix="log_guard")


def _print_counts(title: str, values: dict) -> None:
    print(f"\n--- {title} ---")
    if not values:
        print("  None")
        return
    for key, count in values.items():
        print(f"  {key}: {count}")


def print_summary(report: dict, report_path: str) -> None:
    print("\n================ LOG ANOMALY TRIAGE =================")
    print(f"Log File     : {report['log_file']}")
    print(f"Total Lines  : {report['total_lines']}")
    print(f"Threshold    : {report['threshold']}")
    print(f"Unique IPs   : {report['unique_ips']}")

    _print_counts("High-Volume Source IPs", report["high_volume_ips"])
    _print_counts("Repeated Authentication Failures", report["repeat_auth_failures"])
    _print_counts("Suspicious Path Probes", report["suspicious_paths"])

    print(f"\nReport saved : {report_path}")
    print("====================================================\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log_guard.py",
        description="Triage a log file for repeated auth failures, high-volume IPs and suspicious path probes.",
        epilog="Example: python3 log_guard.py /var/log/auth.log 10",
    )
    parser.add_argument("logfile", help="path to the log file to analyze")
    parser.add_argument(
        "threshold",
        nargs="?",
        type=positive_int,
        default=5,
        help="minimum repeated events to report (default: 5)",
    )
    add_output_dir_arg(parser)
    add_json_arg(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log_path = Path(args.logfile).expanduser()
    if not log_path.is_file():
        print_error(f"log file not found: {log_path}")
        return 1

    try:
        report = analyze_log(log_path, args.threshold)
        report_path = save_report_to(report, args.output_dir)
    except OSError as exc:
        print_error(f"could not process log file: {exc}")
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_summary(report, report_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
