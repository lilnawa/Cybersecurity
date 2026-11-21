"""Check workspaces for world-writable files and potential secret leaks."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
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

SENSITIVE_PATTERNS = {
    "github_classic_token": re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    "github_fine_grained": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    "private_key_header": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "bearer_or_api_secret": re.compile(
        r"(?i)\b(?:api_key|secret_key|password|passwd|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}"
    ),
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
                with open(full, "r", encoding="utf-8", errors="ignore") as handle:
                    for line_no, line in enumerate(handle, start=1):
                        for label, pattern in SENSITIVE_PATTERNS.items():
                            if pattern.search(line):
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
    summary = (
        f"Scanned {target_path}: {len(world_writable)} world-writable file(s), "
        f"{len(secret_hits)} potential secret exposure(s)"
    )
    return build_report(
        "android_guard",
        summary=summary,
        target_path=os.path.abspath(target_path),
        world_writable_files=world_writable,
        potential_secret_exposures=secret_hits,
    )


def save_report(report: dict, output_dir: str | None = None) -> str:
    return write_report(report, output_dir, prefix="android_guard")


def print_summary(report: dict, report_path: str) -> None:
    print("\n================ ANDROID / WORKSPACE GUARD ================")
    print(f"Target Path          : {report['target_path']}")

    writable = report["world_writable_files"]
    print(f"World-Writable Files : {len(writable)}")
    for item in writable[:10]:
        print(f"  [!] Writable by others: {item}")

    secrets = report["potential_secret_exposures"]
    print(f"Potential Secret Hits: {len(secrets)}")
    for hit in secrets[:10]:
        print(f"  [!] {hit['file']}:{hit['line']} -> {hit['type']}")

    print(f"\nReport saved         : {report_path}")
    print("===========================================================\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="android_guard.py",
        description="Check an Android/workspace directory for permissive files and hardcoded secrets.",
        epilog="Example: python3 android_guard.py ./my-project",
    )
    parser.add_argument("path", nargs="?", default=".", help="directory or file to inspect (default: .)")
    add_output_dir_arg(parser)
    add_json_arg(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    target = Path(args.path).expanduser()
    if not target.exists():
        print_error(f"path not found: {target}")
        return 1

    try:
        report = audit_workspace(str(target))
        report_path = save_report(report, args.output_dir)
    except OSError as exc:
        print_error(f"could not inspect path: {exc}")
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_summary(report, report_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
