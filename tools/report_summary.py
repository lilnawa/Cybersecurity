"""Summarize the latest report produced by each toolkit module."""

from __future__ import annotations

import argparse
import glob
import json
import os
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
    load_json_file,
    metadata_of,
    resolve_output_dir,
    save_report as write_report,
)

CATEGORIES = {
    "web": "web_audit_*.json",
    "net": "net_audit_*.json",
    "log": "log_guard_*.json",
    "integrity": "integrity_*.json",
    "android": "android_guard_*.json",
    "plan": "incident_plan_*.json",
}
LABELS = {
    "web": "WEB",
    "net": "NET",
    "log": "LOG",
    "integrity": "INT",
    "android": "AND",
    "plan": "PLAN",
}


def latest_file(pattern: str) -> str | None:
    matches = sorted(glob.glob(pattern))
    return matches[-1] if matches else None


def load_json(path: str | None) -> dict | None:
    if not path:
        return None
    return load_json_file(path)


def _entry(category: str, path: str | None, data: dict | None) -> dict:
    if not data:
        return {"found": False, "file": None, "metadata": None}

    entry: dict = {
        "found": True,
        "file": os.path.basename(path) if path else None,
        "metadata": metadata_of(data),
    }
    if category == "web":
        cookies = data.get("cookies") or []
        entry.update({
            "target": data.get("final_url"),
            "http_status": data.get("http_status"),
            "header_score": data.get("header_score"),
            "missing_headers": len(data.get("missing_headers") or []),
            "cookies_with_issues": sum(1 for cookie in cookies if cookie.get("issues")),
        })
    elif category == "net":
        drift = data.get("drift") or {}
        entry.update({
            "host": data.get("host"),
            "open_ports": list((data.get("open_ports") or {}).keys()),
            "newly_opened": list(drift.get("newly_opened") or []),
        })
    elif category == "log":
        entry.update({
            "total_lines": data.get("total_lines", 0),
            "high_volume_ips": len(data.get("high_volume_ips") or {}),
            "repeat_auth_failures": len(data.get("repeat_auth_failures") or {}),
            "suspicious_paths": len(data.get("suspicious_paths") or {}),
        })
    elif category == "integrity":
        changes = data.get("changes") or {}
        entry.update({
            "target_dir": data.get("target_dir"),
            "modified": len(changes.get("modified") or []),
            "added": len(changes.get("added") or []),
            "removed": len(changes.get("removed") or []),
        })
    elif category == "android":
        entry.update({
            "target_path": data.get("target_path"),
            "world_writable_files": len(data.get("world_writable_files") or []),
            "potential_secret_exposures": len(data.get("potential_secret_exposures") or []),
        })
    elif category == "plan":
        entry.update({
            "scenario": data.get("scenario"),
            "title": data.get("title"),
            "steps": len(data.get("steps") or []),
        })
    return entry


def _format_entry(category: str, entry: dict) -> str:
    label = LABELS[category]
    if not entry["found"]:
        return f"[{label}] No report found."

    if category == "web":
        return (
            f"[WEB] {entry['target']} | Status: {entry['http_status']} | "
            f"Headers: {entry['header_score']} | Missing headers: {entry['missing_headers']} | "
            f"Cookies with issues: {entry['cookies_with_issues']}"
        )
    if category == "net":
        return (
            f"[NET] {entry['host']} | Open: {', '.join(entry['open_ports']) or 'None'} | "
            f"Newly opened: {', '.join(entry['newly_opened']) or 'None'}"
        )
    if category == "log":
        return (
            f"[LOG] Lines: {entry['total_lines']} | Flood IPs: {entry['high_volume_ips']} | "
            f"Auth fails: {entry['repeat_auth_failures']} | "
            f"Suspicious paths: {entry['suspicious_paths']}"
        )
    if category == "integrity":
        return (
            f"[INT] Dir: {entry['target_dir']} | Mod: {entry['modified']} | "
            f"Add: {entry['added']} | Del: {entry['removed']}"
        )
    if category == "android":
        return (
            f"[AND] Path: {entry['target_path']} | "
            f"World-writable: {entry['world_writable_files']} | "
            f"Secret hits: {entry['potential_secret_exposures']}"
        )
    return f"[PLAN] Scenario: {entry['scenario']} | {entry['title']} | Steps: {entry['steps']}"


def summarize_reports(reports_dir: str | os.PathLike | None = None) -> dict:
    """Print and return a summary of the latest report for every category."""
    directory = resolve_output_dir(reports_dir)
    reports = {}
    for category, pattern in CATEGORIES.items():
        path = latest_file(os.path.join(str(directory), pattern))
        reports[category] = _entry(category, path, load_json(path))

    present = sum(1 for entry in reports.values() if entry["found"])
    report = build_report(
        "report_summary",
        summary=f"Summarized {len(reports)} report categories: "
                f"{present} present, {len(reports) - present} missing",
        reports_dir=str(directory),
        reports_present=present,
        reports_missing=len(reports) - present,
        reports=reports,
    )

    print("\n================ TOOLKIT REPORT SUMMARY ================")
    for category in CATEGORIES:
        print(_format_entry(category, reports[category]))
    print("======================================================\n")
    return report


def save_summary(report: dict, output_dir: str | None = None) -> str:
    return write_report(report, output_dir, prefix="report_summary")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="report_summary.py",
        description="Summarize the most recent report from each toolkit module.",
        epilog="Example: python3 report_summary.py /path/to/reports",
    )
    parser.add_argument(
        "reports_dir",
        nargs="?",
        default=None,
        help="directory containing JSON reports (default: <repo>/reports)",
    )
    add_output_dir_arg(parser)
    add_json_arg(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    reports_dir = resolve_output_dir(args.reports_dir)
    if not reports_dir.is_dir():
        print(f"[WARN] Reports directory not found: {reports_dir}", file=sys.stderr)

    report = summarize_reports(reports_dir)
    try:
        report_path = save_summary(report, args.output_dir)
    except OSError as exc:
        print_error(f"could not write summary: {exc}")
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Summary saved : {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
