"""Shared helpers for consistent CLI behaviour and JSON reports.

Every toolkit module builds its reports with :func:`build_report` and writes
them with :func:`save_report`, so all generated JSON files share the same
metadata envelope: ``tool``, ``timestamp_utc``, ``status`` and ``summary``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TOOLKIT_NAME = "Cybersecurity Toolkit"
REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_REPORTS_DIR = REPO_ROOT / "reports"


def utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def timestamp_slug() -> str:
    """Return a collision-resistant UTC timestamp for report filenames."""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")


def resolve_output_dir(value: str | os.PathLike[str] | None = None) -> Path:
    """Resolve a user supplied report directory, defaulting to <repo>/reports."""
    if value is None:
        return DEFAULT_REPORTS_DIR
    return Path(value).expanduser()


def build_report(tool: str, *, summary: str, status: str = "ok", **fields: Any) -> dict[str, Any]:
    """Build a JSON-serializable report with the standard metadata envelope."""
    return {
        "tool": tool,
        "timestamp_utc": utc_now(),
        "status": status,
        "summary": summary,
        **fields,
    }


def save_report(
    report: dict[str, Any],
    output_dir: str | os.PathLike[str] | None = None,
    *,
    prefix: str,
) -> str:
    """Write a report as pretty-printed JSON and return its path."""
    directory = resolve_output_dir(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{prefix}_{timestamp_slug()}.json"
    with path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    return str(path)


def load_json_file(path: str | os.PathLike[str]) -> dict[str, Any] | None:
    """Load a JSON object, returning ``None`` for missing or malformed files."""
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def metadata_of(report: dict[str, Any]) -> dict[str, Any]:
    """Extract the standard metadata envelope from a loaded report."""
    return {key: report.get(key) for key in ("tool", "timestamp_utc", "status", "summary")}


def add_output_dir_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-o",
        "--output-dir",
        metavar="DIR",
        default=None,
        help=f"directory for JSON output (default: {DEFAULT_REPORTS_DIR})",
    )


def add_json_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the full JSON report to stdout instead of the text summary",
    )


def print_error(message: str) -> None:
    print(f"[ERROR] {message}", file=sys.stderr)


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return number


def port_number(value: str) -> int:
    number = positive_int(value)
    if number > 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return number
