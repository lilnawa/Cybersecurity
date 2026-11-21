"""SHA-256 directory integrity baseline and drift detection."""

from __future__ import annotations

import argparse
import hashlib
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
    print_error,
    resolve_output_dir,
    save_report as write_report,
)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_directory(target_dir: str) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for root, _, files in os.walk(target_dir):
        for fname in sorted(files):
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, target_dir)
            try:
                hashes[rel_path] = sha256_file(full_path)
            except OSError:
                continue
    return hashes


def load_latest_snapshot(
    target_dir: str | None = None,
    output_dir: str | None = None,
) -> dict | None:
    """Load the most recent baseline, optionally restricted to one directory."""
    directory = resolve_output_dir(output_dir)
    if not directory.is_dir():
        return None
    candidates = sorted(
        path for path in directory.iterdir()
        if path.name.startswith("integrity_") and path.suffix == ".json"
    )
    wanted = os.path.abspath(target_dir) if target_dir else None
    for path in reversed(candidates):
        record = load_json_file(path)
        if record is None:
            continue
        if wanted is None or record.get("target_dir") == wanted:
            return record
    return None


def compare_snapshots(old: dict[str, str], new: dict[str, str]) -> dict:
    added = sorted(p for p in new if p not in old)
    removed = sorted(p for p in old if p not in new)
    modified = sorted(p for p in new if p in old and old[p] != new[p])
    return {"added": added, "removed": removed, "modified": modified}


def save_snapshot(record: dict, output_dir: str | None = None) -> str:
    return write_report(record, output_dir, prefix="integrity")


def print_report(target_dir: str, changes: dict, has_baseline: bool, report_path: str) -> None:
    print("\n================ FILE INTEGRITY GUARD ================")
    print(f"Directory : {os.path.abspath(target_dir)}")
    if not has_baseline:
        print("Status    : Baseline recorded.")
    else:
        print(f"Modified  : {', '.join(changes['modified']) if changes['modified'] else 'None'}")
        print(f"Added     : {', '.join(changes['added']) if changes['added'] else 'None'}")
        print(f"Removed   : {', '.join(changes['removed']) if changes['removed'] else 'None'}")
    print(f"Snapshot  : {report_path}")
    print("======================================================\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="file_guard.py",
        description="Hash a directory with SHA-256 and detect added, modified or removed files.",
        epilog="Example: python3 file_guard.py /etc",
    )
    parser.add_argument("directory", help="directory to snapshot")
    add_output_dir_arg(parser)
    add_json_arg(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    target_dir = Path(args.directory).expanduser()
    if not target_dir.is_dir():
        print_error(f"directory not found: {target_dir}")
        return 1

    try:
        current_hashes = snapshot_directory(str(target_dir))
        previous = load_latest_snapshot(str(target_dir), args.output_dir)
        has_baseline = previous is not None
        changes = compare_snapshots(previous.get("files", {}) if previous else {}, current_hashes)

        if not has_baseline:
            summary = f"Baseline recorded for {len(current_hashes)} file(s) in {target_dir}"
            changes = {"added": [], "removed": [], "modified": []}
        else:
            total = sum(len(items) for items in changes.values())
            summary = (
                "No changes detected" if total == 0 else f"{total} change(s) detected"
            ) + f" across {len(current_hashes)} file(s) in {target_dir}"

        record = build_report(
            "file_guard",
            summary=summary,
            target_dir=str(target_dir.resolve()),
            is_baseline=not has_baseline,
            files=current_hashes,
            changes=changes,
        )
        report_path = save_snapshot(record, args.output_dir)
    except OSError as exc:
        print_error(f"could not process directory: {exc}")
        return 1

    if args.json:
        print(json.dumps(record, indent=2))
    else:
        print_report(args.directory, changes, has_baseline, report_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
