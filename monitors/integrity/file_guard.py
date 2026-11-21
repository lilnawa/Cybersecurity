import hashlib
import json
import os
import sys
from datetime import datetime, timezone


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot_directory(target_dir: str) -> dict[str, str]:
    hashes = {}
    for root, _, files in os.walk(target_dir):
        for fname in sorted(files):
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, target_dir)
            try:
                hashes[rel_path] = sha256_file(full_path)
            except OSError:
                continue
    return hashes


def load_latest_snapshot(output_dir: str = "reports") -> dict | None:
    if not os.path.isdir(output_dir):
        return None
    files = sorted(
        f for f in os.listdir(output_dir)
        if f.startswith("integrity_") and f.endswith(".json")
    )
    if not files:
        return None
    with open(os.path.join(output_dir, files[-1]), "r", encoding="utf-8") as f:
        return json.load(f)


def compare_snapshots(old: dict[str, str], new: dict[str, str]) -> dict:
    added = sorted(p for p in new if p not in old)
    removed = sorted(p for p in old if p not in new)
    modified = sorted(p for p in new if p in old and old[p] != new[p])
    return {"added": added, "removed": removed, "modified": modified}


def save_snapshot(record: dict, output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"integrity_{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
    return path


def print_report(target_dir: str, changes: dict, has_baseline: bool, report_path: str):
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


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 file_guard.py <directory_path>")
        sys.exit(1)

    target_dir = sys.argv[1]
    if not os.path.isdir(target_dir):
        print(f"[ERROR] Directory not found: {target_dir}")
        sys.exit(1)

    current_hashes = snapshot_directory(target_dir)
    prev_record = load_latest_snapshot()
    has_baseline = prev_record is not None
    prev_hashes = prev_record.get("files", {}) if prev_record else {}

    changes = compare_snapshots(prev_hashes, current_hashes)
    record = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "target_dir": os.path.abspath(target_dir),
        "files": current_hashes,
        "changes": changes,
    }
    report_path = save_snapshot(record)
    print_report(target_dir, changes, has_baseline, report_path)


if __name__ == "__main__":
    main()
