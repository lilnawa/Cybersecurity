"""TCP port/banner scanner with baseline drift tracking between runs."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import socket
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
    port_number,
    print_error,
    resolve_output_dir,
    save_report as write_report,
)

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080, 8443]


def probe_port(host: str, port: int, timeout: float = 1.2) -> dict:
    banner = None
    is_open = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) == 0:
                is_open = True
                try:
                    sock.settimeout(0.8)
                    data = sock.recv(256)
                    if data:
                        banner = data.decode("utf-8", errors="replace").strip()[:100]
                except Exception:
                    banner = None
    except Exception:
        is_open = False

    return {
        "port": port,
        "state": "open" if is_open else "closed",
        "banner": banner,
    }


def scan_host(host: str, ports: list[int], workers: int = 20) -> dict:
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(probe_port, host, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda item: item["port"])
    open_ports = {str(item["port"]): item["banner"] for item in results if item["state"] == "open"}
    summary = f"Scanned {host}: {len(open_ports)} of {len(ports)} port(s) open"

    return build_report(
        "net_audit",
        summary=summary,
        host=host,
        scanned_ports=ports,
        open_ports=open_ports,
    )


def load_latest_baseline(host: str, output_dir: str | None = None) -> dict | None:
    directory = resolve_output_dir(output_dir)
    if not directory.is_dir():
        return None
    prefix = f"net_audit_{host}_"
    candidates = sorted(
        path for path in directory.iterdir()
        if path.name.startswith(prefix) and path.suffix == ".json"
    )
    for path in reversed(candidates):
        record = load_json_file(path)
        if record is not None:
            return record
    return None


def compare_scans(previous: dict | None, current: dict) -> dict:
    if not previous:
        return {
            "has_baseline": False,
            "newly_opened": list(current["open_ports"].keys()),
            "newly_closed": [],
            "banner_changes": [],
        }

    prev_open = previous.get("open_ports", {})
    curr_open = current.get("open_ports", {})

    newly_opened = [p for p in curr_open if p not in prev_open]
    newly_closed = [p for p in prev_open if p not in curr_open]
    banner_changes = []

    for p in curr_open:
        if p in prev_open and prev_open[p] != curr_open[p]:
            banner_changes.append({
                "port": p,
                "old_banner": prev_open[p],
                "new_banner": curr_open[p],
            })

    return {
        "has_baseline": True,
        "newly_opened": newly_opened,
        "newly_closed": newly_closed,
        "banner_changes": banner_changes,
    }


def save_report(report: dict, output_dir: str | None = None) -> str:
    safe_host = report["host"].replace("/", "_")
    return write_report(report, output_dir, prefix=f"net_audit_{safe_host}")


def print_summary(current: dict, diff: dict, report_path: str) -> None:
    print("\n================ NETWORK CHANGE AUDIT ================")
    print(f"Host         : {current['host']}")
    print(f"Open Ports   : {', '.join(current['open_ports'].keys()) if current['open_ports'] else 'None'}")

    for port, banner in current["open_ports"].items():
        print(f"  - Port {port}: OPEN" + (f" | Banner: {banner}" if banner else ""))

    print("\n--- Drift vs Previous Scan ---")
    if not diff["has_baseline"]:
        print("First scan recorded as baseline.")
    else:
        print(f"Newly Opened : {', '.join(diff['newly_opened']) if diff['newly_opened'] else 'None'}")
        print(f"Newly Closed : {', '.join(diff['newly_closed']) if diff['newly_closed'] else 'None'}")
        if diff["banner_changes"]:
            for change in diff["banner_changes"]:
                print(f"Banner Change on port {change['port']}: "
                      f"'{change['old_banner']}' -> '{change['new_banner']}'")
        else:
            print("Banner Change: None")

    print(f"\nReport saved : {report_path}")
    print("======================================================\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="net_audit.py",
        description="Check TCP ports and banners, then compare with the previous scan for drift.",
        epilog=f"Example: python3 net_audit.py 127.0.0.1 22 80 443 (default ports: {', '.join(map(str, DEFAULT_PORTS))})",
    )
    parser.add_argument("host", help="hostname or IP address to scan")
    parser.add_argument(
        "ports",
        nargs="*",
        type=port_number,
        help="ports to check (default: common ports)",
    )
    add_output_dir_arg(parser)
    add_json_arg(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.host.strip():
        print_error("host must be a non-empty hostname or IP address")
        return 1

    ports = args.ports or DEFAULT_PORTS
    previous = load_latest_baseline(args.host, args.output_dir)
    current = scan_host(args.host, ports)
    diff = compare_scans(previous, current)
    current["drift"] = diff
    current["summary"] += (
        f"; {len(diff['newly_opened'])} newly opened, "
        f"{len(diff['newly_closed'])} newly closed"
    )

    try:
        report_path = save_report(current, args.output_dir)
    except OSError as exc:
        print_error(f"could not write report: {exc}")
        return 1

    if args.json:
        print(json.dumps(current, indent=2))
    else:
        print_summary(current, diff, report_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
