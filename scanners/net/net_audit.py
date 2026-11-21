import concurrent.futures
import json
import os
import socket
import sys
from datetime import datetime, timezone

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

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "scanned_ports": ports,
        "open_ports": open_ports,
    }


def load_latest_baseline(host: str, output_dir: str = "reports") -> dict | None:
    if not os.path.isdir(output_dir):
        return None
    prefix = f"net_audit_{host}_"
    candidates = [
        os.path.join(output_dir, f)
        for f in os.listdir(output_dir)
        if f.startswith(prefix) and f.endswith(".json")
    ]
    if not candidates:
        return None
    candidates.sort()
    with open(candidates[-1], "r", encoding="utf-8") as f:
        return json.load(f)


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


def save_report(report: dict, output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    safe_host = report["host"].replace("/", "_")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"net_audit_{safe_host}_{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return path


def print_summary(current: dict, diff: dict, report_path: str):
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
            for ch in diff["banner_changes"]:
                print(f"Banner Change on port {ch['port']}: '{ch['old_banner']}' -> '{ch['new_banner']}'")
        else:
            print("Banner Change: None")

    print(f"\nReport saved : {report_path}")
    print("======================================================\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 net_audit.py <host_or_ip> [port1 port2 ...]")
        sys.exit(1)

    host = sys.argv[1]
    ports = [int(p) for p in sys.argv[2:]] if len(sys.argv) > 2 else DEFAULT_PORTS

    previous = load_latest_baseline(host)
    current = scan_host(host, ports)
    diff = compare_scans(previous, current)
    current["drift"] = diff

    report_path = save_report(current)
    print_summary(current, diff, report_path)


if __name__ == "__main__":
    main()
