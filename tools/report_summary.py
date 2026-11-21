import glob
import json
import os
import sys


def latest_file(pattern: str) -> str | None:
    matches = sorted(glob.glob(pattern))
    return matches[-1] if matches else None


def load_json(path: str | None) -> dict | None:
    if not path or not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def summarize_reports(reports_dir: str = "reports"):
    print("\n================ TOOLKIT REPORT SUMMARY ================")

    web = load_json(latest_file(os.path.join(reports_dir, "web_audit_*.json")))
    if web:
        print(f"[WEB] {web.get('final_url')} | Status: {web.get('http_status')} | Headers: {web.get('header_score')}")
        print(f"      Missing headers: {len(web.get('missing_headers', []))} | Cookies with issues: {sum(1 for c in web.get('cookies', []) if c.get('issues'))}")
    else:
        print("[WEB] No report found.")

    net = load_json(latest_file(os.path.join(reports_dir, "net_audit_*.json")))
    if net:
        open_list = ", ".join(net.get("open_ports", {}).keys()) or "None"
        drift = net.get("drift", {})
        new_open = ", ".join(drift.get("newly_opened", [])) or "None"
        print(f"[NET] {net.get('host')} | Open: {open_list} | Newly opened: {new_open}")
    else:
        print("[NET] No report found.")

    log = load_json(latest_file(os.path.join(reports_dir, "log_guard_*.json")))
    if log:
        print(f"[LOG] Lines: {log.get('total_lines')} | Flood IPs: {len(log.get('high_volume_ips', {}))} | Auth fails: {len(log.get('repeat_auth_failures', {}))} | Suspicious paths: {len(log.get('suspicious_paths', {}))}")
    else:
        print("[LOG] No report found.")

    integ = load_json(latest_file(os.path.join(reports_dir, "integrity_*.json")))
    if integ:
        ch = integ.get("changes", {})
        print(f"[INT] Dir: {integ.get('target_dir')} | Mod: {len(ch.get('modified', []))} | Add: {len(ch.get('added', []))} | Del: {len(ch.get('removed', []))}")
    else:
        print("[INT] No report found.")

    and_rep = load_json(latest_file(os.path.join(reports_dir, "android_guard_*.json")))
    if and_rep:
        print(f"[AND] Path: {and_rep.get('target_path')} | World-writable: {len(and_rep.get('world_writable_files', []))} | Secret hits: {len(and_rep.get('potential_secret_exposures', []))}")
    else:
        print("[AND] No report found.")

    print("======================================================\n")


def main():
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else "reports"
    summarize_reports(reports_dir)


if __name__ == "__main__":
    main()
