import glob
import json
import os
import sys
from datetime import datetime, timezone


def latest_json(pattern: str) -> dict | None:
    files = sorted(glob.glob(pattern))
    if not files:
        return None
    with open(files[-1], "r", encoding="utf-8") as f:
        return json.load(f)


def run_triage(reports_dir: str = "reports") -> dict:
    alerts = []
    recommended_plans = []

    web = latest_json(os.path.join(reports_dir, "web_audit_*.json"))
    if web:
        missing_count = len(web.get("missing_headers", []))
        cookie_issues = sum(1 for c in web.get("cookies", []) if c.get("issues"))
        if missing_count >= 3 or cookie_issues > 0 or not web.get("is_https"):
            alerts.append({
                "source": "web",
                "severity": "medium",
                "reason": f"Target {web.get('final_url')} has {missing_count} missing headers and {cookie_issues} cookie flag issue(s).",
            })
            recommended_plans.append("web-exposure")

    log = latest_json(os.path.join(reports_dir, "log_guard_*.json"))
    if log:
        auth_fails = len(log.get("repeat_auth_failures", {}))
        flood_ips = len(log.get("high_volume_ips", {}))
        probes = len(log.get("suspicious_paths", {}))
        if auth_fails > 0 or flood_ips > 0 or probes > 0:
            alerts.append({
                "source": "log",
                "severity": "high" if auth_fails > 0 else "medium",
                "reason": f"Log anomalies detected: {auth_fails} auth-fail IP(s), {flood_ips} high-volume IP(s), {probes} suspicious path(s).",
            })
            recommended_plans.append("ssh-bruteforce")

    integ = latest_json(os.path.join(reports_dir, "integrity_*.json"))
    if integ:
        ch = integ.get("changes", {})
        if ch.get("modified") or ch.get("added") or ch.get("removed"):
            alerts.append({
                "source": "integrity",
                "severity": "high" if ch.get("modified") else "medium",
                "reason": f"Integrity changes in {integ.get('target_dir')}: {len(ch.get('modified', []))} modified, {len(ch.get('added', []))} added, {len(ch.get('removed', []))} removed.",
            })
            recommended_plans.append("file-tamper")

    and_rep = latest_json(os.path.join(reports_dir, "android_guard_*.json"))
    if and_rep:
        ww = len(and_rep.get("world_writable_files", []))
        sec_hits = len(and_rep.get("potential_secret_exposures", []))
        if ww > 0 or sec_hits > 0:
            alerts.append({
                "source": "android",
                "severity": "high" if sec_hits > 0 else "medium",
                "reason": f"Workspace risk in {and_rep.get('target_path')}: {ww} world-writable file(s), {sec_hits} potential secret hit(s).",
            })
            recommended_plans.append("android-risk")

    unique_plans = sorted(set(recommended_plans))
    overall_risk = "HIGH" if any(a["severity"] == "high" for a in alerts) else ("MEDIUM" if alerts else "LOW")

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "overall_risk": overall_risk,
        "alerts": alerts,
        "recommended_plans": unique_plans,
    }


def save_triage(result: dict, output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"triage_ai_{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    return path


def print_triage(result: dict, out_path: str):
    print("\n================ TRIAGE AI SUMMARY ================")
    print(f"Overall Risk : {result['overall_risk']}")
    print(f"Alerts Found : {len(result['alerts'])}\n")

    if not result["alerts"]:
        print("No active risks detected in latest reports.")
    else:
        for idx, al in enumerate(result["alerts"], start=1):
            print(f"  {idx}. [{al['severity'].upper()}] ({al['source']}) {al['reason']}")

    print("\nRecommended Playbooks:")
    if not result["recommended_plans"]:
        print("  None")
    else:
        for p in result["recommended_plans"]:
            print(f"  * secguard plan {p}")

    print(f"\nSaved        : {out_path}")
    print("===================================================\n")


def main():
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else "reports"
    res = run_triage(reports_dir)
    out_path = save_triage(res, reports_dir)
    print_triage(res, out_path)


if __name__ == "__main__":
    main()
