import subprocess
import sys

MODULES = {
    "web": ["python3", "scanners/web/web_audit.py"],
    "net": ["python3", "scanners/net/net_audit.py"],
    "log": ["python3", "monitors/logs/log_guard.py"],
    "integrity": ["python3", "monitors/integrity/file_guard.py"],
    "android": ["python3", "monitors/android/android_guard.py"],
    "report": ["python3", "tools/report_summary.py"],
}


def show_menu():
    print("\n================ CYBERSECURITY TOOLKIT ================")
    print("  web       -> Audit HTTP headers, TLS, cookies & banners")
    print("  net       -> Port/banner scan with baseline drift check")
    print("  log       -> Analyze logs for auth fails, floods & probes")
    print("  integrity -> SHA-256 directory integrity monitor")
    print("  android   -> Workspace permission & secret-pattern check")
    print("  report    -> Summarize latest reports from reports/")
    print("\nUsage:")
    print("  python3 cyber_toolkit.py <module> [args...]")
    print("Example:")
    print("  python3 cyber_toolkit.py web https://example.com")
    print("  python3 cyber_toolkit.py report")
    print("=======================================================\n")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        show_menu()
        sys.exit(0)

    mod_name = sys.argv[1].lower()
    if mod_name not in MODULES:
        print(f"[ERROR] Unknown module '{mod_name}'. Run without args to see options.")
        sys.exit(1)

    cmd = MODULES[mod_name] + sys.argv[2:]
    completed = subprocess.run(cmd)
    sys.exit(completed.returncode)


if __name__ == "__main__":
    main()
