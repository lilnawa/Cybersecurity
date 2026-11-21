import glob
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

PROFILE = {
    "name": "Alemaz",
    "role": "Defensive Security, Code & Voice Assistant",
    "owner": "lilnawa",
}


def speak_text(text: str):
    clean = text.replace('"', " ").replace("'", " ")[:300]
    if shutil.which("termux-tts-speak"):
        subprocess.run(["termux-tts-speak", clean], check=False)
    elif shutil.which("espeak-ng"):
        subprocess.run(["espeak-ng", clean], check=False)
    elif shutil.which("espeak"):
        subprocess.run(["espeak", clean], check=False)


def latest_json(pattern: str) -> dict | None:
    files = sorted(glob.glob(pattern))
    if not files:
        return None
    with open(files[-1], "r", encoding="utf-8") as f:
        return json.load(f)


def build_context(reports_dir: str = "reports") -> dict:
    return {
        "latest_web": latest_json(os.path.join(reports_dir, "web_audit_*.json")),
        "latest_net": latest_json(os.path.join(reports_dir, "net_audit_*.json")),
        "latest_log": latest_json(os.path.join(reports_dir, "log_guard_*.json")),
        "latest_integrity": latest_json(os.path.join(reports_dir, "integrity_*.json")),
        "latest_android": latest_json(os.path.join(reports_dir, "android_guard_*.json")),
        "latest_triage": latest_json(os.path.join(reports_dir, "triage_ai_*.json")),
    }


def search_skills(topic: str, skills_dir: str = "skills") -> list[dict]:
    q = topic.lower().strip()
    matches = []
    if not os.path.isdir(skills_dir):
        return matches

    for root, _, files in os.walk(skills_dir):
        for fname in sorted(files):
            if not fname.endswith((".md", ".txt")):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except OSError:
                continue

            snippet_lines = []
            for idx, line in enumerate(lines, start=1):
                if q in line.lower() or q in fname.lower():
                    snippet_lines.append(f"L{idx}: {line.strip()}")
                if len(snippet_lines) >= 4:
                    break

            if snippet_lines or q in fname.lower():
                matches.append({
                    "file": os.path.relpath(fpath, "."),
                    "matches": snippet_lines[:4],
                })
    return matches


def generate_code_snippet(task_desc: str) -> str:
    safe_comment = task_desc.replace("\n", " ").strip()
    low = safe_comment.lower()

    if any(k in low for k in ("log", "auth", "failed")):
        body = '''def analyze_lines(lines: list[str]) -> dict:
    failed = [ln.strip() for ln in lines if "failed" in ln.lower() or "denied" in ln.lower()]
    return {"total_lines": len(lines), "failed_matches": len(failed), "sample": failed[:5]}'''
    elif any(k in low for k in ("hash", "sha256", "integrity", "file")):
        body = '''import hashlib


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()'''
    elif any(k in low for k in ("json", "config", "validate")):
        body = '''def validate_config(data: dict, required_keys: list[str]) -> list[str]:
    return [k for k in required_keys if k not in data]'''
    else:
        body = '''def run_task() -> dict:
    return {"status": "ready", "note": "Customize this defensive helper for your authorized task."}'''

    return f'''"""Auto-generated defensive helper by Alemaz AI.
Task: {safe_comment}
Use only on authorized systems and owned projects.
"""

import json
from datetime import datetime, timezone

{body}


if __name__ == "__main__":
    print(json.dumps({{"timestamp_utc": datetime.now(timezone.utc).isoformat(), "task": {json.dumps(safe_comment)}, "status": "ok"}}, indent=2))
'''


def answer_question(question: str, ctx: dict) -> str:
    q = question.lower().strip()
    triage = ctx.get("latest_triage")
    android = ctx.get("latest_android")
    log = ctx.get("latest_log")
    integ = ctx.get("latest_integrity")

    if any(k in q for k in ("risk", "status", "triage", "ሁኔታ", "ስጋት")):
        if triage:
            plans = triage.get("recommended_plans", [])
            return (
                f"Overall risk is {triage.get('overall_risk', 'UNKNOWN')} "
                f"with {len(triage.get('alerts', []))} alert(s). "
                f"Recommended plans: {', '.join(plans) if plans else 'none'}."
            )
        return "No triage report found yet. Run alemaz triage first."

    if any(k in q for k in ("android", "secret", "token", "permission")):
        if android:
            return (
                f"Workspace check: {len(android.get('world_writable_files', []))} world-writable files "
                f"and {len(android.get('potential_secret_exposures', []))} potential secret matches."
            )
        return "No android guard report found yet."

    if any(k in q for k in ("log", "auth", "ssh", "ip")):
        if log:
            return (
                f"Log check: {log.get('total_lines', 0)} lines analyzed, "
                f"{len(log.get('repeat_auth_failures', {}))} repeated auth failure sources."
            )
        return "No log guard report found yet."

    if any(k in q for k in ("file", "integrity", "hash", "modified")):
        if integ:
            ch = integ.get("changes", {})
            return (
                f"File integrity: {len(ch.get('modified', []))} modified, "
                f"{len(ch.get('added', []))} added, {len(ch.get('removed', []))} removed."
            )
        return "No integrity report found yet."

    return f"Alemaz heard: {question}. Ask about risk status, logs, file integrity, or workspace security."


def save_session(entry: dict, output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"alemaz_session_{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2)
    return path


def main():
    args = sys.argv[1:]
    voice = False
    if "--voice" in args:
        voice = True
        args.remove("--voice")

    if not args or args[0] in ("-h", "--help", "help"):
        print("\n================ ALEMAZ AI ================")
        print("  alemaz status [--voice]           -> Latest security risk overview")
        print("  alemaz triage [--voice]           -> Run triage analysis")
        print("  alemaz ask \"<text>\" [--voice]     -> Ask a question about reports")
        print("  alemaz code \"<task>\" [--voice]    -> Generate a defensive Python helper")
        print("  alemaz find \"<topic>\" [--voice]   -> Search skills/playbooks for a topic")
        print("===========================================\n")
        sys.exit(0)

    cmd = args[0].lower()
    if cmd == "triage":
        res = subprocess.run(["python3", "tools/triage_ai.py"])
        if voice:
            speak_text("Triage analysis finished.")
        sys.exit(res.returncode)

    ctx = build_context()
    if cmd == "status":
        reply = answer_question("risk status", ctx)
        print(f"\n[{PROFILE['name']}] {reply}\n")
        if voice:
            speak_text(reply)
        sys.exit(0)

    if cmd == "ask":
        if len(args) < 2:
            print("[ERROR] Provide a question after ask.")
            sys.exit(1)
        question = " ".join(args[1:])
        reply = answer_question(question, ctx)
        saved = save_session({
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "ai": PROFILE["name"],
            "question": question,
            "reply": reply,
        })
        print(f"\n[{PROFILE['name']}] {reply}")
        print(f"[Saved] {saved}\n")
        if voice:
            speak_text(reply)
        sys.exit(0)

    if cmd == "code":
        if len(args) < 2:
            print("[ERROR] Provide a task description after code.")
            sys.exit(1)
        task_desc = " ".join(args[1:])
        code_text = generate_code_snippet(task_desc)
        os.makedirs("reports", exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_file = os.path.join("reports", f"generated_{stamp}.py")
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(code_text)
        msg = f"Generated helper code at {out_file}."
        print(f"\n[{PROFILE['name']}] {msg}\n")
        print(code_text)
        if voice:
            speak_text(msg)
        sys.exit(0)

    if cmd == "find":
        if len(args) < 2:
            print("[ERROR] Provide a topic after find.")
            sys.exit(1)
        topic = " ".join(args[1:])
        hits = search_skills(topic)
        print(f"\n[{PROFILE['name']}] Skill search for '{topic}': {len(hits)} file(s)")
        for h in hits:
            print(f"  - {h['file']}")
            for m in h["matches"]:
                print(f"      {m}")
        print()
        if voice:
            speak_text(f"Found {len(hits)} skill match for {topic}.")
        sys.exit(0)

    print(f"[ERROR] Unknown command '{cmd}'.")
    sys.exit(1)


if __name__ == "__main__":
    main()
