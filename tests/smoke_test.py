#!/usr/bin/env python3
"""Lightweight, offline smoke tests for the Cybersecurity Toolkit.

All generated artifacts are written to temporary directories under ``/tmp``
and removed automatically, so the repository stays clean.

Run with::

    python3 tests/smoke_test.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

MODULE_SCRIPTS = (
    "scanners/web/web_audit.py",
    "scanners/net/net_audit.py",
    "monitors/logs/log_guard.py",
    "monitors/integrity/file_guard.py",
    "monitors/android/android_guard.py",
    "tools/report_summary.py",
    "tools/incident_plan.py",
)


def run_command(command, *, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command from the repository root without leaving bytecode behind."""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [str(part) for part in command],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed with exit code {result.returncode}: "
            f"{' '.join(str(part) for part in command)}\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )
    return result


def run_python(script: str, *args, check: bool = True) -> subprocess.CompletedProcess:
    return run_command([sys.executable, REPO_ROOT / script, *args], check=check)


def load_reports(directory: Path, prefix: str) -> list[dict]:
    paths = sorted(directory.glob(f"{prefix}_*.json"))
    return [json.loads(path.read_text(encoding="utf-8")) for path in paths]


class SmokeTests(unittest.TestCase):
    def assert_metadata(self, report: dict, tool: str) -> None:
        self.assertEqual(report.get("tool"), tool)
        self.assertEqual(report.get("status"), "ok")
        self.assertTrue(report.get("summary"), "summary must not be empty")
        timestamp = datetime.fromisoformat(report["timestamp_utc"])
        self.assertIsNotNone(timestamp.tzinfo, "timestamp_utc must include a timezone")

    def test_secguard_help_output(self) -> None:
        result = run_command(["bash", REPO_ROOT / "secguard", "--help"])
        self.assertIn("CYBERSECURITY TOOLKIT", result.stdout)
        self.assertIn("Usage:", result.stdout)
        self.assertIn("secguard <module>", result.stdout)

        dispatcher = run_python("cyber_toolkit.py", "--help")
        self.assertIn("CYBERSECURITY TOOLKIT", dispatcher.stdout)

    def test_all_modules_expose_help(self) -> None:
        for script in MODULE_SCRIPTS:
            with self.subTest(script=script):
                result = run_python(script, "--help")
                self.assertIn("usage:", result.stdout.lower())

    def test_incident_plan_generation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secguard-smoke-", dir="/tmp") as tmp:
            output_dir = Path(tmp) / "reports"
            result = run_python("tools/incident_plan.py", "android-risk", "--output-dir", output_dir)
            self.assertIn("android-risk", result.stdout)

            plans = load_reports(output_dir, "incident_plan_android-risk")
            self.assertEqual(len(plans), 1)
            plan = plans[0]
            self.assert_metadata(plan, "incident_plan")
            self.assertEqual(plan["scenario"], "android-risk")
            self.assertTrue(plan["steps"])

    def test_log_guard_with_sample_log(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secguard-smoke-", dir="/tmp") as tmp:
            root = Path(tmp)
            log_file = root / "sample.log"
            lines = [
                "Nov 21 10:00:00 host sshd[123]: Failed password for invalid user admin "
                "from 192.0.2.10 port 54321 ssh2"
            ] * 6
            lines += [
                f'192.0.2.10 - - [21/Nov/2026:10:0{idx}:00 +0000] '
                '"GET /wp-login.php HTTP/1.1" 404 512'
                for idx in range(4)
            ]
            lines.append(
                '203.0.113.7 - - [21/Nov/2026:10:05:00 +0000] '
                '"GET /index.html HTTP/1.1" 200 1024'
            )
            log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

            output_dir = root / "reports"
            run_python("monitors/logs/log_guard.py", log_file, "3", "--output-dir", output_dir)

            reports = load_reports(output_dir, "log_guard")
            self.assertEqual(len(reports), 1)
            report = reports[0]
            self.assert_metadata(report, "log_guard")
            self.assertEqual(report["total_lines"], len(lines))
            self.assertGreaterEqual(report["high_volume_ips"].get("192.0.2.10", 0), 3)
            self.assertGreaterEqual(report["repeat_auth_failures"].get("192.0.2.10", 0), 3)
            self.assertIn("/wp-login.php", report["suspicious_paths"])

    def test_file_guard_baseline_and_modification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secguard-smoke-", dir="/tmp") as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            config = workspace / "config.txt"
            config.write_text("original content\n", encoding="utf-8")
            output_dir = root / "reports"

            run_python("monitors/integrity/file_guard.py", workspace, "--output-dir", output_dir)
            baseline = load_reports(output_dir, "integrity")[-1]
            self.assert_metadata(baseline, "file_guard")
            self.assertIn("config.txt", baseline["files"])
            self.assertEqual(baseline["changes"], {"added": [], "removed": [], "modified": []})

            config.write_text("modified content\n", encoding="utf-8")
            run_python("monitors/integrity/file_guard.py", workspace, "--output-dir", output_dir)

            reports = load_reports(output_dir, "integrity")
            self.assertEqual(len(reports), 2)
            current = reports[-1]
            self.assert_metadata(current, "file_guard")
            self.assertIn("config.txt", current["changes"]["modified"])

    def test_android_guard_on_temp_workspace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secguard-smoke-", dir="/tmp") as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "creds.txt").write_text(
                'password = "supersecretvalue"\n', encoding="utf-8"
            )
            writable = workspace / "world.txt"
            writable.write_text("public content\n", encoding="utf-8")
            writable.chmod(0o666)

            output_dir = root / "reports"
            run_python("monitors/android/android_guard.py", workspace, "--output-dir", output_dir)

            reports = load_reports(output_dir, "android_guard")
            self.assertEqual(len(reports), 1)
            report = reports[0]
            self.assert_metadata(report, "android_guard")
            self.assertIn("world.txt", report["world_writable_files"])
            self.assertTrue(
                any(hit["type"] == "bearer_or_api_secret"
                    for hit in report["potential_secret_exposures"])
            )

    def test_report_summary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secguard-smoke-", dir="/tmp") as tmp:
            root = Path(tmp)
            output_dir = root / "reports"
            log_file = root / "sample.log"
            log_file.write_text("Failed password from 192.0.2.10\n", encoding="utf-8")

            run_python("tools/incident_plan.py", "file-tamper", "--output-dir", output_dir)
            run_python("monitors/logs/log_guard.py", log_file, "1", "--output-dir", output_dir)
            result = run_python("tools/report_summary.py", output_dir, "--output-dir", output_dir)

            summaries = load_reports(output_dir, "report_summary")
            self.assertEqual(len(summaries), 1)
            summary = summaries[0]
            self.assert_metadata(summary, "report_summary")
            self.assertTrue(summary["reports"]["plan"]["found"])
            self.assertTrue(summary["reports"]["log"]["found"])
            self.assertEqual(summary["reports"]["plan"]["metadata"]["tool"], "incident_plan")
            self.assertIn("[PLAN]", result.stdout)

    def test_cli_forwarding_and_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secguard-smoke-", dir="/tmp") as tmp:
            output_dir = Path(tmp) / "reports"
            run_python("cyber_toolkit.py", "plan", "web-exposure", "--output-dir", output_dir)
            self.assertTrue(load_reports(output_dir, "incident_plan_web-exposure"))

            bad_scenario = run_python("cyber_toolkit.py", "plan", "does-not-exist", check=False)
            self.assertNotEqual(bad_scenario.returncode, 0)
            self.assertIn("[ERROR]", bad_scenario.stderr)

            unknown_module = run_python("cyber_toolkit.py", "unknown", check=False)
            self.assertNotEqual(unknown_module.returncode, 0)
            self.assertIn("[ERROR]", unknown_module.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
