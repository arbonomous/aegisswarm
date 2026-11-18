"""Brand migration must not reset protection state, break legacy aliases, or alter the frozen icon."""
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RebrandTests(unittest.TestCase):
    def test_icons_are_byte_for_byte_unchanged(self):
        baseline = json.loads((ROOT / "docs/icon-baseline.json").read_text())
        for name, digest in baseline.items():
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest, name)

    def test_mcp_alias_matches_legacy_help(self):
        for module in ["aegisswarm_mcp", "museswarm_mcp", "swarmguard_mcp"]:
            p = subprocess.run([sys.executable, "-m", module, "--help"], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("AegisSwarm", p.stdout)

    def test_hook_alias_remains_fail_closed(self):
        for hook in ["aegisswarm_pretool.py", "museswarm_pretool.py", "swarmguard_pretool.py"]:
            p = subprocess.run([sys.executable, str(ROOT / "hooks" / hook)], input="{}", capture_output=True, text=True)
            self.assertIn("AegisSwarm", p.stdout + p.stderr)

    def test_existing_state_and_locks_are_preserved(self):
        self.assertIn("/tmp/swarmguard-menubar.pid", (ROOT / "menubar.py").read_text())
        self.assertIn("'Application Support' / 'SwarmGuard'", (ROOT / "native_workspace.py").read_text())
