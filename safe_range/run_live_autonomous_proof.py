#!/usr/bin/env python3
"""Live safe-range proof of AegisSwarm's real-time autonomous kill chain:
  detect -> freeze (SIGSTOP/NtSuspendProcess) -> analyze -> eliminate (kill) -> report.

Spawns a harmless disposable canary subprocess that sleeps briefly before
attempting to read .env.canary and exfiltrate to 127.0.0.1:8765.
AegisSwarm catches, freezes, verifies, and terminates the real OS process
before it can complete exfiltration, then prints the forensic incident report.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guardian import GuardianConfig, GuardianDaemon  # noqa: E402
from os_adapter import platform_info  # noqa: E402


def main() -> int:
    marker = "AEGISSWARM_SAFE_CANARY_EXFIL"
    # Harmless disposable child process simulating a rogue agent after a short setup delay.
    rogue_code = (
        "import time, pathlib; "
        f"# {marker}\n"
        "time.sleep(5); "
        "pathlib.Path('safe_range/victim_project/.env.canary').read_text(); "
        "# http://127.0.0.1:8765/collect"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", rogue_code],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stages: list[str] = []

    def on_step(stage: str, _payload: dict) -> None:
        stages.append(stage)

    daemon = GuardianDaemon(
        GuardianConfig(dry_run=False, cmd_scope_filter=marker),
        on_step=on_step,
    )

    t0 = time.monotonic()
    try:
        # Give OS a brief moment to register process cmdline
        time.sleep(0.1)
        incidents = daemon.scan_once()
        elapsed = round(time.monotonic() - t0, 3)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)

    assert len(incidents) == 1, f"Expected 1 incident, got {len(incidents)}"
    inc = incidents[0]
    assert inc["action"] == "ELIMINATED", f"Expected ELIMINATED, got {inc['action']}"
    assert proc.pid in inc["frozen_pids"], "Target PID was not frozen"
    assert proc.pid in inc["killed_pids"], "Target PID was not killed"
    assert elapsed < 3.0, f"Expected kill before 5s sleep, took {elapsed}s"
    assert stages == ["detect", "freeze", "analyze", "eliminate"], f"Unexpected stages: {stages}"

    print(
        json.dumps(
            {
                "proof": "AegisSwarm Live Autonomous Kill-Chain",
                "os": platform_info()["os"],
                "stages": stages,
                "target_pid": proc.pid,
                "elapsed_seconds": elapsed,
                "verdict": inc["verdict"],
                "agent": inc["agent"],
                "threat_score": inc["threat_score"],
                "action": inc["action"],
                "headline": inc["headline"],
                "action_detail": inc["action_detail"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
