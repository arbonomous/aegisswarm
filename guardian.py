"""Real-time autonomous defense daemon for AegisSwarm.

Implements the universal 4-stage kill chain across Linux, macOS, and Windows:
  1. DETECT:   Spot suspicious agent/process behavior in real time.
  2. FREEZE:   Immediately suspend the process tree (SIGSTOP / NtSuspendProcess).
  3. ANALYZE:  Run the AegisSwarm council (Bloodhound, Wiretap, Overwatch) on the
               frozen snapshot to verify whether it is a genuine threat.
  4. ELIMINATE & REPORT:
               - If CRITICAL THREAT: kill process tree without approval,
                 quarantine staged artifacts, log forensic report, notify user.
               - If SAFE: immediately resume process tree and log clearance.
"""

from __future__ import annotations

import signal
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import psutil

from os_adapter import (
    ProcessSnapshot,
    capture_process_snapshot,
    freeze_process_tree,
    is_protected_process,
    notify,
    platform_info,
    quarantine_artifact,
    resume_process_tree,
    terminate_process_tree,
)
from swarm_analyzer import SwarmVerdict, analyze_snapshot
from threat_bus import append_incident, raise_threat, reset_to_safe

StepFn = Callable[[str, dict[str, Any]], None]

# Fast pre-filter triggers before freezing a process.
# Keeping this focused prevents freezing every benign compiler/editor process.
FAST_SUSPECT_HINTS = (
    ".env.canary",
    "id_rsa",
    "id_ed25519",
    "webhook.site",
    "ngrok",
    "requestbin",
    "pipedream",
    "127.0.0.1:8765",
    "exfiltrat",
    "base64 -d",
    "base64 --decode",
    "powershell -enc",
    "nc -e",
    "bash -i >& /dev/tcp",
    "cat .env",
    "ignore previous instructions",
)


def looks_suspicious(snapshot: ProcessSnapshot) -> list[str]:
    """Fast pre-freeze trigger check. Returns matched trigger hints."""
    blob = " ".join(
        [
            snapshot.name,
            snapshot.cmdline_str(),
            *snapshot.open_files,
            *snapshot.connections,
        ]
    ).lower()
    return [h for h in FAST_SUSPECT_HINTS if h in blob]


@dataclass
class GuardianConfig:
    interval_s: float = 0.25
    dry_run: bool = False
    allowlist_names: set[str] = field(default_factory=set)
    allowlist_pids: set[int] = field(default_factory=set)
    quarantine_dir: Path | None = None
    # Optional filter for safe-range testing so only matching cmdlines are targeted.
    cmd_scope_filter: str | None = None


class GuardianDaemon:
    def __init__(
        self,
        config: GuardianConfig | None = None,
        *,
        on_step: StepFn | None = None,
    ) -> None:
        self.config = config or GuardianConfig()
        self.on_step = on_step
        self._stop = False
        self._inspected: dict[int, str] = {}

    def stop(self) -> None:
        self._stop = True

    def _emit(self, stage: str, payload: dict[str, Any]) -> None:
        if self.on_step:
            self.on_step(stage, payload)

    def _handle_suspect(
        self, snapshot: ProcessSnapshot, triggers: list[str]
    ) -> dict[str, Any]:
        pid = snapshot.pid
        self._emit(
            "detect",
            {
                "pid": pid,
                "name": snapshot.name,
                "cmdline": snapshot.cmdline_str(),
                "triggers": triggers,
            },
        )

        # Stage 2: FREEZE immediately
        frozen_pids: list[int] = [pid]
        freeze_errors: list[str] = []
        if not self.config.dry_run:
            fres = freeze_process_tree(pid)
            frozen_pids = fres.frozen_pids or [pid]
            freeze_errors = fres.errors
            if fres.snapshot:
                snapshot = fres.snapshot
            self._emit(
                "freeze",
                {
                    "pid": pid,
                    "frozen_pids": frozen_pids,
                    "ok": fres.ok,
                    "errors": freeze_errors,
                },
            )
            raise_threat(
                agent="AegisSwarm",
                threat_score=75,
                verdict="FREEZING_FOR_ANALYSIS",
                summary=f"Froze PID {pid} ({snapshot.name}) for swarm verification.",
                pid=pid,
                scenario=f"Live detection: {', '.join(triggers[:3])}",
                last_action="freeze_process_tree",
            )
        else:
            self._emit("freeze_dry_run", {"pid": pid, "frozen_pids": frozen_pids})

        # Stage 3: ANALYZE while frozen
        verdict: SwarmVerdict = analyze_snapshot(snapshot)
        self._emit("analyze", verdict.as_dict())

        # Stage 4: ELIMINATE or RESUME + REPORT
        if verdict.verdict != "CRITICAL THREAT":
            if not self.config.dry_run:
                resumed = resume_process_tree(frozen_pids)
                reset_to_safe(
                    note=f"Cleared PID {pid} ({snapshot.name}) after inspection; resumed {resumed}.",
                    last_action="false_positive_resumed",
                )
            incident = {
                "trigger": "realtime_guardian",
                "simulation": self.config.dry_run,
                "os": platform_info()["os"],
                "pid": pid,
                "process_name": snapshot.name,
                "cmdline": snapshot.cmdline_str(),
                "verdict": "SAFE",
                "threat_score": verdict.threat_score,
                "agent": verdict.agent_triggered,
                "headline": f"Cleared & resumed PID {pid} ({snapshot.name})",
                "executive_summary": verdict.executive_summary,
                "action": "RESUMED_SAFE",
                "action_detail": (
                    f"Process PID {pid} was frozen, verified benign by AegisSwarm, and resumed."
                ),
                "analysis_source": verdict.analysis_source,
                "resolved_at": datetime.now(timezone.utc).isoformat(),
            }
            append_incident(incident)
            self._emit("resume", incident)
            return incident

        # Confirmed threat -> eliminate completely without asking
        killed_pids: list[int] = []
        kill_errors: list[str] = []
        quarantined_path: str | None = None

        if not self.config.dry_run:
            kres = terminate_process_tree(frozen_pids)
            killed_pids = kres.killed_pids
            kill_errors = kres.errors

            # Quarantine script file if cmdline points to a local script
            for token in snapshot.cmdline[1:4]:
                p = Path(token)
                if p.is_file() and p.suffix in {".py", ".sh", ".ps1", ".js", ".bat"}:
                    quarantined_path = quarantine_artifact(
                        p, quarantine_dir=self.config.quarantine_dir
                    )
                    if quarantined_path:
                        break

        action_label = "DRY_RUN_WOULD_ELIMINATE" if self.config.dry_run else "ELIMINATED"
        action_detail = (
            f"Dry-run: would kill PIDs {frozen_pids}."
            if self.config.dry_run
            else f"Frozen PIDs {frozen_pids} -> verified threat -> killed PIDs {killed_pids} without approval."
        )
        if quarantined_path:
            action_detail += f" Quarantined artifact to {quarantined_path}."

        incident = {
            "trigger": "realtime_guardian",
            "simulation": self.config.dry_run,
            "os": platform_info()["os"],
            "pid": pid,
            "ppid": snapshot.ppid,
            "process_name": snapshot.name,
            "cmdline": snapshot.cmdline_str(),
            "cwd": snapshot.cwd,
            "connections": snapshot.connections,
            "verdict": verdict.verdict,
            "threat_score": verdict.threat_score,
            "agent": verdict.agent_triggered,
            "headline": verdict.headline,
            "executive_summary": verdict.executive_summary,
            "recommended_action": verdict.recommended_action,
            "evidence_quotes": verdict.evidence_quotes,
            "findings": [f.as_dict() for f in verdict.findings],
            "action": action_label,
            "action_detail": action_detail,
            "frozen_pids": frozen_pids,
            "killed_pids": killed_pids,
            "quarantined_path": quarantined_path,
            "errors": freeze_errors + kill_errors,
            "analysis_source": verdict.analysis_source,
            "eliminated_at": datetime.now(timezone.utc).isoformat(),
        }
        append_incident(incident)
        self._emit("eliminate", incident)

        if not self.config.dry_run:
            notify(
                "AegisSwarm Neutralized Threat",
                f"{verdict.headline}: killed PID {pid} ({snapshot.name}).",
                level="critical",
            )
            reset_to_safe(
                note=f"NEUTRALIZED · {verdict.headline}",
                last_action="autonomous_elimination",
            )
        return incident

    def scan_once(self) -> list[dict[str, Any]]:
        """Perform one real-time sweep across all active OS processes."""
        incidents: list[dict[str, Any]] = []
        active_pids: set[int] = set()

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                name = proc.info.get("name") or ""
            except (psutil.Error, TypeError):
                continue

            active_pids.add(pid)
            if is_protected_process(
                pid,
                name,
                allowlist_names=self.config.allowlist_names,
                allowlist_pids=self.config.allowlist_pids,
            ):
                continue

            snapshot = capture_process_snapshot(pid)
            if snapshot is None:
                continue

            cmd_str = snapshot.cmdline_str()
            if self.config.cmd_scope_filter and self.config.cmd_scope_filter not in cmd_str:
                continue

            sig = f"{cmd_str}|{' '.join(snapshot.connections[:3])}"
            if self._inspected.get(pid) == sig:
                continue

            triggers = looks_suspicious(snapshot)
            self._inspected[pid] = sig
            if not triggers:
                continue

            incidents.append(self._handle_suspect(snapshot, triggers))

        # Prune exited PIDs from cache
        for stale in list(self._inspected.keys()):
            if stale not in active_pids:
                self._inspected.pop(stale, None)

        return incidents

    def run_forever(self) -> None:
        """Run the autonomous real-time patrol loop until stopped."""
        reset_to_safe(
            note=f"AegisSwarm guardian armed on {platform_info()['os']}.",
            last_action="guardian_armed",
        )

        def _handle_sig(_signum: int, _frame: Any) -> None:
            self.stop()

        try:
            signal.signal(signal.SIGINT, _handle_sig)
            signal.signal(signal.SIGTERM, _handle_sig)
        except ValueError:
            # Not in main thread
            pass

        while not self._stop:
            self.scan_once()
            time.sleep(max(0.05, self.config.interval_s))
