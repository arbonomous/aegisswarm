"""Cross-platform system health monitor & safe reversible optimizer for AegisSwarm.

Works on Windows, macOS, and Linux with low overhead:
  - Observes CPU, RAM, swap, disk pressure, zombie/runaway processes, and stale temp files.
  - Recommends safe performance improvements and detects internal agent/worker conflicts.
  - Performs reversible temp/cache cleanup by archiving stale files to
    ~/.aegisswarm/cleanup_archive/ rather than permanently deleting them.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from os_adapter import get_os_name, platform_info
from threat_bus import append_incident

_SAFE_TEMP_EXTENSIONS = {".tmp", ".temp", ".log", ".bak", ".dmp", ".cache", ".part"}


@dataclass
class ProcessResourceInfo:
    pid: int
    name: str
    cpu_percent: float
    memory_mb: float
    status: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "name": self.name,
            "cpu_percent": round(self.cpu_percent, 1),
            "memory_mb": round(self.memory_mb, 1),
            "status": self.status,
        }


@dataclass
class HealthSnapshot:
    os_name: str
    cpu_percent: float
    memory_percent: float
    memory_available_mb: float
    disk_percent: float
    disk_free_gb: float
    process_count: int
    zombie_processes: list[ProcessResourceInfo] = field(default_factory=list)
    top_memory: list[ProcessResourceInfo] = field(default_factory=list)
    duplicate_workers: dict[str, int] = field(default_factory=dict)
    captured_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "os": self.os_name,
            "cpu_percent": round(self.cpu_percent, 1),
            "memory_percent": round(self.memory_percent, 1),
            "memory_available_mb": round(self.memory_available_mb, 1),
            "disk_percent": round(self.disk_percent, 1),
            "disk_free_gb": round(self.disk_free_gb, 2),
            "process_count": self.process_count,
            "zombie_processes": [z.as_dict() for z in self.zombie_processes],
            "top_memory": [p.as_dict() for p in self.top_memory],
            "duplicate_workers": self.duplicate_workers,
            "captured_at": self.captured_at,
        }


@dataclass
class OptimizationAction:
    kind: str  # "stale_temp_cleanup" | "memory_pressure" | "disk_pressure" | "zombie_process" | "duplicate_workers"
    severity: str  # "info" | "advisory" | "warning"
    reversible: bool
    summary: str
    recommendation: str
    target_path: str | None = None
    estimated_reclaim_bytes: int = 0
    pid: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "reversible": self.reversible,
            "summary": self.summary,
            "recommendation": self.recommendation,
            "target_path": self.target_path,
            "estimated_reclaim_bytes": self.estimated_reclaim_bytes,
            "pid": self.pid,
        }


def collect_health_snapshot() -> HealthSnapshot:
    """Collect a low-overhead cross-platform system health snapshot."""
    os_name = get_os_name()
    cpu_pct = psutil.cpu_percent(interval=0.05)
    vm = psutil.virtual_memory()
    root_path = os.path.abspath(os.sep)
    disk = psutil.disk_usage(root_path)

    zombies: list[ProcessResourceInfo] = []
    procs: list[ProcessResourceInfo] = []
    name_counts: dict[str, int] = {}

    for proc in psutil.process_iter(["pid", "name", "status", "memory_info"]):
        try:
            info = proc.info
            name = (info.get("name") or "unknown").strip()
            status = str(info.get("status") or "")
            mem_info = info.get("memory_info")
            mem_mb = (mem_info.rss / (1024 * 1024)) if mem_info else 0.0
            entry = ProcessResourceInfo(
                pid=info["pid"],
                name=name,
                cpu_percent=0.0,
                memory_mb=mem_mb,
                status=status,
            )
            procs.append(entry)
            if status == psutil.STATUS_ZOMBIE:
                zombies.append(entry)
            key = name.lower()
            name_counts[key] = name_counts.get(key, 0) + 1
        except (psutil.Error, TypeError):
            continue

    top_mem = sorted(procs, key=lambda p: p.memory_mb, reverse=True)[:5]
    # Flag unusually high duplicate worker counts (potential internal agent/worker conflict)
    dups = {k: v for k, v in name_counts.items() if v >= 12 and k not in {"svchost.exe", "kworker"}}

    return HealthSnapshot(
        os_name=os_name,
        cpu_percent=cpu_pct,
        memory_percent=vm.percent,
        memory_available_mb=vm.available / (1024 * 1024),
        disk_percent=disk.percent,
        disk_free_gb=disk.free / (1024 * 1024 * 1024),
        process_count=len(procs),
        zombie_processes=zombies[:10],
        top_memory=top_mem,
        duplicate_workers=dups,
    )


def default_temp_dirs() -> list[Path]:
    """Return safe user-owned temp directories to scan for stale bloat."""
    candidates = [Path(tempfile.gettempdir())]
    if get_os_name() == "darwin":
        candidates.append(Path.home() / "Library" / "Caches" / "AegisSwarm")
    return [c for c in candidates if c.is_dir()]


def default_cleanup_archive_dir() -> Path:
    custom = os.getenv("AEGIS_CLEANUP_ARCHIVE_DIR")
    if custom:
        return Path(custom).expanduser()
    return Path.home() / ".aegisswarm" / "cleanup_archive"


def analyze_optimizations(
    snapshot: HealthSnapshot,
    *,
    temp_dirs: list[Path] | None = None,
    max_age_hours: float = 24.0,
    scan_limit: int = 25,
) -> list[OptimizationAction]:
    """Identify safe optimizations and resource bottlenecks without touching user data."""
    actions: list[OptimizationAction] = []
    now = time.time()
    cutoff = now - (max_age_hours * 3600.0)

    if snapshot.memory_percent >= 85.0:
        top = snapshot.top_memory[0] if snapshot.top_memory else None
        top_note = f" Top consumer: {top.name} (PID {top.pid}, {top.memory_mb:.0f} MB)." if top else ""
        actions.append(
            OptimizationAction(
                kind="memory_pressure",
                severity="warning",
                reversible=False,
                summary=f"High memory usage ({snapshot.memory_percent:.1f}%).",
                recommendation=f"Close unused heavy tabs/workers to free RAM.{top_note}",
            )
        )

    if snapshot.disk_percent >= 85.0:
        actions.append(
            OptimizationAction(
                kind="disk_pressure",
                severity="warning",
                reversible=False,
                summary=f"Low free disk space ({snapshot.disk_free_gb:.2f} GB free, {snapshot.disk_percent:.1f}% used).",
                recommendation="Run `aegisswarm optimize --apply` to archive stale temp files and review large caches.",
            )
        )

    for z in snapshot.zombie_processes:
        actions.append(
            OptimizationAction(
                kind="zombie_process",
                severity="advisory",
                reversible=False,
                summary=f"Zombie/defunct process detected: {z.name} (PID {z.pid}).",
                recommendation="Reap or restart its parent process to clear stale process table entries.",
                pid=z.pid,
            )
        )

    for name, count in snapshot.duplicate_workers.items():
        actions.append(
            OptimizationAction(
                kind="duplicate_workers",
                severity="advisory",
                reversible=False,
                summary=f"High duplicate worker count: {count} instances of '{name}'.",
                recommendation="Check for runaway agent loops or conflicting background workers.",
            )
        )

    dirs = temp_dirs if temp_dirs is not None else default_temp_dirs()
    found = 0
    for tdir in dirs:
        if not tdir.is_dir():
            continue
        try:
            for item in tdir.iterdir():
                if found >= scan_limit:
                    break
                if item.is_symlink() or not item.is_file():
                    continue
                if item.suffix.lower() not in _SAFE_TEMP_EXTENSIONS:
                    continue
                try:
                    st = item.stat()
                    if st.st_mtime >= cutoff:
                        continue
                    actions.append(
                        OptimizationAction(
                            kind="stale_temp_cleanup",
                            severity="info",
                            reversible=True,
                            summary=f"Stale temp artifact ({st.st_size} bytes): {item.name}",
                            recommendation="Archive to ~/.aegisswarm/cleanup_archive/ (reversible).",
                            target_path=str(item),
                            estimated_reclaim_bytes=st.st_size,
                        )
                    )
                    found += 1
                except OSError:
                    continue
        except OSError:
            continue

    return actions


def apply_safe_cleanup(
    actions: list[OptimizationAction],
    *,
    dry_run: bool = True,
    archive_dir: Path | None = None,
    log_incident: bool = True,
) -> list[dict[str, Any]]:
    """Safely archive stale temp artifacts (reversible). Never deletes user documents."""
    results: list[dict[str, Any]] = []
    dest_root = (archive_dir or default_cleanup_archive_dir()) / datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    for act in actions:
        if act.kind != "stale_temp_cleanup" or not act.target_path:
            continue
        src = Path(act.target_path)
        if dry_run:
            results.append(
                {
                    "action": "DRY_RUN_CLEANUP",
                    "original_path": str(src),
                    "archived_path": None,
                    "reclaimed_bytes": act.estimated_reclaim_bytes,
                    "reversible": True,
                }
            )
            continue
        if not src.is_file():
            continue
        dest_root.mkdir(parents=True, exist_ok=True)
        dest = dest_root / src.name
        if dest.exists():
            dest = dest_root / f"{int(time.time() * 1000)}_{src.name}"
        try:
            shutil.move(str(src), str(dest))
            record = {
                "action": "REVERSIBLE_CLEANUP",
                "original_path": str(src),
                "archived_path": str(dest),
                "reclaimed_bytes": act.estimated_reclaim_bytes,
                "reversible": True,
            }
            results.append(record)
            if log_incident:
                append_incident(
                    {
                        "trigger": "system_optimizer",
                        "verdict": "OPTIMIZED",
                        "headline": f"Archived stale temp file: {src.name}",
                        "executive_summary": f"Moved {src} -> {dest} ({act.estimated_reclaim_bytes} bytes). Reversible.",
                        "action": "REVERSIBLE_CLEANUP",
                        "action_detail": f"Reclaimed {act.estimated_reclaim_bytes} bytes reversibly.",
                        "original_path": str(src),
                        "archived_path": str(dest),
                    }
                )
        except OSError:
            continue
    return results


def restore_cleanup_item(archived_path: str | Path, original_path: str | Path) -> bool:
    """Restore a previously archived temp file back to its original path."""
    src = Path(archived_path)
    dst = Path(original_path)
    if not src.is_file():
        return False
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        return True
    except OSError:
        return False
