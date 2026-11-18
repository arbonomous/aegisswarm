"""Universal cross-platform OS adapter for AegisSwarm (Linux, macOS, Windows).

Provides real-time process inspection, immediate suspension (freeze),
resumption on false positive, termination (elimination) of confirmed threats,
artifact quarantine, and desktop notifications across all major OSes.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

# Processes that must NEVER be frozen or killed by user-space defense.
_SYSTEM_PROTECTED_NAMES = {
    # Linux
    "systemd",
    "init",
    "kthreadd",
    "dbus-daemon",
    "sshd",
    "containerd",
    "dockerd",
    "agy-plugin-proxy",
    # macOS
    "launchd",
    "kernel_task",
    "windowserver",
    "loginwindow",
    "dock",
    "finder",
    "syslogd",
    "notifyd",
    # Windows
    "system",
    "system idle process",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "explorer.exe",
    "dwm.exe",
}


def get_os_name() -> str:
    """Return normalized OS identifier: 'linux', 'darwin', or 'windows'."""
    sys_name = platform.system().lower()
    if sys_name.startswith("darwin"):
        return "darwin"
    if sys_name.startswith("win"):
        return "windows"
    return "linux"


def platform_info() -> dict[str, Any]:
    """Return universal host capability summary."""
    os_name = get_os_name()
    is_admin = False
    try:
        if os_name == "windows":
            import ctypes  # type: ignore

            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            is_admin = os.geteuid() == 0
    except Exception:
        is_admin = False

    return {
        "os": os_name,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "is_admin": is_admin,
        "freeze_method": "NtSuspendProcess" if os_name == "windows" else "SIGSTOP",
        "kill_method": "TerminateProcess" if os_name == "windows" else "SIGKILL",
    }


def _ancestor_pids(pid: int) -> set[int]:
    ancestors: set[int] = set()
    try:
        proc = psutil.Process(pid)
        for parent in proc.parents():
            ancestors.add(parent.pid)
    except (psutil.Error, OSError):
        pass
    return ancestors


def is_protected_process(
    pid: int,
    name: str | None = None,
    *,
    allowlist_names: set[str] | None = None,
    allowlist_pids: set[int] | None = None,
) -> bool:
    """Return True if process must never be frozen or terminated."""
    if pid <= 1:
        return True
    self_pid = os.getpid()
    if pid == self_pid or pid in _ancestor_pids(self_pid):
        return True
    if allowlist_pids and pid in allowlist_pids:
        return True
    norm_name = (name or "").strip().lower()
    if norm_name in _SYSTEM_PROTECTED_NAMES:
        return True
    if allowlist_names and norm_name in {n.lower() for n in allowlist_names}:
        return True
    return False


@dataclass
class ProcessSnapshot:
    pid: int
    ppid: int
    name: str
    cmdline: list[str]
    exe: str
    cwd: str
    username: str
    open_files: list[str] = field(default_factory=list)
    connections: list[str] = field(default_factory=list)
    captured_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def cmdline_str(self) -> str:
        return " ".join(self.cmdline) if self.cmdline else self.name

    def as_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "cmdline": self.cmdline_str(),
            "exe": self.exe,
            "cwd": self.cwd,
            "username": self.username,
            "open_files": self.open_files[:20],
            "connections": self.connections[:20],
            "captured_at": self.captured_at,
        }


def capture_process_snapshot(pid: int) -> ProcessSnapshot | None:
    """Safely capture forensic details of a running/frozen process."""
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            name = proc.name() or ""
            ppid = proc.ppid()
            try:
                cmdline = proc.cmdline() or []
            except (psutil.AccessDenied, psutil.ZombieProcess):
                cmdline = []
            try:
                exe = proc.exe() or ""
            except (psutil.AccessDenied, psutil.ZombieProcess):
                exe = ""
            try:
                cwd = proc.cwd() or ""
            except (psutil.AccessDenied, psutil.ZombieProcess):
                cwd = ""
            try:
                username = proc.username() or ""
            except (psutil.AccessDenied, psutil.ZombieProcess):
                username = ""
            try:
                open_files = [f.path for f in proc.open_files()[:20]]
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                open_files = []
            try:
                conns = []
                for c in proc.net_connections(kind="inet")[:20]:
                    raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "listening"
                    conns.append(f"{c.type.name}:{raddr} ({c.status})")
            except (psutil.AccessDenied, psutil.ZombieProcess, AttributeError, OSError):
                conns = []
        return ProcessSnapshot(
            pid=pid,
            ppid=ppid,
            name=name,
            cmdline=cmdline,
            exe=exe,
            cwd=cwd,
            username=username,
            open_files=open_files,
            connections=conns,
        )
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


@dataclass
class FreezeResult:
    ok: bool
    frozen_pids: list[int]
    errors: list[str]
    snapshot: ProcessSnapshot | None = None


def freeze_process_tree(pid: int) -> FreezeResult:
    """Immediately suspend target process and its children across Linux/macOS/Windows."""
    frozen: list[int] = []
    errors: list[str] = []
    snapshot = capture_process_snapshot(pid)

    try:
        root = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return FreezeResult(ok=False, frozen_pids=[], errors=[f"PID {pid} no longer exists"], snapshot=snapshot)
    except psutil.AccessDenied:
        return FreezeResult(ok=False, frozen_pids=[], errors=[f"Access denied to PID {pid}"], snapshot=snapshot)

    targets: list[psutil.Process] = []
    try:
        targets.extend(root.children(recursive=True))
    except (psutil.Error, OSError):
        pass
    targets.append(root)

    # Suspend children first, then root, to prevent orphan respawns during freeze.
    for proc in targets:
        try:
            proc.suspend()
            frozen.append(proc.pid)
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied as exc:
            errors.append(f"PID {proc.pid}: access denied ({exc})")
        except psutil.Error as exc:
            errors.append(f"PID {proc.pid}: {exc}")

    return FreezeResult(
        ok=len(frozen) > 0,
        frozen_pids=frozen,
        errors=errors,
        snapshot=snapshot,
    )


def resume_process_tree(pids: list[int]) -> list[int]:
    """Resume previously frozen processes when verified SAFE."""
    resumed: list[int] = []
    for pid in reversed(pids):
        try:
            psutil.Process(pid).resume()
            resumed.append(pid)
        except psutil.Error:
            continue
    return resumed


@dataclass
class KillResult:
    ok: bool
    killed_pids: list[int]
    errors: list[str]


def terminate_process_tree(pids: list[int], timeout: float = 2.0) -> KillResult:
    """Eliminate confirmed threat processes without approval."""
    killed: list[int] = []
    errors: list[str] = []
    procs: list[psutil.Process] = []

    for pid in pids:
        try:
            proc = psutil.Process(pid)
            # Also catch any late-spawned children before killing.
            try:
                for child in proc.children(recursive=True):
                    if child.pid not in pids:
                        procs.append(child)
            except psutil.Error:
                pass
            procs.append(proc)
        except psutil.NoSuchProcess:
            continue

    for proc in procs:
        try:
            proc.kill()
            killed.append(proc.pid)
        except psutil.NoSuchProcess:
            killed.append(proc.pid)
        except psutil.AccessDenied as exc:
            errors.append(f"PID {proc.pid}: access denied ({exc})")
        except psutil.Error as exc:
            errors.append(f"PID {proc.pid}: {exc}")

    psutil.wait_procs(procs, timeout=timeout)
    return KillResult(ok=len(killed) > 0 and not errors, killed_pids=killed, errors=errors)


def default_quarantine_dir() -> Path:
    custom = os.getenv("AEGIS_QUARANTINE_DIR") or os.getenv("SWARMGUARD_QUARANTINE_DIR")
    if custom:
        return Path(custom).expanduser()
    return Path.home() / ".aegisswarm" / "quarantine"


def quarantine_artifact(path: str | Path, quarantine_dir: Path | None = None) -> str | None:
    """Move a suspicious script/artifact into a locked quarantine directory."""
    src = Path(path)
    if not src.is_file():
        return None
    qdir = quarantine_dir or default_quarantine_dir()
    qdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = qdir / f"{stamp}_{src.name}.quarantined"
    try:
        shutil.move(str(src), str(dest))
        if get_os_name() != "windows":
            os.chmod(dest, 0o000)
        return str(dest)
    except OSError:
        return None


def notify(title: str, message: str, level: str = "critical") -> bool:
    """Best-effort cross-platform desktop notification. Never raises."""
    if os.getenv("AEGIS_NO_NOTIFY", "0") == "1":
        return False
    os_name = get_os_name()
    try:
        if os_name == "darwin":
            safe_title = title.replace('"', "'")
            safe_msg = message.replace('"', "'")[:240]
            subprocess.Popen(
                ["osascript", "-e", f'display notification "{safe_msg}" with title "{safe_title}"'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        if os_name == "linux" and shutil.which("notify-send"):
            urgency = "critical" if level == "critical" else "normal"
            subprocess.Popen(
                ["notify-send", "-u", urgency, title, message[:240]],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        if os_name == "windows" and shutil.which("powershell"):
            # Lightweight non-blocking toast / balloon fallback
            safe_msg = message.replace("'", "''")[:200]
            safe_title = title.replace("'", "''")
            ps = (
                "Add-Type -AssemblyName System.Windows.Forms;"
                "$n=New-Object System.Windows.Forms.NotifyIcon;"
                "$n.Icon=[System.Drawing.SystemIcons]::Shield;"
                "$n.Visible=$true;"
                f"$n.ShowBalloonTip(5000,'{safe_title}','{safe_msg}',[System.Windows.Forms.ToolTipIcon]::Warning)"
            )
            subprocess.Popen(
                ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
    except Exception:
        return False
    return False
