#!/usr/bin/env python3
"""AegisSwarm — Universal Autonomous AI Defense Swarm CLI.

Works on Linux, macOS, and Windows:
  python aegisswarm.py patrol [--live | --dry-run] [--once] [--interval 0.25]
  python aegisswarm.py status
  python aegisswarm.py incidents [--limit 10]
  python aegisswarm.py console
  python aegisswarm.py mcp -- <mcp-server-cmd...>
  python aegisswarm.py proof
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from guardian import GuardianConfig, GuardianDaemon
from os_adapter import platform_info
from threat_bus import read_gate_status, read_incidents, read_state

ROOT = Path(__file__).resolve().parent


def _cmd_patrol(args: argparse.Namespace) -> int:
    cfg = GuardianConfig(
        interval_s=args.interval,
        dry_run=not args.live,
        cmd_scope_filter=args.scope,
    )

    def on_step(stage: str, payload: dict) -> None:
        print(f"[aegisswarm:{stage}] {json.dumps(payload, default=str)}", flush=True)

    daemon = GuardianDaemon(cfg, on_step=on_step)
    mode = "LIVE ENFORCE (freeze -> analyze -> eliminate)" if args.live else "DRY-RUN"
    print(
        f"AegisSwarm Guardian starting on {platform_info()['os']} ({platform_info()['machine']}) | mode={mode}",
        flush=True,
    )
    if args.once:
        incidents = daemon.scan_once()
        print(f"Scan complete. Incidents recorded: {len(incidents)}")
        return 0
    daemon.run_forever()
    return 0


def _cmd_status(_args: argparse.Namespace) -> int:
    payload = {
        "platform": platform_info(),
        "state": read_state(),
        "mcp_gate": read_gate_status(),
    }
    print(json.dumps(payload, indent=2, default=str))
    return 0


def _cmd_incidents(args: argparse.Namespace) -> int:
    rows = read_incidents(limit=args.limit)
    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return 0
    if not rows:
        print("No incidents recorded yet.")
        return 0
    for row in rows:
        ts = row.get("eliminated_at") or row.get("logged_at") or ""
        action = row.get("action") or row.get("verdict") or "INFO"
        headline = row.get("headline") or row.get("title") or row.get("rule") or "Event"
        detail = row.get("action_detail") or row.get("executive_summary") or ""
        print(f"[{ts}] {action} | {headline}")
        if detail:
            print(f"    {detail}")
    return 0


def _cmd_console(_args: argparse.Namespace) -> int:
    cmd = [sys.executable, "-m", "streamlit", "run", str(ROOT / "dashboard.py")]
    return subprocess.call(cmd, cwd=str(ROOT))


def _cmd_mcp(args: argparse.Namespace) -> int:
    upstream = list(args.upstream)
    if upstream and upstream[0] == "--":
        upstream = upstream[1:]
    if not upstream:
        print("Usage: python aegisswarm.py mcp -- <mcp-server-cmd...>", file=sys.stderr)
        return 2
    cmd = [sys.executable, str(ROOT / "mcp_proxy.py"), "--", *upstream]
    return subprocess.call(cmd, cwd=str(ROOT))


def _cmd_proof(_args: argparse.Namespace) -> int:
    cmd = [sys.executable, str(ROOT / "safe_range" / "run_live_autonomous_proof.py")]
    return subprocess.call(cmd, cwd=str(ROOT))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aegisswarm",
        description="AegisSwarm — Universal autonomous defense swarm for AI agents.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_patrol = sub.add_parser("patrol", help="Run real-time OS threat patrol.")
    p_patrol.add_argument("--live", action="store_true", help="Actually freeze & eliminate confirmed threats.")
    p_patrol.add_argument("--dry-run", action="store_true", help="Detect & analyze without freezing/killing (default).")
    p_patrol.add_argument("--once", action="store_true", help="Run one sweep and exit.")
    p_patrol.add_argument("--interval", type=float, default=0.25, help="Poll interval in seconds.")
    p_patrol.add_argument("--scope", type=str, default=None, help="Optional cmdline substring filter.")
    p_patrol.set_defaults(func=_cmd_patrol)

    p_status = sub.add_parser("status", help="Show OS capabilities and swarm status.")
    p_status.set_defaults(func=_cmd_status)

    p_inc = sub.add_parser("incidents", help="Show recent forensic incident reports.")
    p_inc.add_argument("--limit", type=int, default=10)
    p_inc.add_argument("--json", action="store_true")
    p_inc.set_defaults(func=_cmd_incidents)

    p_con = sub.add_parser("console", help="Launch cross-platform Streamlit console.")
    p_con.set_defaults(func=_cmd_console)

    p_mcp = sub.add_parser("mcp", help="Wrap an MCP server with fail-closed policy gate.")
    p_mcp.add_argument("upstream", nargs=argparse.REMAINDER)
    p_mcp.set_defaults(func=_cmd_mcp)

    p_proof = sub.add_parser("proof", help="Run live safe-range autonomous kill-chain proof.")
    p_proof.set_defaults(func=_cmd_proof)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
