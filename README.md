# AegisSwarm

<p align="center">
  <img src="assets/brand/swarmguard-mark.png" alt="AegisSwarm" width="128" />
</p>

**Universal Autonomous AI Defense Swarm** — real-time protection against rogue or hijacked AI agents across **Linux, macOS, and Windows**.

AegisSwarm polices your machine in real time using a four-stage autonomous loop:
1. **Detect** — Monitors active processes, command lines, open secret surfaces, and network egress in real time (`guardian.py`), plus pre-execution IDE hooks (`hooks/aegisswarm_pretool.py`) and an MCP stdio policy proxy (`mcp_proxy.py`).
2. **Freeze** — Immediately suspends the suspect process tree (`SIGSTOP` on Linux/macOS, `NtSuspendProcess` on Windows via `os_adapter.py`) before it can exfiltrate secrets or finish destructive actions.
3. **Analyze** — Runs the three-agent verification council (`swarm_analyzer.py`: **Bloodhound** for secrets, **Wiretap** for network egress, **Overwatch** for obfuscation/injection) on the frozen snapshot—100% offline/deterministic by default, with optional model-agnostic LLM verification (`AEGIS_LLM_VERIFY=1`).
4. **Eliminate & Report** — If confirmed `CRITICAL THREAT`, kills the process tree without asking for approval, quarantines staged malicious scripts, writes a forensic incident report to `incidents.jsonl`, and sends a cross-platform desktop notification. If verified `SAFE`, immediately resumes the process.

```
Live OS Processes / Network  ──▶  guardian.py (detect -> freeze -> analyze -> eliminate/resume)
Cursor / Claude Code         ──▶  IDE hook (hooks/aegisswarm_pretool.py)
Agent MCP tools              ──▶  MCP proxy (mcp_proxy.py)
                                        │
                                        ▼
                       threat_bus.py + CLI / Console / Desktop Notify
```

## Quick Start (Linux, macOS, Windows)

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows:     .venv\Scripts\activate
pip install -r requirements.txt
```

### Run the Universal CLI (`aegisswarm.py`)

```bash
# 1. Prove the live OS kill-chain safely (spawns a disposable canary & terminates it)
python aegisswarm.py proof

# 2. Run a dry-run sweep of your machine
python aegisswarm.py patrol --dry-run --once

# 3. Run the live autonomous guardian daemon (freeze -> analyze -> eliminate -> report)
python aegisswarm.py patrol --live

# 4. Inspect platform status & forensic incident reports
python aegisswarm.py status
python aegisswarm.py incidents

# 5. Launch the cross-platform web console
python aegisswarm.py console

# 6. Wrap any MCP server with the fail-closed policy gate
python aegisswarm.py mcp -- python safe_range/fake_mcp_upstream.py
```

### Optional Model-Agnostic LLM Second Opinion

AegisSwarm works **100% offline** with deterministic policy + specialist heuristics. To enable optional LLM verification of frozen suspects with any OpenAI-compatible endpoint (OpenAI, local Ollama, etc.):

```bash
export AEGIS_LLM_VERIFY=1
export AEGIS_API_KEY="your-key"
export AEGIS_BASE_URL="https://api.openai.com/v1"
export AEGIS_MODEL="gpt-4o-mini"
```

## Honest OS & Privilege Boundaries

* **Same-user / unprivileged mode:** AegisSwarm can inspect, `suspend()`, `resume()`, and `kill()` any process owned by your user account without root/Administrator privileges. Processes running as `root`/`SYSTEM` or protected OS daemons (`systemd`, `launchd`, `svchost.exe`, etc.) are never touched.
* **Sub-millisecond short-lived commands:** User-space `psutil` polling catches active/long-lived rogue agents and anything caught during execution; pre-execution blocking of instant commands (`cat .env`) is handled by the **IDE hooks** (`.cursor/hooks.json`, `.claude/settings.json`) and **MCP proxy** (`mcp_proxy.py`).

## IDE Hooks & MCP Proxy

| Surface | Path |
| :--- | :--- |
| Primary CLI | `aegisswarm.py` |
| OS Adapter (Linux/macOS/Windows) | `os_adapter.py` |
| Swarm Analyzer | `swarm_analyzer.py` |
| Autonomous Guardian Daemon | `guardian.py` |
| Hook script | `hooks/aegisswarm_pretool.py` |
| Cursor project hooks | `.cursor/hooks.json` (`failClosed: true`) |
| Claude Code project hooks | `.claude/settings.json` |
| MCP Proxy package | `python -m aegisswarm_mcp -- <cmd>` |

## Verification & Tests

```bash
python -m unittest discover -s tests -v
python safe_range/run_live_autonomous_proof.py
python safe_range/run_enforcement_demo.py
python safe_range/run_mcp_gate_demo.py
python safe_range/run_ide_hook_demo.py
```

## Configuration Compatibility

Legacy `museswarm_mcp`, `swarmguard_mcp`, `hooks/museswarm_pretool.py`, `hooks/swarmguard_pretool.py`, and `SWARMGUARD_*` environment variables remain supported as aliases.
