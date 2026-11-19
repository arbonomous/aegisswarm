"""Plain-language native dashboard detail model. No browser imports or model calls."""
from __future__ import annotations
import json
from policy import enforce_enabled, probe_catalog_enforcement
from threat_bus import read_gate_status, read_incidents, read_state
from threat_model import coverage_rows, summary_counts


def section_text(section: str) -> str:
    gate = read_gate_status()
    if section == 'Status':
        try:
            from swarm_brain import api_status
            api = api_status()
            ai = 'Set, not live-verified' if api.get('configured') else 'Missing (heuristic council active)'
        except ImportError:
            ai = 'Heuristic council active'
        health_line = 'Unavailable'
        try:
            from system_optimizer import collect_health_snapshot, analyze_optimizations
            snap = collect_health_snapshot()
            advisories = analyze_optimizations(snap)
            health_line = (
                f"CPU {snap['cpu_percent']}% | RAM {snap['memory_percent']}% | "
                f"Disk {snap['disk_percent']}% | Advisories: {len(advisories)}"
            )
        except Exception:
            pass
        return ('AEGISSWARM AUTONOMOUS DEFENSE & HEALTH\n'
                'Policy configuration: ' + ('On' if enforce_enabled() else 'Off') +
                '\nMCP gate: ' + ('Wrapping tools' if gate.get('wrapping') else 'Idle') +
                '\nSystem health: ' + health_line +
                '\nAI key: ' + ai + '\nLogged incidents: ' + str(len(read_incidents(100))) +
                '\n\nUse the menu bar to Start/Stop Live Guardian (real-time process freeze -> council verify -> eliminate) or run System Health & Clean.\n\n' +
                str(gate.get('note') or 'No active MCP connection confirmed.'))
    if section == 'Attack catalog':
        counts = summary_counts()
        rows = coverage_rows()
        return ('CATALOG, NOT A PREVENTION RATE\n' + json.dumps(counts, indent=2) +
                '\n\nRules require connected hooks/tools. Analysis is not a host block.\n\n' +
                '\n\n'.join('\n'.join(f'{k}: {v}' for k,v in row.items()) for row in rows))
    if section == 'Policy checks':
        probes = probe_catalog_enforcement()
        return ('SYNTHETIC INPUTS ONLY\nNo actual host attack was attempted.\n\n' +
                '\n'.join(('PASS' if row['ok'] else 'FAIL') + ': ' + str(row['threat_id']) + ' | ' + str(row['rule']) for row in probes))
    if section == 'Activity and evidence':
        rows = read_incidents(100)
        return ('RECENT ACTIVITY AND EVIDENCE\n\n' +
                ('\n\n'.join(_activity(row) for row in rows) if rows else 'No logged incidents.'))
    if section == 'Latest analysis':
        return ('LATEST LOCAL STATE\n\n' +
                json.dumps(read_state(), indent=2, ensure_ascii=False))
    return ('HOW AEGISSWARM WORKS\n\n1. Live Guardian monitors processes in real time across macOS, Windows, and Linux.\n2. Suspect threats are frozen immediately (SIGSTOP / NtSuspendProcess) before completing exfiltration.\n3. Multi-agent council (Bloodhound, Wiretap, Overwatch) verifies and eliminates confirmed threats or resumes benign processes.\n4. System Optimizer monitors CPU/RAM/disk bottlenecks and performs reversible temp cleanup.\n5. Connected IDE hooks and MCP tools enforce policy on routed tool calls.\n\nModel settings:\n' + _model_settings())


def _activity(row: dict) -> str:
    title = str(row.get('headline') or row.get('title') or 'Logged activity')
    summary = str(row.get('action_detail') or row.get('executive_summary') or '')
    detail = json.dumps({k:v for k,v in row.items() if k not in ('headline','title','action_detail','executive_summary')}, indent=2, ensure_ascii=False)
    return title + '\n' + summary + '\nDetails:\n' + detail


def _model_settings() -> str:
    try:
        from swarm_brain import api_status
        data=api_status()
        return '\n'.join(key + ': ' + str(data.get(key) or 'unset') for key in ('guard_model','forensic_model','sam_model'))
    except ImportError:
        return 'Analysis dependencies unavailable in this Python environment.'
