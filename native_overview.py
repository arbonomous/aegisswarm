"""Plain-language native dashboard detail model. No browser imports or model calls."""
from __future__ import annotations
import json
from policy import enforce_enabled, probe_catalog_enforcement
from threat_bus import read_gate_status, read_incidents, read_state
from threat_model import coverage_rows, summary_counts


def section_text(section: str) -> str:
    gate = read_gate_status()
    if section == 'Overview':
        return _overview_text()
    if section == 'Activity':
        rows = read_incidents(25)
        if not rows:
            return (
                "RECENT ACTIVITY\n\n"
                "Nothing suspicious has been blocked yet.\n"
                "When AegisSwarm freezes and stops a threat, a plain-English summary will appear here."
            )
        return "RECENT ACTIVITY\n\n" + "\n\n".join(_friendly_activity(row) for row in rows)
    if section == 'Mac Health & Cleanup':
        return _health_text()
    if section == 'Test Blocking':
        return (
            "TEST THREAT BLOCKING\n\n"
            "Want to see AegisSwarm in action? Click 'Test Threat Blocking' above.\n\n"
            "What it does:\n"
            "1. Starts a harmless fake intruder program on your Mac.\n"
            "2. AegisSwarm spots it, freezes it in place, and verifies it is dangerous.\n"
            "3. Stops it completely in under a second before it can touch any files.\n\n"
            "100% safe — no real files or personal data are ever touched."
        )
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
                f"CPU {snap.cpu_percent:.1f}% | RAM {snap.memory_percent:.1f}% | "
                f"Disk {snap.disk_percent:.1f}% | Advisories: {len(advisories)}"
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


def _overview_text() -> str:
    try:
        import menubar
        running = menubar.guardian_running()
    except Exception:
        running = False
    prot = "ON — Actively watching your Mac in real time." if running else "OFF — Click 'Turn On Protection' above to start watching your Mac."
    rows = read_incidents(20)
    threats = [r for r in rows if str(r.get("action") or "").upper() in ("ELIMINATED", "BLOCKED")]
    health_summary = "Checking..."
    tips_count = 0
    try:
        from system_optimizer import collect_health_snapshot, analyze_optimizations
        snap = collect_health_snapshot()
        advisories = analyze_optimizations(snap)
        tips_count = len(advisories)
        health_summary = (
            f"Processor (CPU): {snap.cpu_percent:.0f}% used\n"
            f"Memory (RAM): {snap.memory_percent:.0f}% used\n"
            f"Storage (Disk): {snap.disk_percent:.0f}% full ({snap.disk_free_gb:.1f} GB free)"
        )
    except Exception:
        pass
    return (
        f"LIVE PROTECTION\n{prot}\n\n"
        f"MAC HEALTH\n{health_summary}\n"
        f"Cleanup & speed tips: {tips_count} item(s) found\n\n"
        f"RECENT THREATS STOPPED\n"
        + (f"{len(threats)} threat(s) stopped recently. Switch to 'Activity' to see what happened."
           if threats else "All clear — no threats stopped recently.")
    )


def _health_text() -> str:
    try:
        from system_optimizer import collect_health_snapshot, analyze_optimizations
        snap = collect_health_snapshot()
        advisories = analyze_optimizations(snap)
    except Exception as exc:
        return f"Could not read Mac health right now ({type(exc).__name__})."
    lines = [
        "YOUR MAC'S HEALTH",
        f"• Processor (CPU): {snap.cpu_percent:.1f}% used",
        f"• Memory (RAM): {snap.memory_percent:.1f}% used ({snap.memory_available_mb:.0f} MB free)",
        f"• Storage (Disk): {snap.disk_percent:.1f}% full ({snap.disk_free_gb:.1f} GB free)",
        f"• Running programs: {snap.process_count}",
        "",
        f"WHAT WE FOUND ({len(advisories)} tip(s)):",
    ]
    if not advisories:
        lines.append("Your Mac looks clean and healthy — nothing needs attention right now.")
    else:
        for i, adv in enumerate(advisories, 1):
            lines.append(f"{i}. {adv.summary}")
            lines.append(f"   Tip: {adv.recommendation}")
        lines.append("")
        lines.append("Click 'Clean Up Mac' above to safely archive junk files (you can always undo it).")
    return "\n".join(lines)


def _friendly_activity(row: dict) -> str:
    action = str(row.get("action") or "").upper()
    headline = str(row.get("headline") or row.get("title") or "Security event")
    detail = str(row.get("action_detail") or row.get("executive_summary") or "")
    when = str(row.get("timestamp") or row.get("ts") or "")
    badge = "STOPPED THREAT" if action == "ELIMINATED" else ("CLEANED" if action == "OPTIMIZED" else "CHECK")
    parts = [f"[{badge}] {headline}"]
    if detail:
        parts.append(f"  What happened: {detail}")
    if when:
        parts.append(f"  When: {when}")
    return "\n".join(parts)


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
