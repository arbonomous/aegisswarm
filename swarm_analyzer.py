"""AegisSwarm multi-agent threat verification council.

Analyzes a frozen process snapshot (or intercepted agent action) using three
specialist agents before deciding whether to eliminate or resume:
  - Bloodhound: secret files, keychains, credentials, wallets
  - Wiretap: outbound exfiltration, webhooks, reverse shells, C2 egress
  - Overwatch: obfuscated execution, destructive commands, prompt-injection hijack

Deterministic policy + heuristics run first in <1ms with zero API spend.
Optional LLM verification can be enabled via AEGIS_LLM_VERIFY=1 with any
OpenAI-compatible endpoint (OpenAI, local Ollama, Anthropic-compatible proxy, etc.).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from os_adapter import ProcessSnapshot
from policy import evaluate_tool_call

# Additional behavioral indicators for live OS processes
_OBFUSCATION_RE = re.compile(
    r"(base64\s+-d|base64\s+--decode|powershell\s+-enc|frombase64string|"
    r"curl\s+[^|]+\|\s*(ba)?sh|wget\s+[^|]+\|\s*(ba)?sh|"
    r"python[0-9.]*\s+-c\s+['\"].*(urllib|requests|socket|subprocess|pty\.spawn)|"
    r"eval\s*\(\s*base64|nc\s+-e\s+/bin/(ba)?sh)",
    re.I,
)

_EXFIL_URL_RE = re.compile(
    r"(webhook\.site|ngrok\.|pipedream|requestbin|burpcollaborator|"
    r"transfer\.sh|pastebin\.com|discord\.com/api/webhooks|api\.telegram\.org/bot|"
    r"127\.0\.0\.1:8765)",
    re.I,
)

_SECRET_HINTS = (
    ".env",
    ".env.canary",
    "id_rsa",
    "id_ed25519",
    ".ssh/",
    "credentials.json",
    ".aws/credentials",
    ".kube/config",
    ".git-credentials",
    ".netrc",
    "login data",
    "keychain",
    "wallet",
    "seed.txt",
)

_INJECTION_MARKERS = (
    "ignore previous instructions",
    "system override",
    "exfiltrate",
    "send to attacker",
    "disregard prior",
    "hidden instruction",
)


@dataclass
class AgentFinding:
    agent: str
    role: str
    score: int
    verdict: str  # "SAFE" | "CRITICAL THREAT"
    reason: str
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "role": self.role,
            "score": self.score,
            "verdict": self.verdict,
            "reason": self.reason,
            "evidence": self.evidence,
        }


@dataclass
class SwarmVerdict:
    verdict: str  # "SAFE" | "CRITICAL THREAT"
    threat_score: int
    agent_triggered: str
    headline: str
    executive_summary: str
    recommended_action: str
    evidence_quotes: list[str]
    findings: list[AgentFinding]
    analysis_source: str = "deterministic+swarm_heuristics"

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "threat_score": self.threat_score,
            "agent_triggered": self.agent_triggered,
            "headline": self.headline,
            "executive_summary": self.executive_summary,
            "recommended_action": self.recommended_action,
            "evidence_quotes": self.evidence_quotes,
            "findings": [f.as_dict() for f in self.findings],
            "analysis_source": self.analysis_source,
        }


def _evaluate_bloodhound(snapshot: ProcessSnapshot) -> AgentFinding:
    blob = " ".join(
        [snapshot.cmdline_str(), snapshot.cwd, *snapshot.open_files]
    ).lower()
    hits = [h for h in _SECRET_HINTS if h in blob]
    policy_verdict = evaluate_tool_call("bash", {"command": snapshot.cmdline_str()})

    evidence: list[str] = []
    if hits:
        evidence.extend(f"secret_surface:{h}" for h in hits[:5])
    if policy_verdict.decision == "deny" and policy_verdict.threat_id in {
        "secret_files",
        "git_creds",
        "env_dump",
    }:
        evidence.append(f"policy:{policy_verdict.rule}")

    if evidence:
        score = 92 if policy_verdict.decision == "deny" else 82
        return AgentFinding(
            agent="Bloodhound",
            role="Secret & Filesystem Guard",
            score=score,
            verdict="CRITICAL THREAT",
            reason=f"Process accessed or targeted sensitive credential surface ({', '.join(evidence[:3])}).",
            evidence=evidence,
        )
    return AgentFinding(
        agent="Bloodhound",
        role="Secret & Filesystem Guard",
        score=0,
        verdict="SAFE",
        reason="No sensitive credential or secret file access detected.",
    )


def _evaluate_wiretap(snapshot: ProcessSnapshot) -> AgentFinding:
    cmd = snapshot.cmdline_str()
    blob = " ".join([cmd, *snapshot.connections]).lower()
    evidence: list[str] = []

    url_match = _EXFIL_URL_RE.search(blob)
    if url_match:
        evidence.append(f"egress_sink:{url_match.group(0)}")

    policy_verdict = evaluate_tool_call("bash", {"command": cmd})
    if policy_verdict.decision == "deny" and policy_verdict.threat_id in {
        "network_exfil",
        "reverse_shell",
        "canary_exfil",
    }:
        evidence.append(f"policy:{policy_verdict.rule}")

    if snapshot.connections and any(h in cmd.lower() for h in _SECRET_HINTS):
        evidence.append(f"active_socket_with_secret:{snapshot.connections[0]}")

    if evidence:
        score = 95 if len(evidence) >= 2 or policy_verdict.decision == "deny" else 84
        return AgentFinding(
            agent="Wiretap",
            role="Network & Exfiltration Guard",
            score=score,
            verdict="CRITICAL THREAT",
            reason=f"Suspicious network egress or exfiltration channel detected ({', '.join(evidence[:3])}).",
            evidence=evidence,
        )
    return AgentFinding(
        agent="Wiretap",
        role="Network & Exfiltration Guard",
        score=0,
        verdict="SAFE",
        reason="No unauthorized outbound exfiltration or C2 socket detected.",
    )


def _evaluate_overwatch(snapshot: ProcessSnapshot) -> AgentFinding:
    cmd = snapshot.cmdline_str()
    lower = cmd.lower()
    evidence: list[str] = []

    obf = _OBFUSCATION_RE.search(cmd)
    if obf:
        evidence.append(f"obfuscated_exec:{obf.group(0)[:60]}")

    for marker in _INJECTION_MARKERS:
        if marker in lower:
            evidence.append(f"injection_marker:{marker}")

    policy_verdict = evaluate_tool_call("bash", {"command": cmd})
    if (
        policy_verdict.decision == "deny"
        and policy_verdict.rule not in {"deny_unknown_cmd", "deny_unknown_tool", "deny_unknown_path"}
        and policy_verdict.threat_id
        not in {
            "secret_files",
            "git_creds",
            "env_dump",
            "network_exfil",
            "reverse_shell",
            "canary_exfil",
        }
    ):
        evidence.append(f"policy:{policy_verdict.rule}")

    if evidence:
        score = 90 if policy_verdict.decision == "deny" or obf else 80
        return AgentFinding(
            agent="Overwatch",
            role="Behavioral & Injection Guard",
            score=score,
            verdict="CRITICAL THREAT",
            reason=f"Hostile execution pattern or prompt-hijack signature detected ({', '.join(evidence[:3])}).",
            evidence=evidence,
        )
    return AgentFinding(
        agent="Overwatch",
        role="Behavioral & Injection Guard",
        score=0,
        verdict="SAFE",
        reason="No obfuscated payload, destructive command, or injection marker detected.",
    )


def _optional_llm_verify(snapshot: ProcessSnapshot, local_verdict: SwarmVerdict) -> SwarmVerdict:
    """Optional model-agnostic LLM second opinion when AEGIS_LLM_VERIFY=1."""
    if os.getenv("AEGIS_LLM_VERIFY", "0").strip().lower() not in {"1", "true", "yes"}:
        return local_verdict

    api_key = (
        os.getenv("AEGIS_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or os.getenv("MODEL_API_KEY")
        or ""
    ).strip()
    if not api_key:
        return local_verdict

    base_url = (
        os.getenv("AEGIS_BASE_URL")
        or os.getenv("OPENAI_BASE_URL")
        or "https://api.openai.com/v1"
    ).rstrip("/")
    model = os.getenv("AEGIS_MODEL", "gpt-4o-mini")

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key, base_url=base_url, timeout=15.0)
        prompt = (
            "You are AegisSwarm's forensic verifier. A process was frozen in real time. "
            "Confirm if it is a genuine threat ('CRITICAL THREAT') or benign ('SAFE'). "
            "Respond ONLY with JSON: {\"verdict\": \"SAFE\"|\"CRITICAL THREAT\", \"reason\": \"...\"}.\n\n"
            f"Snapshot: {json.dumps(snapshot.as_dict())}\n"
            f"Local findings: {json.dumps([f.as_dict() for f in local_verdict.findings])}"
        )
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
            temperature=0,
        )
        raw = (resp.choices[0].message.content or "").strip()
        data = json.loads(raw)
        if data.get("verdict") in {"SAFE", "CRITICAL THREAT"}:
            local_verdict.verdict = data["verdict"]
            if data.get("reason"):
                local_verdict.executive_summary = f"{data['reason']} (Verified by {model})"
            local_verdict.analysis_source = f"swarm_heuristics+llm:{model}"
    except Exception:
        # Never fail open or crash on LLM timeout; fall back to deterministic swarm verdict.
        pass
    return local_verdict


def analyze_snapshot(snapshot: ProcessSnapshot) -> SwarmVerdict:
    """Run all three AegisSwarm specialist agents on a frozen process snapshot."""
    findings = [
        _evaluate_bloodhound(snapshot),
        _evaluate_wiretap(snapshot),
        _evaluate_overwatch(snapshot),
    ]

    threats = [f for f in findings if f.verdict == "CRITICAL THREAT"]
    if not threats:
        verdict = SwarmVerdict(
            verdict="SAFE",
            threat_score=0,
            agent_triggered="None",
            headline="Process verified benign",
            executive_summary=(
                f"PID {snapshot.pid} ({snapshot.name}) was inspected while frozen and cleared by all 3 guards."
            ),
            recommended_action="RESUME",
            evidence_quotes=[],
            findings=findings,
        )
        return _optional_llm_verify(snapshot, verdict)

    top = max(threats, key=lambda f: f.score)
    all_evidence: list[str] = []
    for t in threats:
        all_evidence.extend(t.evidence)

    verdict = SwarmVerdict(
        verdict="CRITICAL THREAT",
        threat_score=top.score,
        agent_triggered=top.agent,
        headline=f"{top.agent} confirmed threat on PID {snapshot.pid} ({snapshot.name})",
        executive_summary=" ".join(t.reason for t in threats),
        recommended_action="ELIMINATE_AND_QUARANTINE",
        evidence_quotes=all_evidence[:8],
        findings=findings,
    )
    return _optional_llm_verify(snapshot, verdict)
