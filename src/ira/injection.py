"""Heuristic prompt-injection detector for untrusted text (tool output, alerts).

This only FLAGS content: flagged output is marked `suspicious="true"` in its wrapper and an
audit event is recorded. It is not a security boundary; the real defenses are untrusted-data
delimiting, read-only tools, verified citations, draft checks and human approval.
"""

from __future__ import annotations

import re

RULES: dict[str, list[re.Pattern[str]]] = {
    "ignore_instructions": [
        re.compile(
            r"\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+"
            r"(instructions|prompts|rules)",
            re.I,
        )
    ],
    "role_spoof": [
        re.compile(r"(^|\n|\s)(system|assistant|developer)\s*:", re.I),
        re.compile(r"\byou are now\b", re.I),
    ],
    "tag_spoof": [
        re.compile(
            r"</?\s*(tool_output|alert_data|investigation_data|system|instructions?)\b", re.I
        )
    ],
    "agent_address": [
        re.compile(r"\bnote to (the )?(ai|llm|assistant|agents?)\b", re.I),
        re.compile(r"\bAI (agents?|assistants?)\b\s*[:,]", re.I),
    ],
    "tool_call_bait": [
        re.compile(
            r"\b(call|invoke|run|use)\b[^.\n]{0,40}\b(submit_findings|restart_\w+|rollback_\w+|"
            r"scale_\w+|\w+_service)\b",
            re.I,
        )
    ],
    "exfil_request": [
        re.compile(
            r"\b(include|put|print|reveal|output|send)\b[^.\n]{0,60}\b(password|secret|token|"
            r"credential|env(ironment)? var)",
            re.I,
        )
    ],
    "approval_claim": [
        re.compile(r"\b(already |pre-?)approved by\b", re.I),
        re.compile(r"\bon-?call approved\b", re.I),
    ],
}


def scan(text: str) -> list[str]:
    """Return the sorted names of rules that match `text` (empty list = nothing suspicious)."""
    return sorted(name for name, pats in RULES.items() if any(p.search(text) for p in pats))
