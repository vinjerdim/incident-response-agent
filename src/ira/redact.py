"""Secret/PII redaction applied to every tool result before it can reach the model.

Rules are ordered: more specific patterns (DSN credentials, JWTs) run before generic ones so
the placeholder names stay meaningful. Replacements look like `[REDACTED:<kind>]`.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

Replacer = str | Callable[[re.Match[str]], str]


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _card(m: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    if 13 <= len(digits) <= 19 and _luhn_ok(digits):
        return "[REDACTED:card]"
    return m.group(0)


_KEY_NAMES = (
    r"password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?key|"
    r"s3_access_key|private[_-]?key|auth[_-]?token|token"
)

RULES: list[tuple[str, re.Pattern[str], Replacer]] = [
    # scheme://user:password@host -> keep user and host
    (
        "dsn_password",
        re.compile(r"(\b[a-z][a-z0-9+.-]*://[^:/\s@]+:)([^@\s]+)(@)", re.I),
        r"\1[REDACTED:password]\3",
    ),
    ("jwt", re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+"), "[REDACTED:jwt]"),
    ("bearer", re.compile(r"(\bBearer\s+)[A-Za-z0-9._~+/=-]+", re.I), r"\1[REDACTED:token]"),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws_key]"),
    (
        "live_key",
        re.compile(r"\b(?:sk|pk|rk|[a-z]{2,10})_(?:live|test)_[A-Za-z0-9]{6,}\b"),
        "[REDACTED:api_key]",
    ),
    (
        "key_value",
        re.compile(
            rf"(\b(?:[A-Za-z0-9]+_)*(?:{_KEY_NAMES})\s*[=:]\s*)(?!\[REDACTED)([^\s,;&\"']+)", re.I
        ),
        r"\1[REDACTED:secret]",
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"),
        "[REDACTED:email]",
    ),
    ("card", re.compile(r"\b\d(?:[ -]?\d){12,18}\b"), _card),
]


@dataclass
class Redaction:
    text: str
    counts: Counter[str] = field(default_factory=Counter)


class Redactor:
    def __init__(self, rules: list[tuple[str, re.Pattern[str], Replacer]] | None = None):
        self.rules = rules if rules is not None else RULES

    def redact(self, text: str) -> Redaction:
        counts: Counter[str] = Counter()
        for kind, pattern, repl in self.rules:

            def sub(m: re.Match[str], kind=kind, repl=repl) -> str:
                out = repl(m) if callable(repl) else m.expand(repl)
                if out != m.group(0):
                    counts[kind] += 1
                return out

            text = pattern.sub(sub, text)
        return Redaction(text, counts)

    def redact_obj(self, obj: Any, counts: Counter[str] | None = None) -> Any:
        """Recursively redact strings inside dicts/lists (tool `data` payloads)."""
        counts = counts if counts is not None else Counter()
        if isinstance(obj, str):
            r = self.redact(obj)
            counts.update(r.counts)
            return r.text
        if isinstance(obj, dict):
            return {k: self.redact_obj(v, counts) for k, v in obj.items()}
        if isinstance(obj, list | tuple):
            return [self.redact_obj(v, counts) for v in obj]
        return obj
