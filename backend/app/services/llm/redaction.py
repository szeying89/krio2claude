"""Pre-send secret redaction.

Scans text for common secret shapes (provider API keys, AWS access keys,
generic "password: ..." assignments, PEM private key blocks, JWTs) and
replaces each with a placeholder. The mapping from placeholder back to the
original value is kept only in the returned RedactionResult, in memory, for
local display purposes (a "diff preview" of what would be removed) — it is
never itself sent anywhere or logged; only `redacted_text` is safe to send
or log.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("anthropic_api_key", re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}")),
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("openai_api_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    (
        "generic_secret_assignment",
        re.compile(
            r"(?i)\b(password|secret|api[_-]?key|token)\b['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9\-_/+=]{8,}['\"]?"
        ),
    ),
]


@dataclass(frozen=True)
class RedactionFinding:
    kind: str
    original: str
    placeholder: str


@dataclass(frozen=True)
class RedactionResult:
    redacted_text: str
    findings: tuple[RedactionFinding, ...]

    def reveal(self) -> str:
        """Reconstruct the original text — for local display only. Never
        send or log the result of this method."""
        text = self.redacted_text
        for finding in self.findings:
            text = text.replace(finding.placeholder, finding.original)
        return text


def redact_secrets(text: str) -> RedactionResult:
    findings: list[RedactionFinding] = []

    def _make_replacer(kind: str):
        def _replace(match: re.Match[str]) -> str:
            placeholder = f"[REDACTED:{kind}:{len(findings)}]"
            findings.append(
                RedactionFinding(kind=kind, original=match.group(0), placeholder=placeholder)
            )
            return placeholder

        return _replace

    redacted = text
    for kind, pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(_make_replacer(kind), redacted)

    return RedactionResult(redacted_text=redacted, findings=tuple(findings))
