"""Redaction of secret-like strings before anything is logged or reported."""

from __future__ import annotations

import re

_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)(\"?\s*[:=]\s*\"?)([^\s\"',}]{4,})"),
]


def redact(text: str) -> str:
    """Replace secret-like values with a fixed marker. Never returns the raw value."""
    out = text
    for pattern in _PATTERNS:
        if pattern.groups == 3:
            out = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", out)
        else:
            out = pattern.sub("[REDACTED]", out)
    return out
