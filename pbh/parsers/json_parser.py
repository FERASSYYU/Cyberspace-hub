"""Safe JSON parsing: rejects duplicate keys, enforces depth and size limits."""

from __future__ import annotations

import json
from typing import Any


class JsonSafetyError(ValueError):
    pass


MAX_DEPTH = 64


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JsonSafetyError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _depth(value: Any, level: int = 0) -> int:
    if level > MAX_DEPTH:
        raise JsonSafetyError("maximum nesting depth exceeded")
    if isinstance(value, dict):
        return max([level] + [_depth(v, level + 1) for v in value.values()])
    if isinstance(value, list):
        return max([level] + [_depth(v, level + 1) for v in value])
    return level


def parse_json(text: str) -> Any:
    """Parse strict JSON. Raises JsonSafetyError or json.JSONDecodeError."""
    value = json.loads(text, object_pairs_hook=_reject_duplicates)
    _depth(value)
    return value


def strip_jsonc_comments(text: str) -> str:
    """Remove // and /* */ comments outside string literals. Trailing commas are not handled."""
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                raise JsonSafetyError("unterminated block comment")
            i = end + 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)
