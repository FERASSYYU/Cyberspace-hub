"""Scope and policy gate.

The gate runs before any engine. It fails closed: any unknown mode, any
attempt to enable live testing, or any target host outside an explicit,
approved set stops the run with a non-zero exit.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

ALLOWED_MODES = frozenset({"repository_analysis", "local_fixture_benchmark"})


class PolicyViolation(RuntimeError):
    """Raised when the safety gate refuses a run."""


@dataclass(frozen=True)
class Program:
    program_id: str
    live_testing_enabled: bool
    in_scope_hosts: tuple[str, ...]
    out_of_scope_hosts: tuple[str, ...]
    rate_limit_rps: int
    required_header: str
    notes: tuple[str, ...] = field(default_factory=tuple)


def load_program(path: Path) -> Program:
    """Load and validate a program definition. Any inconsistency raises."""
    data = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "program_id",
        "live_testing_enabled",
        "in_scope_hosts",
        "out_of_scope_hosts",
        "rate_limit_rps",
        "required_header",
    }
    missing = required - data.keys()
    if missing:
        raise PolicyViolation(f"program file missing keys: {sorted(missing)}")
    if not isinstance(data["live_testing_enabled"], bool):
        raise PolicyViolation("live_testing_enabled must be a boolean")
    if not isinstance(data["rate_limit_rps"], int) or data["rate_limit_rps"] > 5:
        raise PolicyViolation("rate_limit_rps must be an integer no greater than 5")
    return Program(
        program_id=str(data["program_id"]),
        live_testing_enabled=data["live_testing_enabled"],
        in_scope_hosts=tuple(data["in_scope_hosts"]),
        out_of_scope_hosts=tuple(data["out_of_scope_hosts"]),
        rate_limit_rps=data["rate_limit_rps"],
        required_header=str(data["required_header"]),
        notes=tuple(data.get("notes", [])),
    )


def check_run_allowed(mode: str, program: Program, *, target_hosts: tuple[str, ...] = ()) -> None:
    """Refuse any run that is not a safe local mode.

    Live-target hosts are never allowed in this implementation, regardless of
    the program file. A live-testing flag set to true is itself a refusal.
    """
    if mode not in ALLOWED_MODES:
        raise PolicyViolation(f"mode {mode!r} is not permitted; allowed: {sorted(ALLOWED_MODES)}")
    if program.live_testing_enabled:
        raise PolicyViolation("live testing is enabled in the program file; this implementation does not support it")
    if target_hosts:
        raise PolicyViolation(f"live target hosts supplied ({len(target_hosts)}); refusing to run")
