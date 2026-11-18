"""PBH Finding model and validation."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

VALIDATION_STATES = frozenset(
    {"unverified", "needs_human_review", "confirmed_in_lab", "rejected_false_positive", "authorized_manual_confirmation"}
)
CLAIM_LEVELS = frozenset(
    {"informational", "static_analysis_hypothesis", "needs_manual_review", "confirmed_in_lab", "not_a_live_target_finding"}
)
SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})


@dataclass(frozen=True)
class Finding:
    program_id: str
    asset_ref: str
    artifact_ref: str
    line: int | None
    category: str
    cwe: str | None
    tool_severity: str
    pbh_severity: str
    confidence: str
    tool_name: str
    tool_version: str
    detected_at: str
    evidence_ref: str
    redacted_evidence: str
    validation_state: str
    claim_level: str
    policy_state: str
    correlation_id: str
    remediation: str

    def __post_init__(self) -> None:
        # Validate at construction so no unsafe finding can exist, not only when someone remembers to call validate().
        self.validate()

    def validate(self) -> None:
        if self.validation_state not in VALIDATION_STATES:
            raise ValueError(f"invalid validation_state {self.validation_state!r}")
        if self.claim_level not in CLAIM_LEVELS:
            raise ValueError(f"invalid claim_level {self.claim_level!r}")
        if self.tool_severity not in SEVERITIES or self.pbh_severity not in SEVERITIES:
            raise ValueError("invalid severity value")
        # A scanner result is never "confirmed". Only lab or manual confirmation may set these.
        if self.validation_state == "confirmed_in_lab" and self.claim_level != "confirmed_in_lab":
            raise ValueError("confirmed_in_lab state requires confirmed_in_lab claim level")
        if self.claim_level == "confirmed_in_lab" and self.validation_state != "confirmed_in_lab":
            raise ValueError("confirmed_in_lab claim level requires confirmed_in_lab state")
        if self.pbh_severity in {"low", "medium", "high", "critical"} and self.claim_level != "confirmed_in_lab":
            raise ValueError("a bounty-relevant severity requires confirmed impact evidence")

    def to_dict(self) -> dict:
        return asdict(self)


def correlation_id(category: str, artifact_ref: str, line: int | None) -> str:
    """Stable identifier used to deduplicate the same issue across runs."""
    raw = f"{category}|{artifact_ref}|{line}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]
