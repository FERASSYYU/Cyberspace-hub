"""Sanitized report writers: JSON, SARIF 2.1.0, Markdown, CSV."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from typing import Any

from pbh.core.finding import Finding


def _summary(findings: list[Finding], run: dict[str, Any]) -> dict[str, Any]:
    return {
        "run": run,
        "finding_count": len(findings),
        "by_category": dict(Counter(f.category for f in findings)),
        "by_claim_level": dict(Counter(f.claim_level for f in findings)),
        "by_confidence": dict(Counter(f.confidence for f in findings)),
        "by_validation_state": dict(Counter(f.validation_state for f in findings)),
    }


def write_json(findings: list[Finding], run: dict[str, Any]) -> str:
    doc = {"summary": _summary(findings, run), "findings": [f.to_dict() for f in findings]}
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def write_sarif(findings: list[Finding], run: dict[str, Any]) -> str:
    level = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}
    results = []
    for f in findings:
        results.append({
            "ruleId": f.category,
            "level": level[f.tool_severity],
            "message": {"text": f"{f.redacted_evidence} [{f.claim_level}]"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.artifact_ref},
                                                "region": {"startLine": f.line or 1}}}],
            "partialFingerprints": {"pbhCorrelation": f.correlation_id},
            "properties": {"validation_state": f.validation_state, "confidence": f.confidence},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "project-bounty-hunter", "version": run.get("pbh_version", "")}},
                  "invocations": [{"executionSuccessful": True}],
                  "properties": {"run": run},
                  "results": results}],
    }
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def write_markdown(findings: list[Finding], run: dict[str, Any]) -> str:
    s = _summary(findings, run)
    lines = ["# PBH sanitized report", "", "## Run", ""]
    for key, value in run.items():
        lines.append(f"- {key}: {value}")
    lines += ["", "## Summary", "", f"- Findings: {s['finding_count']}"]
    lines.append(f"- By claim level: {s['by_claim_level']}")
    lines.append("- Every finding is a static-analysis hypothesis until a human verifies it.")
    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("No findings were produced by the analysed inputs.")
    for f in findings:
        lines.append(f"- `{f.artifact_ref}` line {f.line or '-'}: **{f.category}** "
                     f"({f.claim_level}, validation: {f.validation_state}) — {f.redacted_evidence}")
    lines.append("")
    return "\n".join(lines)


def write_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["correlation_id", "artifact_ref", "line", "category", "cwe", "tool_severity",
                     "pbh_severity", "confidence", "claim_level", "validation_state", "tool_name", "tool_version"])
    for f in findings:
        writer.writerow([f.correlation_id, f.artifact_ref, f.line or "", f.category, f.cwe or "",
                         f.tool_severity, f.pbh_severity, f.confidence, f.claim_level,
                         f.validation_state, f.tool_name, f.tool_version])
    return buf.getvalue()
