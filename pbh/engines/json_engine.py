"""JSON engine: syntax, duplicate keys, sensitive values, debug settings, API security and CORS.

Every result is a static-analysis hypothesis. A missing declaration in an API
specification is not proof that a live endpoint is vulnerable.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pbh import __version__
from pbh.core.finding import Finding, correlation_id
from pbh.core.redact import redact
from pbh.parsers.json_parser import JsonSafetyError, parse_json, strip_jsonc_comments

TOOL_NAME = "pbh-json-engine"
SENSITIVE_KEY = re.compile(r"(?i)(password|secret|api[_-]?key|private[_-]?key|access[_-]?token)")
HTTP_METHODS = {"get", "put", "post", "delete", "patch", "options", "head", "trace"}


def _finding(program_id: str, rel: str, category: str, cwe: str | None, severity: str,
             remediation: str, evidence: str, detected_at: str, line: int | None = None) -> Finding:
    f = Finding(
        program_id=program_id,
        asset_ref="local-fixture",
        artifact_ref=rel,
        line=line,
        category=category,
        cwe=cwe,
        tool_severity=severity,
        pbh_severity="info",
        confidence="low",
        tool_name=TOOL_NAME,
        tool_version=__version__,
        detected_at=detected_at,
        evidence_ref=f"{rel}",
        redacted_evidence=redact(evidence)[:200],
        validation_state="needs_human_review",
        claim_level="static_analysis_hypothesis",
        policy_state="offline_only",
        correlation_id=correlation_id(category, rel, line),
        remediation=remediation,
    )
    f.validate()
    return f


def _walk(node: Any, path: str = "$"):
    yield path, node
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]")


def analyze_json_document(text: str, *, kind: str, rel: str, program_id: str,
                          detected_at: str) -> tuple[list[Finding], str | None]:
    """Return (findings, syntax_error). A syntax error yields no findings and an error string."""
    source = strip_jsonc_comments(text) if kind == "jsonc" else text
    try:
        doc = parse_json(source)
    except (json.JSONDecodeError, JsonSafetyError) as exc:
        return [], str(exc)

    findings: list[Finding] = []
    for path, node in _walk(doc):
        if isinstance(node, dict):
            for key, value in node.items():
                if SENSITIVE_KEY.search(key) and isinstance(value, str) and len(value) >= 8 \
                        and not value.startswith("${") and value.upper() != value.lower() \
                        and "EXAMPLE" not in value.upper():
                    findings.append(_finding(program_id, rel, "sensitive_value_in_config", "CWE-798",
                                             "medium", "Move the value to a secret store and reference it at runtime.",
                                             f"{path}.{key}", detected_at))
                if key.lower() in {"debug", "development_mode", "devmode"} and value is True:
                    findings.append(_finding(program_id, rel, "debug_setting_enabled", "CWE-489",
                                             "low", "Disable debug settings in production configuration.",
                                             f"{path}.{key}=true", detected_at))
                if key.lower() in {"access-control-allow-origin", "allow_origins", "cors_origins"} \
                        and (value == "*" or value == ["*"]):
                    findings.append(_finding(program_id, rel, "cors_wildcard_origin", "CWE-942",
                                             "low", "Restrict CORS origins to an explicit allowlist.",
                                             f"{path}.{key}=*", detected_at))

    if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc):
        findings.extend(_openapi_checks(doc, rel, program_id, detected_at))
    return findings, None


def _openapi_checks(doc: dict, rel: str, program_id: str, detected_at: str) -> list[Finding]:
    out: list[Finding] = []
    has_global_security = bool(doc.get("security"))
    schemes = (doc.get("components") or {}).get("securitySchemes") or doc.get("securityDefinitions") or {}
    if not has_global_security and not schemes:
        out.append(_finding(program_id, rel, "api_no_security_definition", "CWE-306", "low",
                            "Declare security schemes; verify live endpoint auth separately.",
                            "no security or securitySchemes", detected_at))
    for p, methods in (doc.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() in HTTP_METHODS and isinstance(op, dict) and not op.get("security") \
                    and not has_global_security:
                out.append(_finding(program_id, rel, "api_operation_without_security", "CWE-306", "info",
                                    "Confirm this operation is intentionally public.",
                                    f"{method.upper()} {p}", detected_at))
    return out


def inventory_operations(doc: dict) -> list[dict[str, str]]:
    """List OpenAPI operations as method/path pairs, for inventory only."""
    ops = []
    for p, methods in (doc.get("paths") or {}).items():
        if isinstance(methods, dict):
            for method in methods:
                if method.lower() in HTTP_METHODS:
                    ops.append({"method": method.upper(), "path": p})
    return ops
