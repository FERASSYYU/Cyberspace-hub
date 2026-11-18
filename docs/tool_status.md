# Tool and component status

Status as of 2026-11-18. The sandbox used for this phase could not reach PyPI or GitHub release
downloads, so third-party tools could not be installed, pinned, or verified here.

| Component | Status | Reason |
|---|---|---|
| Scope gate, policy profile | Implemented, tested | — |
| JSON engine (syntax, duplicates, secrets, debug, CORS, OpenAPI security) | Implemented, tested | — |
| Safe JSON parser (depth, duplicate keys, JSONC) | Implemented, tested | — |
| Finding model and validation states | Implemented, tested | — |
| Sanitized JSON, SARIF, Markdown, CSV reports | Implemented, tested | — |
| Inventory limits (size, depth, symlinks, count) | Implemented, tested | — |
| Synthetic benchmark | Implemented, 8 files only | Too small for meaningful statistics; labels written by the same author as the engine |
| actionlint 1.7.12 | Workflow step added, checksum-verified against release checksums | Not yet executed in CI at time of writing |
| zizmor 1.32.0 | Workflow step added (PyPI, version pinned, not hash-pinned) | Not yet executed in CI at time of writing |
| jq, yq | Not integrated | Not required by the current engines; to add with pinned binaries |
| jsonschema, defusedxml | Not integrated | PyPI unreachable here; core uses the standard library |
| uv.lock | Not generated | Requires PyPI access |
| Vacuum, Spectral | Not integrated | Requires install and benchmark |
| Opengrep, CodeQL | Not integrated | Requires install and benchmark |
| OSV-Scanner, pip-audit | Not integrated | Requires install |
| Titus, Gitleaks | Not integrated | Requires install and benchmark |
| Checkov, KICS | Not integrated | Requires install and benchmark |
| Syft, Grype | Not integrated | Requires install |
| mobsfscan, Androguard | Not integrated | Requires install |
| OpenSSF Scorecard | Not integrated | Requires install |
| Trivy | Excluded | Supply-chain advisory in spec; not used |
| ZAP, Schemathesis, Subfinder, httpx, Katana, Nuclei, Amass | Excluded | Active or live tools, forbidden against Atmail |

Nothing in this table was executed against any Atmail host.
