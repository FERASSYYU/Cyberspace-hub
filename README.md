# Project Bounty Hunter (PBH)

Offline, fail-closed security-analysis tooling for authorized review.

- **No live targets.** PBH has no mode that contacts a network host. The Atmail profile is reference only, with `live_testing_enabled: false`.
- **Fail-closed gate.** The scope gate runs before any input is read. Unknown modes, live-testing flags, or target hosts stop the run.
- **Hypotheses, not verdicts.** Every engine result is a static-analysis hypothesis until a human verifies it. Scanner output is never labelled confirmed.
- **Sanitized reports.** JSON, SARIF, Markdown, and CSV. Evidence is redacted; no raw inputs are uploaded.

## Run locally

    python3 -m unittest discover -s tests/unit -t . -v
    python3 -m pbh.cli --mode local_fixture_benchmark --program programs/atmail/program.json --input lab/fixtures --output /tmp/pbh-out
    python3 -m benchmark.run_benchmark

Requires Python 3.13. No third-party runtime dependencies in this phase.

## Layout

- `pbh/core`: scope gate, redaction, inventory limits, finding model, reports, controller.
- `pbh/engines/json_engine.py`: JSON syntax, duplicate keys, sensitive values, debug settings, CORS, OpenAPI security.
- `pbh/parsers/json_parser.py`: safe JSON parsing with depth limits and JSONC comment stripping.
- `lab/`: synthetic fixtures with obviously fake values and ground-truth labels.
- `benchmark/`: scoring against ground truth. The dataset is too small for meaningful statistics.
- `programs/atmail/`: policy reference profile. See `docs/atmail_eligibility.md` for an unresolved eligibility conflict.
- `docs/tool_status.md`: status of every tool in the specification.
- `.github/workflows/pbh.yml`: manual and weekly runs, local modes only.

## Status

See `docs/tool_status.md` for what is implemented, what is not, and why.
