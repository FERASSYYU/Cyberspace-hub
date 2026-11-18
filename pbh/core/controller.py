"""Controller: scope gate first, then inventory, engines, reports, and cleanup."""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from pbh import __version__
from pbh.core import reports
from pbh.core.inventory import build_inventory
from pbh.core.scope import Program, check_run_allowed, load_program
from pbh.engines.json_engine import analyze_json_document

log = logging.getLogger("pbh")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_analysis(mode: str, program_path: Path, input_root: Path, output_dir: Path) -> dict:
    """Run one analysis. The scope gate runs first and fails closed."""
    started = _now()
    program: Program = load_program(program_path)
    check_run_allowed(mode, program)  # raises PolicyViolation before any input is read

    scratch = Path(tempfile.mkdtemp(prefix="pbh-"))
    try:
        inventory = build_inventory(input_root)
        findings = []
        processed = 0
        syntax_errors: list[str] = []
        for item in inventory.items:
            if item.kind not in {"json", "jsonc"}:
                continue
            text = item.path.read_text(encoding="utf-8", errors="strict")
            processed += 1
            found, err = analyze_json_document(text, kind=item.kind, rel=item.relative,
                                               program_id=program.program_id, detected_at=_now())
            if err:
                syntax_errors.append(f"{item.relative}: {err}")
            findings.extend(found)
        run = {
            "pbh_version": __version__,
            "mode": mode,
            "program_id": program.program_id,
            "started_at": started,
            "finished_at": _now(),
            "python_version": ".".join(map(str, __import__("sys").version_info[:3])),
            "files_inventoried": len(inventory.items),
            "files_processed_json": processed,
            "files_skipped": len(inventory.skipped),
            "skip_reasons": sorted({reason for _, reason in inventory.skipped}),
            "json_syntax_errors": len(syntax_errors),
            "live_testing": "disabled",
            "tools_executed": ["pbh-json-engine"],
        }
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "pbh-report.json").write_text(reports.write_json(findings, run), encoding="utf-8")
        (output_dir / "pbh-report.sarif").write_text(reports.write_sarif(findings, run), encoding="utf-8")
        (output_dir / "pbh-report.md").write_text(reports.write_markdown(findings, run), encoding="utf-8")
        (output_dir / "pbh-report.csv").write_text(reports.write_csv(findings), encoding="utf-8")
        log.info("analysis complete: %d findings", len(findings))
        return run
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
