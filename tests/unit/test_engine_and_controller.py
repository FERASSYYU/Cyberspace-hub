import json
import tempfile
import unittest
from pathlib import Path

from pbh.core.controller import run_analysis
from pbh.core.scope import PolicyViolation
from pbh.engines.json_engine import analyze_json_document

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "lab" / "fixtures"
PROGRAM = ROOT / "programs" / "atmail" / "program.json"


def _categories(path: Path) -> set[str]:
    kind = "jsonc" if path.suffix == ".jsonc" else "json"
    found, err = analyze_json_document(path.read_text(encoding="utf-8"), kind=kind,
                                       rel=path.name, program_id="lab", detected_at="2026-11-18T00:00:00+00:00")
    if err:
        return {"SYNTAX_ERROR"}
    return {f.category for f in found}


class EngineTests(unittest.TestCase):
    def test_ground_truth_matches_engine_output(self):
        truth = json.loads((ROOT / "lab" / "ground_truth.json").read_text(encoding="utf-8"))["files"]
        for rel, expected in truth.items():
            with self.subTest(file=rel):
                self.assertEqual(_categories(LAB / rel), set(expected))

    def test_findings_are_never_confirmed(self):
        found, _ = analyze_json_document('{"debug": true}', kind="json", rel="x.json",
                                         program_id="lab", detected_at="2026-11-18T00:00:00+00:00")
        self.assertTrue(found)
        for f in found:
            self.assertEqual(f.claim_level, "static_analysis_hypothesis")
            self.assertEqual(f.validation_state, "needs_human_review")


class ControllerTests(unittest.TestCase):
    def test_end_to_end_local_run_writes_all_reports(self):
        with tempfile.TemporaryDirectory() as out:
            run = run_analysis("local_fixture_benchmark", PROGRAM, LAB, Path(out))
            for name in ("pbh-report.json", "pbh-report.sarif", "pbh-report.md", "pbh-report.csv"):
                self.assertTrue((Path(out) / name).exists(), name)
            self.assertEqual(run["live_testing"], "disabled")
            self.assertGreaterEqual(run["files_processed_json"], 5)

    def test_gate_refuses_before_writing_anything(self):
        with tempfile.TemporaryDirectory() as out:
            with self.assertRaises(PolicyViolation):
                run_analysis("live_scan", PROGRAM, LAB, Path(out) / "never")
            self.assertFalse((Path(out) / "never").exists())


if __name__ == "__main__":
    unittest.main()
