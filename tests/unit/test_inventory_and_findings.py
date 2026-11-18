import json
import os
import tempfile
import unittest
from pathlib import Path

from pbh.core import inventory as inv_mod
from pbh.core.finding import Finding, correlation_id
from pbh.core.reports import write_csv, write_json, write_markdown, write_sarif


def _f(**overrides) -> Finding:
    base = dict(program_id="lab", asset_ref="local-fixture", artifact_ref="a.json", line=1,
                category="debug_setting_enabled", cwe="CWE-489", tool_severity="low", pbh_severity="info",
                confidence="low", tool_name="t", tool_version="0", detected_at="2026-11-18T00:00:00+00:00",
                evidence_ref="a.json", redacted_evidence="debug=true", validation_state="needs_human_review",
                claim_level="static_analysis_hypothesis", policy_state="offline_only",
                correlation_id=correlation_id("debug_setting_enabled", "a.json", 1), remediation="disable")
    base.update(overrides)
    return Finding(**base)


class InventoryTests(unittest.TestCase):
    def test_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "root"
            root.mkdir()
            outside = Path(d) / "secret.json"
            outside.write_text("{}", encoding="utf-8")
            os.symlink(outside, root / "link.json")
            (root / "ok.json").write_text("{}", encoding="utf-8")
            result = inv_mod.build_inventory(root)
            names = [i.relative for i in result.items]
            self.assertEqual(names, ["ok.json"])
            self.assertIn(("link.json", "symlink_not_followed"), result.skipped)

    def test_size_limit_skips_large_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "big.json").write_bytes(b"x" * (inv_mod.MAX_FILE_BYTES + 1))
            result = inv_mod.build_inventory(root)
            self.assertEqual(result.items, ())
            self.assertIn(("big.json", "size_limit"), result.skipped)

    def test_package_manifests_are_routed_as_json(self):
        self.assertEqual(inv_mod.classify(Path("package-lock.json")), "json")
        self.assertEqual(inv_mod.classify(Path("api/openapi.json")), "json")


class FindingTests(unittest.TestCase):
    def test_scanner_output_is_never_confirmed(self):
        with self.assertRaises(ValueError):
            _f(validation_state="confirmed_in_lab")

    def test_bounty_severity_needs_confirmed_evidence(self):
        with self.assertRaises(ValueError):
            _f(pbh_severity="high")

    def test_reports_render_and_contain_no_raw_secret(self):
        f = _f(redacted_evidence="[REDACTED]")
        run = {"pbh_version": "0.1.0", "mode": "local_fixture_benchmark"}
        doc = json.loads(write_json([f], run))
        self.assertEqual(doc["summary"]["finding_count"], 1)
        sarif = json.loads(write_sarif([f], run))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("pbhCorrelation", sarif["runs"][0]["results"][0]["partialFingerprints"])
        self.assertIn("correlation_id", write_csv([f]).splitlines()[0])
        self.assertIn("static_analysis_hypothesis", write_markdown([f], run))


if __name__ == "__main__":
    unittest.main()
