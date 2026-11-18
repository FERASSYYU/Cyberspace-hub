import json
import tempfile
import unittest
from pathlib import Path

from pbh.core.scope import PolicyViolation, check_run_allowed, load_program

ROOT = Path(__file__).resolve().parents[2]


def _write(data: dict) -> Path:
    d = Path(tempfile.mkdtemp())
    p = d / "program.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


class ScopeGateTests(unittest.TestCase):
    def setUp(self):
        self.program = load_program(ROOT / "programs" / "atmail" / "program.json")

    def test_atmail_profile_has_live_testing_disabled(self):
        self.assertFalse(self.program.live_testing_enabled)
        self.assertLessEqual(self.program.rate_limit_rps, 5)

    def test_local_modes_are_allowed(self):
        for mode in ("repository_analysis", "local_fixture_benchmark"):
            check_run_allowed(mode, self.program)

    def test_unknown_mode_is_refused(self):
        with self.assertRaises(PolicyViolation):
            check_run_allowed("live_scan", self.program)

    def test_live_testing_flag_refuses_run(self):
        bad = load_program(_write({**self._base(), "live_testing_enabled": True}))
        with self.assertRaises(PolicyViolation):
            check_run_allowed("local_fixture_benchmark", bad)

    def test_target_hosts_refuse_run(self):
        with self.assertRaises(PolicyViolation):
            check_run_allowed("local_fixture_benchmark", self.program, target_hosts=("www.atmail.com",))

    def test_rate_limit_above_five_is_rejected(self):
        with self.assertRaises(PolicyViolation):
            load_program(_write({**self._base(), "rate_limit_rps": 6}))

    def test_missing_keys_are_rejected(self):
        with self.assertRaises(PolicyViolation):
            load_program(_write({"program_id": "x"}))

    @staticmethod
    def _base():
        return {"program_id": "t", "live_testing_enabled": False, "in_scope_hosts": [],
                "out_of_scope_hosts": [], "rate_limit_rps": 5, "required_header": "X-Bug-Bounty"}


if __name__ == "__main__":
    unittest.main()
