"""Compara límites acumulados sin ejecutar Cachegrind."""
import contextlib
import collections
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import guard


class FixedAnchorTest(unittest.TestCase):
    def run_guard(self, total, approved=None, omit=None):
        with tempfile.TemporaryDirectory() as tmp:
            progs = os.path.join(tmp, "progs")
            os.mkdir(progs)
            open(os.path.join(progs, "sample.syn"), "w", encoding="utf-8").close()
            baseline = os.path.join(tmp, "baseline.json")
            approvals = os.path.join(tmp, "approved.json")
            rows = {f"sample|{mode}": {"total": 10000, "fns": {}}
                    for mode in guard.MODES if mode != omit}
            with open(baseline, "w", encoding="utf-8") as f:
                json.dump({"budget_pct": 0.3, "meta": {"commit": "fixed"}, "programs": rows}, f)
            with open(approvals, "w", encoding="utf-8") as f:
                json.dump(approved or {}, f)
            output = io.StringIO()
            with patch.object(guard, "PROGS", progs), patch.object(guard, "BASELINE", baseline), \
                    patch.object(guard, "APPROVED", approvals), \
                    patch.object(guard, "measure", return_value=(total, {}, collections.Counter({"sample": total}))), \
                    patch.object(sys, "argv", ["guard.py", "--bin", "run"]), \
                    contextlib.redirect_stdout(output):
                status = guard.main()
            return status, output.getvalue()

    def test_unapproved_loss_fails_against_fixed_anchor(self):
        status, output = self.run_guard(10040)
        self.assertEqual(status, 1)
        self.assertIn("+0.400%", output)
        self.assertIn("+0.300%", output)

    def test_approved_cost_keeps_cumulative_reference_and_new_loss_fails(self):
        approved = {"sample|jit": {"accepted_total": 10040, "reason": "measured security cost"}}
        status, output = self.run_guard(10040, approved)
        self.assertEqual(status, 1)  # The other two modes still have the general limit.
        self.assertIn("+0.400%", output)
        self.assertIn("+0.400%", output)
        approved.update({f"sample|{mode}": {"accepted_total": 10040, "reason": "measured security cost"}
                         for mode in ("vm", "ref")})
        self.assertEqual(self.run_guard(10040, approved)[0], 0)
        self.assertEqual(self.run_guard(10041, approved)[0], 1)

    def test_missing_anchor_fails(self):
        status, output = self.run_guard(10000, omit="ref")
        self.assertEqual(status, 1)
        self.assertIn("sin ancla", output)

    def test_reanchor_rejects_same_ci_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline = os.path.join(tmp, "baseline.json")
            artifact = os.path.join(tmp, "perf.json")
            meta = {"rustc": "rustc 1", "valgrind": "valgrind 1", "runner": "ubuntu 1"}
            for path in (baseline, artifact):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump({"meta": meta, "programs": {}}, f)
            with patch.object(guard, "BASELINE", baseline), \
                    patch.object(sys, "argv", ["guard.py", "--bless-from", artifact]):
                with self.assertRaisesRegex(SystemExit, "el entorno de CI no cambió"):
                    guard.main()


if __name__ == "__main__":
    unittest.main()
