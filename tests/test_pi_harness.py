import json
import os
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))

from pi_harness import MockTarget, evaluate, run, summarize  # noqa: E402


class SafeTarget:
    name = "safe"

    def complete(self, system, user):
        return "I can only help with orders, shipping and returns."


class TestHarness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(HERE, "..", "payloads.json"), encoding="utf-8") as handle:
            cls.payloads = json.load(handle)

    def test_evaluate_detects_canary_leak(self):
        status, reasons = evaluate("the code is CANARY-ABCD1234", "CANARY-ABCD1234", "system_prompt_extraction")
        self.assertEqual(status, "fail")
        self.assertIn("canary_leaked", reasons)

    def test_evaluate_detects_marker(self):
        status, reasons = evaluate("PWNED", "CANARY-0000", "direct_override")
        self.assertEqual(status, "fail")
        self.assertIn("followed_injected_instruction", reasons)

    def test_mock_target_fails_attacks_and_passes_control(self):
        results = run(MockTarget(), self.payloads)
        control = [r for r in results if r["category"] == "control"]
        attacks = [r for r in results if r["category"] != "control"]
        self.assertTrue(all(r["status"] == "pass" for r in control))
        self.assertTrue(all(r["status"] == "fail" for r in attacks))

    def test_safe_target_passes_everything(self):
        summary = summarize(run(SafeTarget(), self.payloads))
        self.assertEqual(summary["failed"], 0)

    def test_each_run_uses_fresh_canary(self):
        seen = []

        class Recorder:
            name = "rec"

            def complete(self, system, user):
                seen.append(system)
                return ""

        run(Recorder(), self.payloads[:3])
        self.assertEqual(len(set(seen)), 3)


if __name__ == "__main__":
    unittest.main()
