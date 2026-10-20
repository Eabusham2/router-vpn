#!/usr/bin/env python3
"""Require executable Tor editor mutation coverage, independently of summaries."""
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

AUDIT = runpy.run_path(str(Path(__file__).with_name("tor-circumvention-audit.py")))
CHECK = AUDIT["need_android_tor_editor_controls"]
SOURCE = (Path(__file__).resolve().parents[1]/"android/test_android_tor_form.py").read_text()


class TorEditorAuditTests(unittest.TestCase):
    def errors(self, source):
        errors = []
        with patch.dict(CHECK.__globals__, {"read": lambda _: source, "errors": errors}):
            CHECK("fixture.py")
        return errors

    def test_current_policy_and_visibility_mutations_are_executed(self):
        self.assertEqual([], self.errors(SOURCE))

    def test_cosmetic_test_count_text_is_not_an_authoritative_gate(self):
        self.assertEqual([], self.errors(SOURCE.replace("all five original-source negative controls rejected", "all editor mutation controls rejected")))

    def test_each_control_is_required_and_comments_cannot_replace_it(self):
        for label in ("rewritten-policy", "ipv6-default", "lan-default", "dns-precedence", "hidden-mode-list"):
            with self.subTest(label=label):
                changed = SOURCE.replace('("'+label+'",', '("removed",')
                self.assertTrue(self.errors(changed + '\n# ("'+label+'",\n'))

    def test_ignored_or_unrelated_mutation_failure_is_rejected(self):
        for guard in ("False", "failure not in rejected.stderr", "rejected.returncode == 0"):
            with self.subTest(guard=guard):
                self.assertTrue(self.errors(SOURCE.replace("rejected.returncode == 0 or failure not in rejected.stderr", guard)))


if __name__ == "__main__":
    unittest.main()
