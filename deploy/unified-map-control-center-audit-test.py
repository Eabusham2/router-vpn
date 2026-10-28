#!/usr/bin/env python3
"""Keep the map release audit bound to actual captured Android Tor health."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
AUDIT_PATH = ROOT / "deploy/unified-map-control-center-audit.py"
with redirect_stdout(io.StringIO()):
    AUDIT = runpy.run_path(str(AUDIT_PATH))
CHECK = AUDIT["need_android_tor_health"]
SOURCE_PATH = ROOT / "android/app/src/main/java/com/eabusham/routervpn/AndroidTorSession.java"
SOURCE = SOURCE_PATH.read_text(encoding="utf-8")


class AndroidTorHealthAuditTests(unittest.TestCase):
    def errors(self, source):
        errors = []
        with patch.dict(CHECK.__globals__, {"read": lambda _: source, "errors": errors}):
            CHECK()
        return errors

    def reject(self, old, new):
        self.assertEqual(1, SOURCE.count(old), "mutation must target the shipping guard once")
        errors = self.errors(SOURCE.replace(old, new))
        self.assertTrue(errors, "broken captured health must fail the release audit")
        self.assertTrue(all("captured Tor health/DNS ownership:" in error for error in errors))

    def test_actual_captured_request_owner_passes(self):
        self.assertNotIn("request.healthy()", SOURCE)
        self.assertEqual([], self.errors(SOURCE))

    def test_formatting_and_comments_preserve_the_contract(self):
        changed = SOURCE.replace("\n", "\r\n").replace(
            "captured.healthy()", "captured /* braces { } */ . healthy ( )")
        self.assertEqual([], self.errors(changed))

    def test_missing_or_uncaptured_health_cannot_hide_in_comments_or_literals(self):
        old = "if (!current() || !captured.healthy()) throw unavailable();"
        for new in ("if (!current()) throw unavailable();", "if (!current() || !request.healthy()) throw unavailable();"):
            with self.subTest(new=new):
                self.reject(old, new + "\n// " + old + '\nString decoy = "' + old + ' { }";')

    def test_a_different_method_cannot_supply_the_missing_check(self):
        old = "if (!current() || !captured.healthy()) throw unavailable();"
        changed = SOURCE.replace(old, "if (!current()) throw unavailable();")
        end = changed.rindex("}")
        changed = changed[:end] + "void unrelated(RouterTorProofRequest captured) { " + old + " }\n" + changed[end:]
        self.assertTrue(self.errors(changed), "another method cannot supply a missing health guard")

    def test_admission_capture_and_receipt_are_required_in_order(self):
        for old, new in (
            ("if (!proved || cancelled || request == null) return false;", "if (request == null) return false;"),
            ("captured = request;\n            try {", "captured = anotherRequest;\n            try {"),
            ("padding.accept(captured.paddingStatusJSON(), System.currentTimeMillis());", "return true;"),
            ("if (!current() || !captured.healthy()) throw unavailable();", "return true;"),
        ):
            with self.subTest(old=old):
                self.reject(old, new)

    def test_failure_clears_the_proof_and_revokes_exactly_the_captured_owner(self):
        for old, new in (
            ('cancelled = true;\n                proved = false;\n                result = "";', 'cancelled = true;'),
            ("captured.cancel();\n        return false;", "request.cancel();\n        return false;"),
            ("captured.cancel();\n        return false;", "return false;"),
        ):
            with self.subTest(old=old):
                self.reject(old, new)

    def test_revocation_inside_the_monitor_is_rejected(self):
        self.reject('result = "";\n            }', 'result = "";\n                captured.cancel();\n            }')

    def test_selected_dns_and_both_native_receipt_checks_are_required(self):
        for old, new in (
            ("Libbox.routerStrategyDNSProof(server);", "ordinaryNetworkLookup();"),
            ("synchronized (this) { if (cancelled || !current() || !captured.healthy()) throw unavailable(); padding.accept(captured.paddingStatusJSON(),System.currentTimeMillis()); }", ""),
            ("if (cancelled || !current() || !captured.healthy()) throw unavailable();\n            padding.accept(captured.paddingStatusJSON(),System.currentTimeMillis());", "padding.accept(captured.paddingStatusJSON(),System.currentTimeMillis());"),
            ("padding.accept(captured.paddingStatusJSON(),System.currentTimeMillis());\n            result = response;", "result = response;"),
            ("network.equals(owner.network())", "true"),
        ):
            with self.subTest(old=old):
                self.reject(old, new)

    def test_post_dns_adoption_cannot_precede_its_receipt(self):
        old = "padding.accept(captured.paddingStatusJSON(),System.currentTimeMillis());\n            result = response;\n            proved = true;"
        self.reject(old, "result = response; proved = true;\n            padding.accept(captured.paddingStatusJSON(),System.currentTimeMillis());")

    def test_the_release_audit_actually_calls_the_health_check(self):
        original = Path.read_text
        broken = SOURCE.replace("Libbox.routerStrategyDNSProof(server);", "ordinaryNetworkLookup();")
        def read(path, *args, **kwargs):
            return broken if path == SOURCE_PATH else original(path, *args, **kwargs)
        output = io.StringIO()
        with patch.object(Path, "read_text", read), redirect_stdout(output), self.assertRaises(SystemExit) as failure:
            runpy.run_path(str(AUDIT_PATH))
        self.assertEqual(1, failure.exception.code)
        self.assertIn("captured Tor health/DNS ownership:", output.getvalue())


if __name__ == "__main__":
    unittest.main()
