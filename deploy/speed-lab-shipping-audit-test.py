#!/usr/bin/env python3
"""Regression tests for real Speed Lab response entries versus token-only text."""
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

AUDIT = runpy.run_path(str(Path(__file__).with_name("speed-lab-shipping-audit.py")))
CHECK = AUDIT["need_go_map_entry"]
IOS_CHECK = AUDIT["need_ios_topology_routes"]
ANDROID_CHECK = AUDIT["need_android_captured_transaction"]


class SpeedLabResponseAuditTests(unittest.TestCase):
    def check_entry(self, source: str) -> list[str]:
        errors: list[str] = []
        with patch.dict(CHECK.__globals__, {"read": lambda _: source, "errors": errors}):
            CHECK("fixture.go", "hops", "hops")
        return errors

    def test_gofmt_alignment_and_line_breaks_preserve_the_contract(self) -> None:
        for source in ('"hops": hops,', '\t"hops":        hops,', '\t"hops":\n\t\thops,'):
            with self.subTest(source=source):
                self.assertEqual([], self.check_entry(source))

    def test_missing_or_different_response_entry_fails(self) -> None:
        for source in ('', '"hop": hops,', '"hops": nil,', '"hops": other,', '"hops": hopsCached,', '"hops": "hops",'):
            with self.subTest(source=source):
                self.assertEqual(["fixture.go: missing Speed Lab response entry 'hops': hops"], self.check_entry(source))

    def test_line_and_block_comments_cannot_supply_response_entries(self) -> None:
        for source in ('// "hops": hops,', '/*\n"hops": hops,\n*/', '/* "hops": hops, */\n"ok": true,'):
            with self.subTest(source=source):
                self.assertTrue(self.check_entry(source))

    def test_raw_string_fixture_does_not_count_as_shipping_code(self) -> None:
        self.assertTrue(self.check_entry('const fixture = `\n"hops": hops,\n`'))

    def test_escaped_string_fixture_does_not_count_as_shipping_code(self) -> None:
        self.assertTrue(self.check_entry(r'const fixture = "\n\"hops\": hops,\n"'))

    def test_comments_beside_a_real_entry_are_allowed(self) -> None:
        self.assertEqual([], self.check_entry('"hops": /* independently measured */ hops, // no fake values\n'))

    def test_url_or_raw_string_elsewhere_does_not_hide_a_real_entry(self) -> None:
        self.assertEqual([], self.check_entry('"source": "https://example.invalid/",\n"hops": hops,\n"note": `not a hop`,\n'))


class SpeedLabIOSTopologyAuditTests(unittest.TestCase):
    source = (Path(__file__).resolve().parents[1]/"ios/RouterVPN/App/IOSSpeedLabRunner.swift").read_text()

    def check_source(self, source: str) -> list[str]:
        errors: list[str] = []
        with patch.dict(IOS_CHECK.__globals__, {"read": lambda _: source, "errors": errors}):
            IOS_CHECK("fixture.swift")
        return errors

    def test_current_router_external_and_tor_graphs_preserve_topology(self):
        self.assertEqual([], self.check_source(self.source))

    def test_entry_proof_wrong_engine_and_direct_substitution_are_rejected(self):
        for marker in ('selected.multihopEnabled == true',
                       'model.iosMultihopEntryBundle(for: saved)',
                       'if external { await model.connectSelectedExternal() }',
                       'else { await model.connect() }',
                       'model.activeEngine == (external ? "external-libbox" : "multihop-libbox")',
                       'selected.multihopEnabled != true'):
            with self.subTest(marker=marker):
                self.assertTrue(self.check_source(self.source.replace(marker, "removed")))

    def test_comment_cannot_supply_a_missing_captured_entry(self):
        marker = 'model.iosMultihopEntryBundle(for: saved)'
        changed = self.source.replace(marker, 'removed') + '\n// '+marker+'\n'
        self.assertTrue(self.check_source(changed))


class SpeedLabAndroidTransactionAuditTests(unittest.TestCase):
    source = (Path(__file__).resolve().parents[1]/"android/app/src/main/java/com/eabusham/routervpn/AndroidSpeedLabController.java").read_text()

    def check_source(self, source):
        errors = []
        with patch.dict(ANDROID_CHECK.__globals__, {"read": lambda _: source, "errors": errors}):
            ANDROID_CHECK("fixture.java")
        return errors

    def test_captured_cleanup_and_exact_fresh_restoration_are_required(self):
        self.assertEqual([], self.check_source(self.source))
        for marker in ('original=connection.captureRestorePoint()',
                       'connection.restorePointCurrent(original)',
                       'connection.stopCaptured(home,topology,',
                       'if(pathDecisionChanged||!connection.idleCurrent(idle))',
                       'connection.restoreCaptured(original,idle,',
                       '!connection.restoredCurrent(original,restoredOwner[0])',
                       'meter.cancel()', 'nativeHopMeter.cancel()',
                       'AndroidMTUMeasurementGate.release(lease)'):
            with self.subTest(marker=marker):
                changed = self.source.replace(marker, "removed")
                self.assertTrue(self.check_source(changed))
                self.assertTrue(self.check_source(changed + "\n// " + marker))


if __name__ == "__main__":
    unittest.main()
