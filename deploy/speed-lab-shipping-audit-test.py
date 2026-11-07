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
NATIVE_CHECK = AUDIT["need_native_multihop_lanes"]


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


class SpeedLabNativeMultihopLaneAuditTests(unittest.TestCase):
    source = (Path(__file__).resolve().parents[1]/"cmd/client/multihop_native_capture.go").read_text()
    imported = (Path(__file__).resolve().parents[1]/"cmd/client/multihop_native_imported.go").read_text()

    def check_source(self, source, imported=None):
        errors = []
        def read(path):
            return source if path == "fixture.go" else self.imported if imported is None else imported
        with patch.dict(NATIVE_CHECK.__globals__, {"read": read, "errors": errors}):
            NATIVE_CHECK("fixture.go")
        return errors

    def test_shipping_captured_graph_installs_both_proof_lanes(self):
        self.assertEqual([], self.check_source(self.source))

    def test_capture_call_both_listeners_and_routing_are_required(self):
        for marker in ('nativeMultihopProofConfig(config, sel.Entry)',
                       'nativeEntryPrivateOutbound(',
                       'graph["outbounds"] = append(outs, private)',
                       'graph["inbounds"] = append(ins,',
                       '"tag": "multihop-entry-proof"',
                       '"listen_port": nativeMultihopEntryProofPort',
                       '"tag": "multihop-proof"',
                       '"listen_port": nativeMultihopExitProofPort',
                       'route["rules"] = append([]any{',
                       '"inbound": []any{"multihop-entry-proof"}',
                       'entryProofTag = "entry-private"',
                       '"inbound": []any{"multihop-proof"}',
                       '"outbound": "proxy"'):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.source)
                self.assertTrue(self.check_source(self.source.replace(marker, "removed")))

    def test_wrong_paired_imported_branch_or_route_is_rejected(self):
        changes = (
            ('entry.NodeKind == "external" && entry.External != nil', 'entry.NodeKind != "external" && entry.External != nil'),
            ('entryProofTag := "entry-wg"', 'entryProofTag := "entry-private"'),
            ('if !imported {', 'if imported {'),
            ('entryProofTag = "entry-private"', 'entryProofTag = "entry-wg"'),
            ('"outbound": entryProofTag', '"outbound": "entry-private"'),
            ('entry.SocksHost, entry.SocksPort, entry.SocksUsername, entry.SocksPassword', 'entry.SocksHost, entry.SocksPort, "", ""'),
            ('nativeMultihopProofConfig(config, sel.Entry)', 'nativeMultihopProofConfig(config, sel.Exit)'),
            ('captureDesktopImportedMultihop(ctx, root, sel, modes, lookup)', 'captureDesktopImportedMultihop(context.Background(), root, sel, modes, lookup)'),
            ('proof["tag"] != "routervpn-proof"', 'proof["tag"] != "other-proof"'),
            ('tun["strict_route"] != true', 'false'),
            ('route["final"] != "proxy"', 'false'),
        )
        for before, after in changes:
            with self.subTest(before=before):
                self.assertIn(before, self.source)
                changed = self.source.replace(before, after)
                self.assertTrue(self.check_source(changed + "\n// " + before))

    def test_imported_compiler_and_original_entry_are_required(self):
        for before, after in (
            ('mobilemultihop.NewImportedEntry(source, capture, sel.ExitMode, encodeDesktopNodeAssets(files), string(rawFinal), startJSON, bootstrap)', 'compileUnrelatedGraph()'),
            ('nativeMultihopProofConfig(compiled.Config(), sel.Entry)', 'nativeMultihopProofConfig(compiled.Config(), sel.Exit)'),
            ('c.configs[sel.ExitMode] = config', 'c.configs[sel.ExitMode] = other'),
        ):
            for replacement in (after, "/* " + before + " */", '"' + before + '"'):
                with self.subTest(before=before, replacement=replacement):
                    self.assertIn(before, self.imported)
                    self.assertTrue(self.check_source(self.source, self.imported.replace(before, replacement)))

    def test_branch_comments_and_unrelated_functions_cannot_supply_routes(self):
        for marker in ('entryProofTag := "entry-wg"', 'entryProofTag = "entry-private"',
                       'private, err = nativeEntryPrivateOutbound(entry.SocksHost, entry.SocksPort, entry.SocksUsername, entry.SocksPassword)',
                       'graph["outbounds"] = append(outs, private)', '"outbound": entryProofTag'):
            for witness in ('\n// ' + marker, '\n/* ' + marker + ' */', '\nvar fixture = `' + marker + '`',
                            '\nfunc unrelatedSourceWitness() { ' + marker + ' }'):
                with self.subTest(marker=marker, witness=witness):
                    self.assertIn(marker, self.source)
                    self.assertTrue(self.check_source(self.source.replace(marker, "removed") + witness))

    def test_graph_guard_accepts_formatting_but_rejects_duplicate_definition(self):
        changed = self.source.replace('entryProofTag := "entry-wg"', 'entryProofTag := /* captured imported entry */\n "entry-wg"')
        self.assertEqual([], self.check_source(changed))
        declaration = "func nativeMultihopProofConfig(config string, entry common.RouterProfile) (string, string, error)"
        self.assertTrue(self.check_source(self.source + "\n" + declaration + " {}\n"))

    def test_comments_and_raw_fixtures_cannot_supply_a_proof_lane(self):
        marker = '"inbound": []any{"multihop-entry-proof"}'
        changed = self.source.replace(marker, "removed")
        for replacement in ('\n// '+marker, '\n/* '+marker+' */', '\nvar fixture = `'+marker+'`'):
            with self.subTest(replacement=replacement):
                self.assertTrue(self.check_source(changed+replacement))


if __name__ == "__main__":
    unittest.main()
