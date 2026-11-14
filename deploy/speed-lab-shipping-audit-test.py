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
IMPORTED_CURRENT_CHECK = AUDIT["need_imported_speed_lab_current"]


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
        for marker in ('captured=connection.captureRestorePoint()',
                       'original=preparedOriginal!=null?preparedOriginal:connection.captureRestorePoint()',
                       'connection.restorePointCurrent(original)',
                       'connection.stopCaptured(home,topology,',
                       'connection.capturedCleanupPending(home,topology)',
                       'if(pathDecisionChanged||!connection.idleCurrent(idle))',
                       'connection.restoreCaptured(original,idle,',
                       'connection.restoredCurrent(original,restoredOwner[0])',
                       '!connection.pathCurrent(observed)',
                       '!connection.restoreChoiceCurrent(original)',
                       'meter.cancel()', 'nativeHopMeter.cancel()',
                       'AndroidMTUMeasurementGate.release(lease)'):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.source)
                changed = self.source.replace(marker, "removed")
                self.assertTrue(self.check_source(changed))
                self.assertTrue(self.check_source(changed + "\n// " + marker))

    def test_async_capture_and_callback_delivery_cannot_adopt_mutable_replacements(self):
        changes = (
            ('original=preparedOriginal!=null?preparedOriginal:connection.captureRestorePoint()',
             'original=connection.captureRestorePoint()'),
            ('runCaptured(frozen,callback,borrowedLease,work,originalCapture)',
             'runCaptured(frozen,callback,borrowedLease,work,connection.captureRestorePoint())'),
            ('connection.restoreCaptured(original,idle,', 'connection.restoreCaptured(connection.captureRestorePoint(),idle,'),
            ('if(!orderedCapturePending||ticket!=orderedCaptureGeneration)return;', 'if(!orderedCapturePending)return;'),
            ('if(orderedCaptureCancelled){callback.finished(null,cancelled());return;}', ''),
            ('if(error!=null){callback.finished(null,error);return;}', ''),
            ('!connection.pathCurrent(expected)||!connection.restoreChoiceCurrent(originalCapture)',
             '!connection.pathCurrent(expected)'),
            ('public void owned(String session){if(current(owner)&&restoredOwner[0].isEmpty())restoredOwner[0]=session;}',
             'public void owned(String session){}'),
            ('restoredOwner[0]=session', 'restoredOwner[0]=AndroidHomeStateStore.snapshot(activity).sessionId'),
            ('boolean proved=ok&&connection.restoredCurrent(original,restoredOwner[0]);', 'boolean proved=ok;'),
            ('finishRestored(ok&&connection.restoredCurrent(original,restoredOwner[0]),', 'finishRestored(ok,'),
            ('if(!proved||!connection.pathCurrent(observed)||!connection.restoreChoiceCurrent(original))', 'if(!proved)'),
            ('public void superseded(){pathDecisionChanged=true;}', 'public void superseded(){}'),
            ('if(!ok||pathDecisionChanged)', 'if(!ok)'),
        )
        for before, after in changes:
            with self.subTest(before=before):
                self.assertEqual(self.source.count(before), 1)
                self.assertTrue(self.check_source(self.source.replace(before, after)))

    def test_comments_strings_and_unrelated_methods_cannot_supply_captured_callbacks(self):
        for marker in (
            'runCaptured(frozen,callback,borrowedLease,work,originalCapture)',
            'public void owned(String session){if(current(owner)&&restoredOwner[0].isEmpty())restoredOwner[0]=session;}',
            'boolean proved=ok&&connection.restoredCurrent(original,restoredOwner[0]);',
        ):
            changed = self.source.replace(marker, 'removed')
            for witness in ('\n// '+marker, '\n/* '+marker+' */', '\nString witness="'+marker+'";',
                            '\nvoid unrelatedWitness() { '+marker+' }'):
                with self.subTest(marker=marker, witness=witness):
                    self.assertTrue(self.check_source(changed+witness))

    def test_worker_home_is_checked_before_and_after_capture(self):
        marker = 'if(!connection.pathCurrent(expected))throw'
        self.assertEqual(self.source.count(marker), 2)
        for index in range(2):
            pieces = self.source.split(marker)
            changed = marker.join(pieces[:index+1])+'if(false)throw'+marker.join(pieces[index+1:])
            self.assertTrue(self.check_source(changed))

    def test_formatting_does_not_replace_the_exact_semantic_receipt(self):
        changed = self.source.replace('original=preparedOriginal!=null?preparedOriginal:connection.captureRestorePoint()',
                                      'original = preparedOriginal != null ? /* retained worker capture */\npreparedOriginal : connection.captureRestorePoint()')
        self.assertEqual([], self.check_source(changed))


class SpeedLabImportedCurrentAuditTests(unittest.TestCase):
    platform_sources = ("cmd/client/desktop_imported_platform.go", "cmd/client/desktop_imported_linux_lifecycle.go",
                        "cmd/client/desktop_node_owned.go", "cmd/client/desktop_imported_linux_host.go",
                        "cmd/client/desktop_node_chain_dispatch.go", "cmd/client/desktop_node_chain_host.go",
                        "cmd/client/desktop_node_chain_policy_dispatch.go",
                        "cmd/client/desktop_node_chain_linux.go",
                        "cmd/client/desktop_node_chain_execution_launch.go",
                        "cmd/client/desktop_node_chain_execution_graph.go")
    sources = {path: (Path(__file__).resolve().parents[1]/path).read_text() for path in (
        "cmd/client/speed_lab_paths.go", "cmd/client/desktop_external_path.go",
        "cmd/client/speed_lab.go", "cmd/client/multihop_native_launch.go", *platform_sources)}

    def check_sources(self, changes=None):
        sources = dict(self.sources)
        sources.update(changes or {})
        errors = []
        with patch.dict(IMPORTED_CURRENT_CHECK.__globals__, {"read": sources.__getitem__, "errors": errors}):
            IMPORTED_CURRENT_CHECK()
        return errors

    def test_shipping_capture_dns_and_physical_observer_share_the_original_owner(self):
        self.assertEqual([], self.check_sources())

    def test_each_traced_native_platform_source_remains_required(self):
        for path in self.platform_sources:
            with self.subTest(path=path):
                self.assertTrue(self.check_sources({path: ""}))
                self.assertTrue(self.check_sources({path: "/* original source cannot be borrowed from a comment\n"+self.sources[path]+"\n*/"}))

    def test_owner_context_and_dns_cannot_be_removed_or_borrowed(self):
        changes = (
            ("cmd/client/speed_lab_paths.go", 'Imported: imported', 'Imported: nil'),
            ("cmd/client/speed_lab_paths.go", 'owner != identity.Imported', 'owner == nil'),
            ("cmd/client/speed_lab_paths.go", 'network, err = identity.Imported.physicalNetworkContext(ctx)', 'network, err = "cached-network", nil'),
            ("cmd/client/desktop_external_path.go", 'validateSpeedLabIdentityContext(ctx, a, identity)', 'validateSpeedLabIdentity(a, identity)'),
            ("cmd/client/desktop_external_path.go", 'a.proveImportedNativeDNS(ctx, identity.Imported.selection, identity.Command)', 'a.proveImportedNativeDNS(context.Background(), identity.Imported.selection, identity.Command)'),
            ("cmd/client/desktop_external_path.go", 'a.proveImportedNativeDNS(ctx, identity.Imported.selection, identity.Command)', 'a.proveImportedNativeDNS(ctx, otherSelection, identity.Command)'),
            ("cmd/client/desktop_external_path.go", 'return errors.Join(err, ctx.Err())', 'return err'),
            ("cmd/client/speed_lab.go", 'identity.Standard != nil || identity.Imported != nil', 'identity.Standard != nil'),
            ("cmd/client/multihop_native_launch.go", 'networkIdentityContext: observe', 'networkIdentityContext: nil'),
            ("cmd/client/multihop_native_launch.go", 'networkIdentityContext: observe', 'networkIdentityContext: cachedNetwork'),
            ("cmd/client/multihop_native_launch.go", 'observe := physicalNetworkIdentityContext', 'observe := cachedNetwork'),
            ("cmd/client/multihop_native_launch.go", 'observe = launch.ownedNode.imported.readNetwork', 'observe = physicalNetworkIdentityContext'),
            ("cmd/client/multihop_native_launch.go", 'actual, err := observe(ctx)', 'actual, err := observe(context.Background())'),
            ("cmd/client/multihop_native_launch.go", 'actual, err := observe(ctx)', 'actual, err := network, error(nil)'),
            ("cmd/client/multihop_native_launch.go", 'if err != nil || ctx.Err() != nil {', 'if err != nil {'),
            ("cmd/client/multihop_native_launch.go", 'actual != network', 'false'),
            ("cmd/client/multihop_native_launch.go", '!found || current != launch', '!found'),
            ("cmd/client/multihop_native_launch.go", 'a.desktopOwnedNodeCurrentContext(ctx, owner.launch, true)', 'a.desktopOwnedNodeCurrentContext(context.Background(), owner.launch, true)'),
            ("cmd/client/multihop_native_launch.go", 'a.desktopOwnedNodeCurrentContext(ctx, owner.launch, true)', 'a.desktopOwnedNodeCurrentContext(ctx, otherLaunch, true)'),
            ("cmd/client/multihop_native_launch.go", 'network, err := owner.physicalNetworkContext(ctx)', 'network, err := owner.network, nil'),
            ("cmd/client/multihop_native_launch.go", 'owner.networkIdentityContext == nil', 'false'),
            ("cmd/client/multihop_native_launch.go", 'return network, errors.Join(err, ctx.Err())', 'return network, nil'),
        )
        for path, before, after in changes:
            with self.subTest(path=path, before=before, after=after):
                self.assertIn(before, self.sources[path])
                self.assertTrue(self.check_sources({path: self.sources[path].replace(before, after)}))

    def test_comments_strings_and_unrelated_functions_cannot_supply_a_live_binding(self):
        for path, marker in (
            ("cmd/client/speed_lab_paths.go", 'owner != identity.Imported'),
            ("cmd/client/desktop_external_path.go", 'a.proveImportedNativeDNS(ctx, identity.Imported.selection, identity.Command)'),
            ("cmd/client/multihop_native_launch.go", 'networkIdentityContext: observe'),
            ("cmd/client/multihop_native_launch.go", 'observe = launch.ownedNode.imported.readNetwork'),
        ):
            changed = self.sources[path].replace(marker, 'removed')
            for witness in ('\n// '+marker, '\n/* '+marker+' */', '\nvar fixture = `'+marker+'`',
                            '\nfunc unrelatedSourceWitness() { '+marker+' }'):
                with self.subTest(path=path, witness=witness):
                    self.assertTrue(self.check_sources({path: changed+witness}))

    def test_dns_must_remain_between_both_contextual_identity_checks(self):
        path = "cmd/client/desktop_external_path.go"
        before = 'if err := validateSpeedLabIdentityContext(ctx, a, identity); err != nil {'
        first, rest = self.sources[path].split(before, 1)
        changed = first + 'if err := validateSpeedLabIdentity(a, identity); err != nil {' + rest
        self.assertTrue(self.check_sources({path: changed}))
        changed = self.sources[path] + '\nfunc unrelated() { validateSpeedLabIdentityContext(ctx, a, identity) }'
        self.assertEqual([], self.check_sources({path: changed}))

    def test_formatting_is_allowed_but_duplicate_owner_constructor_is_rejected(self):
        path = "cmd/client/multihop_native_launch.go"
        changed = self.sources[path].replace('networkIdentityContext: observe',
                                            'networkIdentityContext: /* original retained observer */\nobserve')
        self.assertEqual([], self.check_sources({path: changed}))
        for declaration in (
            "func bindNativeMultihopRuntime(a *app, launch *desktopNodeLaunch, sel multihopSelection, network string) error",
            "func bindNativeMultihopRuntimeContext(ctx context.Context, a *app, launch *desktopNodeLaunch, sel multihopSelection, network string) error",
        ):
            with self.subTest(declaration=declaration):
                self.assertTrue(self.check_sources({path: self.sources[path]+'\n'+declaration+' { return nil }'}))

    def test_original_observer_is_checked_before_retained_binding(self):
        path = "cmd/client/multihop_native_launch.go"
        observation = '\tactual, err := observe(ctx)\n'
        binding = '\tnativeMultihopOwners.Store(a, &nativeMultihopRuntime{execution: execution, launch: launch, selection: sel, graph: graph, network: network, networkIdentityContext: observe})\n'
        self.assertEqual(self.sources[path].count(observation), 1)
        self.assertEqual(self.sources[path].count(binding), 1)
        changed = self.sources[path].replace(observation, '').replace(binding, binding+observation)
        self.assertTrue(self.check_sources({path: changed}))


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
