#!/usr/bin/env python3
"""Execute actual native shipping audit predicates against broken call paths."""
from __future__ import annotations

import ast
from pathlib import Path
import re
import shlex
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NativeShippingAuditTests(unittest.TestCase):
    def setUp(self):
        self.changes = {}
        weighted = ast.parse((ROOT / "deploy/weighted-release-audit.py").read_text(encoding="utf-8"))
        functions = [node for node in weighted.body if isinstance(node, ast.FunctionDef)
                     and node.name in ("windows_owned_package", "retained_native_multihop_platform")]
        self.assertEqual(len(functions), 2)
        self.scope = {"all_markers": self.has, "none_markers": self.no}
        exec(compile(ast.Module(body=functions, type_ignores=[]), "native-shipping-predicates", "exec"), self.scope)
        self.legacy = {}
        for node in ast.walk(weighted):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "Gate":
                continue
            name = ast.literal_eval(node.args[0])
            if name in ("Windows native WPF app + Portable lifecycle", "macOS native AppKit packages"):
                self.legacy[name] = eval(compile(ast.Expression(node.args[2]), "native-shipping-gate", "eval"), self.scope)
        self.assertEqual(len(self.legacy), 2)
        recovered = ast.parse((ROOT / "deploy/recovered-release-audit-v3.py").read_text(encoding="utf-8"))
        functions = [node for node in recovered.body if isinstance(node, ast.FunctionDef)
                     and node.name in ("windows_shipping_has", "controller_multihop_platform")]
        self.assertEqual(len(functions), 2)
        module = types.SimpleNamespace(has=self.has, legacy=types.SimpleNamespace(
            windows_owned_package=self.scope["windows_owned_package"],
            retained_native_multihop_platform=self.scope["retained_native_multihop_platform"]))
        self.recovered = {"mod": module, "Path": Path}
        exec(compile(ast.Module(body=functions, type_ignores=[]), "recovered-shipping-predicates", "exec"), self.recovered)

    def body(self, path):
        return self.changes[path] if path in self.changes else (ROOT / path).read_text(encoding="utf-8")

    def has(self, path, *markers):
        text = self.body(path)
        return bool(text) and all(marker in text for marker in markers)

    def no(self, path, *markers):
        text = self.body(path)
        return bool(text) and all(marker not in text for marker in markers)

    def replace(self, path, before, after):
        original = self.body(path)
        self.assertIn(before, original)
        self.changes[path] = original.replace(before, after)

    def test_current_shipping_chain_passes_both_scorers(self):
        self.assertTrue(self.scope["windows_owned_package"]())
        for platform in ("windows", "darwin"):
            self.assertTrue(self.scope["retained_native_multihop_platform"](platform))
            self.assertTrue(self.recovered["controller_multihop_platform"](platform))
        for gate in self.legacy.values():
            self.assertTrue(gate())
        self.assertTrue(self.recovered["windows_shipping_has"]("/api/session/events", "MapCanvas", "latitude", "longitude"))

    def test_old_launch_strings_do_not_replace_owned_executable_dispatch(self):
        path = "deploy/package-builds.sh"
        self.replace(path, "$process=Start-Process @start", "$process=$null")
        self.changes[path] += '\nRouterVPN-Windows-App.ps1\ncp -a "$ROOT/client"\n'
        self.assertFalse(self.scope["windows_owned_package"]())
        self.assertFalse(self.legacy["Windows native WPF app + Portable lifecycle"]())
        self.assertFalse(self.recovered["windows_shipping_has"]("/api/session/events"))

    def test_package_shutdown_and_executable_regressions_remain_required(self):
        mutations = (
            ("deploy/package-builds.sh", 'cp "$DIST/client/RouterVPN-$arch.exe" "$dir/RouterVPN.exe"', "omit owned launcher"),
            ("cmd/windows-app-launcher/main.go", 'filepath.Join(root, "client", "RouterVPN-Windows-App.ps1")', 'filepath.Join(root, "web-link")'),
            ("cmd/windows-app-launcher/main.go", "controllerprocess.Track(child, ownerToken)", "trackUnrelated(child)"),
            ("cmd/portable-launcher/controller_shutdown.go", "controllerprocess.Stop(cmd)", "nil"),
            ("internal/controllerprocess/client.go", "receipt.Token != token", "false"),
            ("internal/controllerprocess/client.go", "!receipt.Closed", "false"),
            ("internal/controllerprocess/client.go", "<-owner.done", "<-unrelatedDone"),
            (".github/workflows/windows-native-contract.yml", "test_windows_recovery_launcher.py --shell powershell.exe", "unrelated-test.py"),
        )
        for path, before, after in mutations:
            with self.subTest(path=path, removed=before):
                self.changes.clear()
                self.replace(path, before, after)
                self.assertFalse(self.scope["windows_owned_package"]())
                self.assertFalse(self.recovered["windows_shipping_has"]("MapCanvas"))

    def test_removed_platform_dispatch_cannot_be_replaced_by_legacy_markers(self):
        path = "cmd/client/multihop_native_routes.go"
        for platform in ("windows", "darwin"):
            with self.subTest(platform=platform):
                self.changes.clear()
                self.replace(path, f'case "{platform}":', f'case "unsupported-{platform}":')
                self.changes[path] += f'\n// runtime.GOOS == "{platform}"\n'
                self.assertFalse(self.scope["retained_native_multihop_platform"](platform))
                self.assertFalse(self.recovered["controller_multihop_platform"](platform))

    def test_both_platforms_require_retained_source_policy_and_runtime_owner(self):
        mutations = (
            ("cmd/client/multihop_native_launch.go", "verifyBundledNativeContext(ctx, desktopAmneziaPackageRoot())", "findUnverifiedEngine()"),
            ("cmd/client/multihop_native_launch.go", "preflightRetainedNativeMultihop(ctx, binary, launch, runDesktopExternalPreflightCommand)", "preflightRetainedNativeMultihop(context.Background(), binary, launch, runDesktopExternalPreflightCommand)"),
            ("cmd/client/multihop_execution.go", "desktopExecutionCommandContext(ctx, d.a, sel, descriptor)", "desktopExecutionCommand(d.a, sel, descriptor)"),
            ("cmd/client/multihop_execution_config.go", "prepareOwnedNativeMultihopCommandContext(ctx, a, sel, d)", "prepareOwnedNativeMultihopCommand(a, sel, d)"),
            ("cmd/client/bundled_native.go", "context.WithTimeout(ctx, 10*time.Second)", "context.WithTimeout(context.Background(), 10*time.Second)"),
            ("cmd/client/multihop_native_launch.go", "sel.Native.validate(sel) != nil", "false"),
            ("cmd/client/multihop_native_launch.go", 'inbound["auto_route"] != true || inbound["strict_route"] != true', "false"),
            ("cmd/client/multihop_native_launch.go", "compileDesktopExecutionConfig(data, *descriptor, sel)", "compileUnrelatedServer(data)"),
            ("cmd/client/multihop_native_launch.go", "registerNativeMultihopDNSRuntime(a, sel, launch.command)", "registerUnrelatedDNS()"),
            ("cmd/client/multihop_native_launch.go", "!a.ownsConnectionRuntime(launch.command)", "false"),
            ("cmd/client/desktop_node_native.go", "receipt.ConfigSHA256 != configSHA256", "false"),
            ("cmd/client/multihop_native_routes.go", "a.proveNativeMultihop(sel, cmd)", "proveUnrelatedPath()"),
        )
        for path, before, after in mutations:
            with self.subTest(path=path, removed=before):
                self.changes.clear()
                self.replace(path, before, after)
                for platform in ("windows", "darwin"):
                    self.assertFalse(self.scope["retained_native_multihop_platform"](platform))
                    self.assertFalse(self.recovered["controller_multihop_platform"](platform))
                for gate in self.legacy.values():
                    self.assertFalse(gate())

    def test_real_darwin_wrapper_and_firewall_cannot_be_substituted(self):
        self.replace("cmd/client/multihop_native_darwin.go", "return prepareOwnedNativeMultihopCommand(a, sel, nil)",
                     'return nil, errors.New("unavailable")')
        self.assertFalse(self.recovered["controller_multihop_platform"]("darwin"))
        self.assertFalse(self.legacy["macOS native AppKit packages"]())
        self.changes.clear()
        self.replace("modes/native-multihop-darwin.sh", "kill-switch-platform.py", "unprotected-helper.py")
        self.assertFalse(self.recovered["controller_multihop_platform"]("darwin"))
        self.assertFalse(self.legacy["macOS native AppKit packages"]())


class MacUnifiedCompilerAuditTests(unittest.TestCase):
    def test_actual_map_audit_checks_compiler_inputs_without_stale_adjacency(self):
        path = ROOT / "deploy/unified-map-shipping-audit.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == "macos_compiler_closure"]
        self.assertEqual(len(functions), 1)
        self.assertTrue(any(isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                            and isinstance(node.value.func, ast.Name) and node.value.func.id == "macos_compiler_closure"
                            for node in tree.body))
        body = (ROOT / "client/macos/build-native-app.sh").read_text(encoding="utf-8")
        changes, errors = {}, []
        scope = {"read": lambda _: changes.get("body", body), "errors": errors, "re": re, "shlex": shlex}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), scope)
        scope["macos_compiler_closure"]()
        self.assertEqual(errors, [])
        # Reordering an independent extension must not invalidate the map gate.
        changed = body.replace('"$DNS_PANEL_SRC" "$GLOBE_SRC"', '"$GLOBE_SRC" "$DNS_PANEL_SRC"')
        self.assertNotEqual(changed, body)
        changes["body"] = changed
        scope["macos_compiler_closure"]()
        self.assertEqual(errors, [])
        before_compiler, compiler = body.split("xcrun swiftc ", 1)
        for name in ("HARDENED_UNIFIED_SRC", "TELEMETRY_SRC", "SPEED_LAB_SRC", "SPEED_LAB_TRANSPORT_SRC",
                     "MTU_TRANSPORT_SRC", "MTU_CONTROLLER_SRC", "MTU_PANEL_SRC",
                     "DNS_TRANSPORT_SRC", "DNS_CONTROLLER_SRC", "DNS_PANEL_SRC", "GLOBE_SRC",
                     "PROFILE_SRC", "PROFILE_CHROME_SRC", "ONBOARDING_SRC", "HOME_SRC", "SETTINGS_SRC"):
            with self.subTest(removed=name):
                token = '"$' + name + '"'
                self.assertIn(token, body)
                errors.clear()
                # The file declaration and a comment cannot replace the input.
                changes["body"] = before_compiler + "xcrun swiftc " + compiler.replace(token, "", 1) + "\n# " + token + "\n"
                scope["macos_compiler_closure"]()
                self.assertTrue(errors, "Uncompiled map extension passed the real audit")
        for changed in (
            body.replace('"$GLOBE_SRC"', '"$GLOBE_SRC" "$GLOBE_SRC"', 1),
            body.replace("xcrun swiftc ", "# xcrun swiftc ", 1),
            body + '\nxcrun swiftc "$GLOBE_SRC"\n',
        ):
            errors.clear(); changes["body"] = changed
            scope["macos_compiler_closure"]()
            self.assertTrue(errors, "Invalid compiler owner passed the real audit")


class LinuxDNSMeasurementAuditTests(unittest.TestCase):
    def test_actual_product_audit_follows_panel_dispatch_and_cleanup(self):
        path = ROOT / "deploy/product-parity-audit.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == "linux_dns_measurement_controls"]
        self.assertEqual(len(functions), 1)
        self.assertTrue(any(isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                            and isinstance(node.value.func, ast.Name) and node.value.func.id == "linux_dns_measurement_controls"
                            for node in tree.body))
        changes, errors = {}, []

        def require(path, *markers):
            body = changes[path] if path in changes else (ROOT / path).read_text(encoding="utf-8")
            errors.extend(path + ": missing " + marker for marker in markers if marker not in body)
            return body

        scope = {"require": require, "errors": errors, "re": re}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), scope)
        scope["linux_dns_measurement_controls"]()
        self.assertEqual(errors, [])
        mutations = (
            ("client/linux/build-native-app.sh", '#include "routervpn-dns-measurement-v1.inc"\\n', ""),
            ("client/linux/build-native-app.sh", 'G_CALLBACK(linux_dns_parent_delete_v1)', 'G_CALLBACK(unrelated_close)'),
            ("client/linux/routervpn-gtk-product-v5.c", "linux_dns_retest_v1(app);", "unrelated_retest(app);"),
            ("client/linux/apply-async-actions.py", "linux_dns_retest_v1((App *)data);", "unrelated_retest((App *)data);"),
            ("client/linux/routervpn-dns-measurement-v1.inc", 'g_strcmp0(token, s->token) != 0', "FALSE"),
            ("client/linux/routervpn-dns-measurement-v1.inc", "s->complete && s->drained", "s->complete"),
            ("client/linux/routervpn-dns-measurement-v1.inc", '"/api/dns/measurement/select"', '"/api/dns/policy"'),
            ("client/linux/routervpn-dns-measurement-v1.inc", 'post_and_log(s->app, "/api/dns/retest"', 'post_and_log(s->app, "/api/unrelated"'),
            (".github/workflows/linux-native-app.yml", "python3 deploy/test_linux_dns_measurement.py", "python3 unrelated.py"),
        )
        for changed_path, before, after in mutations:
            with self.subTest(path=changed_path, removed=before):
                original = (ROOT / changed_path).read_text(encoding="utf-8")
                self.assertIn(before, original)
                changes.clear(); errors.clear(); changes[changed_path] = original.replace(before, after)
                scope["linux_dns_measurement_controls"]()
                self.assertTrue(errors, "Broken DNS shipping composition passed the real audit")


class WindowsProfileControlsAuditTests(unittest.TestCase):
    def test_actual_product_audit_traces_captured_quick_control_and_full_settings(self):
        path = ROOT / "deploy/product-parity-audit.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == "windows_profile_controls"]
        self.assertEqual(len(functions), 1)
        self.assertTrue(any(isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                            and isinstance(node.value.func, ast.Name) and node.value.func.id == "windows_profile_controls"
                            for node in tree.body), "Actual product audit stopped invoking the shipping control gate")
        changes, errors = {}, []
        def require(path, *markers):
            body = changes[path] if path in changes else (ROOT / path).read_text(encoding="utf-8")
            errors.extend(path + ": missing " + marker for marker in markers if marker not in body)
            return body
        scope = {"require": require, "errors": errors, "re": re}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), scope)
        scope["windows_profile_controls"]()
        self.assertEqual(errors, [])
        mutations = (
            ("client/RouterVPN-Windows-App.ps1", ". ([ScriptBlock]::Create($ProfileSettingsSource))", "$null"),
            ("client/RouterVPN-Windows-UnifiedShell.ps1", "$DisplayedProfileID=[string]$RouterCombo.SelectedValue", "$DisplayedProfileID='replacement'"),
            ("client/RouterVPN-Windows-UnifiedShell.ps1", "Set-RouterVPNProfileProtection -BaseUrl", "Set-UnrelatedProtection -BaseUrl"),
            ("client/RouterVPN-Windows-ProfileSettings.ps1", "[string]$captured.profile_id -cne $DisplayedProfileID", "$false"),
            ("client/RouterVPN-Windows-ProfileSettings.ps1", "profile_token=[string]$captured.profile_token", "profile_token='unrelated-source'"),
            ("client/RouterVPN-Windows-ProfileSettings.ps1", "'/api/profile/protection') -Method Get", "'/api/profile/settings') -Method Get"),
            ("client/RouterVPN-Windows-ProfileSettings.ps1", "'/api/profile/protection') -Method Post", "'/api/profile/settings') -Method Post"),
            ("client/RouterVPN-Windows-ProfileSettings.ps1", "-Body ($body | ConvertTo-Json -Compress)", "-Body ($captured | ConvertTo-Json -Compress)"),
            ("cmd/client/profile_settings.go", 'h.HandleFunc("/api/profile/protection", a.profileProtectionSettings)', "// route removed"),
            ("cmd/client/profile_protection.go", "profileStartupSettingsToken(current) != capture.revision", "false"),
            ("cmd/client/profile_protection.go", "a.beginProtectionAwareMutationOperation(r, true)", "a.beginUnrelatedMutation(r)"),
            ("cmd/client/profile_protection.go", "q.ProfileToken != capture.token", "false"),
            ("cmd/client/profile_protection.go", "a.nodeProtection != capture.slot", "false"),
            ("cmd/client/profile_protection.go", 'fields["kill_switch_policy"] == nil', "false"),
            ("cmd/client/profile_protection.go", "decodeRelayControlJSON(raw, &q)", "decodeUnrelatedJSON(raw, &q)"),
            ("cmd/client/multihop_exact_json.go", "decoder.DisallowUnknownFields()", "// unchecked fields"),
            ("cmd/client/multihop_exact_json.go", "err != nil || !ok || seen[name]", "err != nil || !ok"),
            ("cmd/client/profile_protection_owned.go", "capture.view.token(capture.revision)", "capture.revision"),
            ("cmd/client/desktop_node_protection_off.go", "s.binding.ProfileID != profileID", "false"),
            ("cmd/client/desktop_node_protection_off.go", "s.viewLocked().token(profileRevision) != token", "false"),
            ("cmd/client/desktop_node_protection_off.go", "s.backend.read(ctx, &capture.target)", "readUnrelated(ctx)"),
            ("cmd/client/desktop_node_protection_off.go", "s.backend.read(ctx, nil)", "readUnrelated(ctx)"),
            ("cmd/client/desktop_node_protection_off.go", "capture.owner.Close(ctx)", "closeUnrelated(ctx)"),
            ("cmd/client/desktop_node_protection_windows.go", "mobiletor.NewDesktopWindowsProtectionRecoveryTarget(ctx, target)", "mobiletor.NewDesktopWindowsProtectionRecovery(ctx)"),
            ("cmd/client/profile_protection_owned.go", "saveErr = a.persistProfilesLocked()", "saveErr = nil"),
            ("cmd/client/profile_protection_owned.go", "errors.Join(errDesktopProtectionOffUnsaved, saveErr)", "nil"),
            ("cmd/client/desktop_node_owned.go", "a.resumeDesktopProtectionOff(ctx, slot, pending, true)", "a.resumeUnrelatedOff(ctx)"),
            ("cmd/client/operation_guard.go", "a.guardDesktopProtectionOffPending()", "unrelatedGuard()"),
            ("client/RouterVPN-Windows-ProfileSettings.ps1", "-Body ($body | ConvertTo-Json -Compress) -TimeoutSec 30", "-Body ($body | ConvertTo-Json -Compress) -TimeoutSec 8"),
            ("client/RouterVPN-Windows-UnifiedShell.ps1", "Get-RouterVPNProtectionPresentation -Captured $Protection", "Get-UnrelatedPresentation -Captured $Protection"),
            ("client/RouterVPN-Windows-UnifiedShell.ps1", "Show-RouterVPNProfileSettingsDialog -BaseUrl", "Show-UnrelatedSettings -BaseUrl"),
            ("client/RouterVPN-Windows-ProfileSettings.ps1", "'/api/profile/settings') -Method Post", "'/api/unrelated/settings') -Method Post"),
        )
        for changed_path, before, after in mutations:
            with self.subTest(path=changed_path, removed=before):
                original = (ROOT / changed_path).read_text(encoding="utf-8")
                self.assertIn(before, original)
                changes.clear(); errors.clear()
                changes[changed_path] = original.replace(before, after)
                scope["windows_profile_controls"]()
                self.assertTrue(errors, "Broken shipping control passed its actual product audit")


class CapturedTorDNSAuditTests(unittest.TestCase):
    def test_actual_product_audit_requires_captured_idle_and_connection_dns_paths(self):
        path = ROOT / "deploy/product-parity-audit.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == "captured_tor_dns_policy"]
        self.assertEqual(len(functions), 1)
        self.assertTrue(any(isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                            and isinstance(node.value.func, ast.Name) and node.value.func.id == "captured_tor_dns_policy"
                            for node in tree.body), "Product audit stopped invoking captured Tor DNS validation")
        changes, errors = {}, []

        def require(relative, *markers):
            body = changes[relative] if relative in changes else (ROOT / relative).read_text(encoding="utf-8")
            errors.extend(relative + ": missing " + marker for marker in markers if marker not in body)
            return body

        scope = {"require": require, "errors": errors, "re": re}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), scope)
        scope["captured_tor_dns_policy"]()
        self.assertEqual(errors, [])
        mutations = (
            ("cmd/client/tor_bridge_runtime.go", 'return protocol == "tor" || protocol == "tor-bridge"', 'return protocol == "tor-bridge"'),
            ("cmd/client/tor_bridge_runtime.go", 'return protocol == "tor" || protocol == "tor-bridge"', 'return protocol == "tor"'),
            ("cmd/client/dns_policy_external.go", "if desktopTorProtocol(profile.External.Protocol)", 'if profile.External.Protocol == "tor-bridge"'),
            ("cmd/client/desktop_tor_prepare.go", "desktopTorProtocol(policy.External.Protocol)", 'policy.External.Protocol == "tor-bridge"'),
            ("cmd/client/external_profile_connect.go", 'case "tor", "tor-bridge":', 'case "tor-bridge":'),
            ("cmd/client/external_profile_connect.go", "if desktopTorProtocol(externalProfile.External.Protocol)", 'if externalProfile.External.Protocol == "tor-bridge"'),
            ("cmd/client/dns_policy_external.go", "_, err := capturedTorBridgeDNS(profile, entry, true)", "_, err := selectedTorBridgeDNS(profile)"),
            ("cmd/client/dns_policy_external.go", "profile = cloneRouterProfile(profile)", "profile = common.RouterProfile{}"),
            ("cmd/client/dns_policy_external.go", "profile.MultihopEntryMode = mode", "profile.MultihopEntryMode = unrelatedMode"),
            ("cmd/client/dns_policy_external.go", "mobiletor.SelectDesktopBridgeDNS(string(raw), entryJSON, idle)", 'mobiletor.SelectDesktopBridgeDNS(string(raw), "", idle)'),
            ("cmd/client/external_profile_connect.go", "_, err = capturedTorBridgeDNS(policy, entry, false)", "_, err = capturedTorBridgeDNS(policy, entry, true)"),
            ("cmd/client/tor_bridge_routes.go", "a.torBridgeConnectSelectionOwned(w, profile, externalProfileConnectRequest{ProfileID: profile.ID}, startup, desktopTorConnectRuntime{})", "a.unrelatedTorConnect(w, profile, startup)"),
            ("cmd/client/tor_bridge_routes.go", "a.torBridgeConnectSelectionOwned(w, profile, q, nil, driver)", "a.torBridgeConnectOwned(w, profile)"),
            ("cmd/client/external_profile_connect.go", "a.torBridgeConnectSelectionOwned(w, externalProfile, q, startup, driver.tor)", "a.torBridgeConnectOwned(w, externalProfile)"),
            ("cmd/client/desktop_tor_selection.go", "direct = *q.Direct", "direct = !profile.MultihopEnabled"),
            ("cmd/client/desktop_tor_selection.go", "entryID = profile.MultihopEntryID", "entryID = unrelatedEntryID"),
            ("cmd/client/desktop_tor_selection.go", "desktopTorEntryMode(profile, entry, q.EntryMode, base)", 'desktopTorEntryMode(profile, entry, "", "")'),
            ("cmd/client/desktop_tor_selection.go", "captureDesktopTorPredecessor(a, policy, lookup)", "unrelatedTorPredecessor(a, policy, lookup)"),
            ("cmd/client/desktop_tor_selection.go", "desktopTorSourceIdentityToken(entry) != selection.predecessor.profileToken", "false"),
            ("cmd/client/desktop_tor_selection.go", "policy, err = externalDNSPolicyForPath(policy, entry, direct)", "policy, err = externalDNSPolicyForPath(policy, common.RouterProfile{}, true)"),
            ("cmd/client/desktop_tor_selection.go", "policy, err = externalDNSPolicyForPath(policy, entry, direct)\n\tif err != nil {\n\t\treturn nil, err\n\t}", "policy, err = externalDNSPolicyForPath(policy, entry, direct)\n\terr = nil"),
            ("cmd/client/desktop_tor_predecessor_external.go", "if _, err := standardExitFromExternalProfile(entry); err != nil", "if _, err := standardExit{}, error(nil); err != nil"),
            ("cmd/client/desktop_tor_predecessor_external.go", 'mode != "" && mode != entry.External.Protocol', "false"),
            ("cmd/client/desktop_tor_predecessor_external.go", "copyDNSPolicy(&runtimeProfile, policy)", "copyDNSPolicy(&runtimeProfile, source)"),
            ("cmd/client/desktop_tor_predecessor_external.go", "entry: source, profileToken: desktopTorSourceIdentityToken(source)", "entry: runtimeProfile, profileToken: desktopTorSourceIdentityToken(runtimeProfile)"),
            ("cmd/client/desktop_tor_predecessor_external.go", "mobiletor.NewDesktopExternalPredecessor(mode, string(raw), string(launch.external.source), assets)", "mobiletor.NewDesktopExternalPredecessor(mode, string(raw), string(launch.config), assets)"),
            ("cmd/client/tor_bridge_routes.go", "lookup = desktopTorEndpointLookup", "lookup = nil"),
            ("cmd/client/tor_bridge_routes.go", "selection, err := captureDesktopTorSelection(a, profile, capturedRequest, lookup)", "selection, err := captureDesktopTorSelection(a, profile, capturedRequest, nil)"),
            ("cmd/client/tor_bridge_routes.go", "capturedRequest := cloneDesktopTorConnectRequest(q)", "capturedRequest := externalProfileConnectRequest{}"),
            ("cmd/client/tor_bridge_routes.go", "a.retainedExternalStartupExecution(startup) != driver.startupExecution", "false"),
            ("cmd/client/tor_bridge_routes.go", 'desktopTorExecution(driver.startupExecution) == ""', "false"),
            ("cmd/client/tor_bridge_routes.go", "capturedRequest.Execution = driver.startupExecution", "capturedRequest.Execution = q.Execution"),
            ("cmd/client/tor_bridge_routes.go", "a.torBridgeCompareSelectionOwned(w, profile, q, startup, driver)", "a.unrelatedTorCompare(w, profile, q)"),
            ("cmd/client/desktop_tor_comparison_driver.go", "captureDesktopTorSelection(a, profile, choice, lookup)", "captureDesktopTorSelection(a, profile, request, lookup)"),
            ("cmd/client/desktop_tor_comparison_driver.go", "!reflect.DeepEqual(localPolicy, serverPolicy)", "false"),
            ("cmd/client/desktop_tor_comparison_driver.go", "local.predecessor.profileToken != server.predecessor.profileToken", "false"),
            ("cmd/client/desktop_tor_comparison_routes.go", "winner.retainPath(cleanup)", "unrelatedRetainedProof()"),
            ("cmd/client/tor_bridge_routes.go", "prepareTorBridgeCommandWithRuntime(a, policy, profile, selection.predecessor, driver)", "prepareTorBridgeCommandWithRuntime(a, policy, profile, nil, driver)"),
            ("cmd/client/tor_bridge_routes.go", "a.validateExternalProfileExpectedProfiles(q, profile)", "unrelatedSourceCheck(q, profile)"),
            ("cmd/client/tor_bridge_routes.go", "if err := check(); err != nil {\n\t\tfailure := errors.Join(err, prelaunch.cleanup())", "if err := unrelatedCheck(); err != nil {\n\t\tfailure := errors.Join(err, prelaunch.cleanup())"),
            ("cmd/client/desktop_tor_prepare.go", "driver.runtime = prepareTorBridgeRuntimeWithPredecessor", "driver.runtime = unrelatedRuntime"),
            ("cmd/client/desktop_tor_prepare.go", "launch.tor.predecessor != predecessor", "false"),
            ("cmd/client/desktop_tor_prepare.go", "preflightDesktopTorLaunch(a.connectionOperationContextOrBackground(), prepared.NativeBinary, launch, environment, driver.preflight)", "unrelatedPreflight()"),
            ("cmd/client/tor_bridge_prelaunch.go", "desktopTorSourceIdentityToken(profile) == launch.tor.profileToken", "true"),
            ("cmd/client/tor_bridge_prelaunch.go", "launch.tor.entryCurrent(owner.app)", "unrelatedEntryCheck(owner.app)"),
            ("cmd/client/tor_bridge_prelaunch.go", "if err := check(); err != nil {\n\t\t\tdesktopNodeOwners.CompareAndDelete(owner.app, launch)", "if err := unrelatedCheck(); err != nil {\n\t\t\tdesktopNodeOwners.CompareAndDelete(owner.app, launch)"),
            ("cmd/client/tor_bridge_prelaunch.go", "registerActiveDNSRuntimeConfig(owner.app, owner.dns.ProfileID, owner.dns.RuntimeID, owner.dns.Config)", "registerUnrelatedDNSConfig(owner.app)"),
            ("internal/mobiletor/desktop_dns.go", '(profile["multihop_enabled"] == true) != (entryJSON != "")', "false"),
            ("internal/mobiletor/desktop_dns.go", "NewPredecessorProof(entryJSON)", "unprovedEntry(entryJSON)"),
            ("internal/mobiletor/desktop_dns.go", 'profile["multihop_entry_id"] != entry["id"]', "false"),
            ("internal/mobiletor/desktop_dns.go", 'profile["multihop_exit_id"] != profile["id"]', "false"),
            ("internal/mobiletor/desktop_dns.go", 'profileString(profile, "multihop_execution") != "local"', "false"),
            ("internal/mobiletor/desktop_dns.go", "torSelectedDNS(profile, entry, idle)", "torSelectedDNS(profile, nil, true)"),
            ("internal/mobiletor/profile.go", "if entry == nil && !idle", "if false"),
            ("internal/mobiletor/profile.go", "if host == address", "if true"),
            ("internal/mobiletor/profile.go", "address.IsPrivate() != home", "false"),
            ("internal/mobiletor/profile.go", 'protocol != "tcp" && protocol != "tls" && protocol != "https" && !(home && (protocol == "udp" || protocol == "h3"))', "false"),
        )
        for relative, before, after in mutations:
            with self.subTest(path=relative, removed=before):
                original = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIn(before, original)
                changes.clear(); errors.clear()
                # A stale helper name or an unattached marker cannot satisfy
                # the required call/guard inside the shipping function.
                changes[relative] = original.replace(before, after) + "\n// " + before + "\n"
                scope["captured_tor_dns_policy"]()
                self.assertTrue(errors, "Broken captured Tor DNS path passed the real product audit")
        for relative, block, later in (
            ("cmd/client/desktop_tor_selection.go",
             "\tpolicy, err = externalDNSPolicyForPath(policy, entry, direct)\n\tif err != nil {\n\t\treturn nil, err\n\t}\n",
             "\tselection.policy = policy"),
            ("cmd/client/desktop_tor_predecessor_external.go",
             "\tcopyDNSPolicy(&runtimeProfile, policy)\n", "\tif launch == nil"),
        ):
            with self.subTest(path=relative, reordered=block):
                original = (ROOT / relative).read_text(encoding="utf-8")
                self.assertEqual(original.count(block), 1)
                self.assertEqual(original.count(later), 1)
                changes.clear(); errors.clear()
                changes[relative] = original.replace(block, "").replace(later, block + later)
                scope["captured_tor_dns_policy"]()
                self.assertTrue(errors, "DNS selection after ordinary transport compilation passed the real product audit")


if __name__ == "__main__":
    unittest.main()
