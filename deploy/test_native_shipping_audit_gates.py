#!/usr/bin/env python3
"""Execute actual native shipping audit predicates against broken call paths."""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import re
import shlex
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
_NATIVE_SPEC = importlib.util.spec_from_file_location("native_multihop_source_guard", ROOT / "deploy/native_multihop_audit.py")
_NATIVE = importlib.util.module_from_spec(_NATIVE_SPEC)
_NATIVE_SPEC.loader.exec_module(_NATIVE)


class NativeShippingAuditTests(unittest.TestCase):
    def setUp(self):
        self.changes = {}
        weighted = ast.parse((ROOT / "deploy/weighted-release-audit.py").read_text(encoding="utf-8"))
        functions = [node for node in weighted.body if isinstance(node, ast.FunctionDef)
                     and node.name in ("windows_owned_package", "retained_native_multihop_platform")]
        self.assertEqual(len(functions), 2)
        self.scope = {"all_markers": self.has, "none_markers": self.no,
                      "body": self.body, "native_multihop_shipping_chain": _NATIVE.native_multihop_shipping_chain,
                      "native_multihop_proof_lanes": _NATIVE.native_multihop_proof_lanes,
                      "native_multihop_proof_admission": _NATIVE.native_multihop_proof_admission}
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

    def assert_multihop_scores(self, expected):
        for platform in ("windows", "darwin"):
            self.assertEqual(self.scope["retained_native_multihop_platform"](platform), expected)
            self.assertEqual(self.recovered["controller_multihop_platform"](platform), expected)
        for gate in self.legacy.values():
            self.assertEqual(gate(), expected)

    def assert_backend_proof_admission(self, expected):
        backend = ast.parse((ROOT / "deploy/backend-session-transaction-audit.py").read_text())
        functions = [node for node in backend.body if isinstance(node, ast.FunctionDef)
                     and node.name == "require_native_multihop_proof_admission"]
        self.assertEqual(len(functions), 1)
        invocations = [node for node in backend.body if isinstance(node, ast.Expr)
                       and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                       and node.value.func.id == "require_native_multihop_proof_admission"]
        self.assertEqual(len(invocations), 1, "backend audit must execute its proof-admission guard")
        scope = {"read": self.body, "errors": [],
                 "native_multihop_proof_admission": _NATIVE.native_multihop_proof_admission}
        exec(compile(ast.Module(body=functions + invocations, type_ignores=[]), "backend-native-proof", "exec"), scope)
        self.assertEqual(not scope["errors"], expected)

    def test_backend_proof_guard_uses_original_runtime_context_and_dns(self):
        self.assert_backend_proof_admission(True)
        for path, before, after in (
            ("cmd/client/multihop_native_capture.go", "a.nativeMultihopProofOwnerCurrentContext(ctx, sel, command)",
             "a.nativeMultihopProofOwnerCurrentContext(context.Background(), sel, command)"),
            ("cmd/client/multihop_native_capture.go", "command != nil && a.cmd == command && !a.closing", "true"),
            ("cmd/client/multihop_native_capture.go", "a.profiles.SelectedID == sel.Control.ID", "true"),
            ("cmd/client/multihop_native_capture.go", "mobilemtu.LockContext(ctx, &a.mu)",
             "mobilemtu.LockContext(context.Background(), &a.mu)"),
            ("cmd/client/multihop_native_capture.go", "a.proveImportedNativeDNS(ctx, sel, command)",
             "a.proveImportedNativeDNS(ctx, sel, other)"),
            ("cmd/client/multihop_native_imported.go", "proveMultihopLaneNodeContext(ctx, profile, proxy)",
             "proveMultihopLaneNodeContext(context.Background(), profile, proxy)"),
            ("cmd/client/multihop_native_imported_dns.go", "expectedDNSSelection(selection.Exit)",
             "expectedDNSSelection(selection.Entry)"),
        ):
            with self.subTest(path=path, before=before):
                self.changes.clear()
                self.replace(path, before, after)
                self.changes[path] += "\n// " + before + "\n"
                self.assert_backend_proof_admission(False)

    def assert_speedlab_imported_platform(self, expected):
        source = ast.parse((ROOT / "deploy/speed-lab-shipping-audit.py").read_text())
        functions = [node for node in source.body if isinstance(node, ast.FunctionDef)
                     and node.name == "need_imported_speed_lab_current"]
        self.assertEqual(len(functions), 1)
        scope = {"read": self.body, "errors": [], "_native_module": _NATIVE}
        exec(compile(ast.Module(body=functions, type_ignores=[]), "speedlab-imported-platform", "exec"), scope)
        scope["need_imported_speed_lab_current"]()
        self.assertEqual(not scope["errors"], expected)

    def test_platform_adapter_requires_concrete_native_owner_and_both_proofs(self):
        self.assert_backend_proof_admission(True)
        self.assert_speedlab_imported_platform(True)
        lifecycle = "cmd/client/desktop_imported_linux_lifecycle.go"
        for path, before, after in (
            ("cmd/client/desktop_node_owned.go", "return guardDesktopImportedPlatformTransition(ctx, a, next)", "return nil"),
            (lifecycle, "owner, ok := launch.importedPlatform.(*desktopLinuxImportedConnection)", "owner, ok := launch.importedPlatform.(desktopImportedPlatformRuntime)"),
            (lifecycle, "!owner.registered", "false"),
            (lifecycle, "_, retained := p.dependents[h]", "retained := true"),
            (lifecycle, "return h.CheckLegacyTransition(ctx)", "return nil"),
            (lifecycle, "s.active != h", "false"),
            (lifecycle, "s.currentLocked(ctx)", "nil"),
            (lifecycle, "h.runningPolicyLocked(ctx)", "nil"),
            (lifecycle, "h.readReadyLocked(ctx, false)", "h.readReadyLocked(context.Background(), false)"),
            (lifecycle, "proveNativeMultihopCapture(ctx, owner.selection, func() bool { return current(ctx) == nil }, proveNativeMultihopLaneContext)", "nil"),
            (lifecycle, "expectedDNSSelection(owner.selection.Exit)", "expectedDNSSelection(owner.selection.Entry)"),
            (lifecycle, "verifySingBoxDNSConfigBytes(h.launch.config, selected)", "nil"),
            (lifecycle, "return owner.session.Monitor(ctx, owner.host)", "return nil"),
            ("cmd/client/desktop_imported_platform.go", "launch.importedPlatform.Start(ctx)", "launch.importedPlatform.Start(context.Background())"),
            ("cmd/client/desktop_imported_platform.go", "launch.importedPlatform.Current(ctx)", "nil"),
            ("cmd/client/multihop_native_launch.go", "if current, found := desktopNodeOwners.Load(a); !found || current != launch {", "if false {"),
        ):
            with self.subTest(path=path, before=before):
                self.changes.clear()
                self.replace(path, before, after)
                self.changes[path] += "\n// " + before + "\n"
                self.assert_backend_proof_admission(False)
                self.assert_speedlab_imported_platform(False)
                self.assert_multihop_scores(False)

    def test_platform_start_proof_activation_and_successor_intent_keep_original_caller(self):
        path = "cmd/client/multihop_native_routes.go"
        for before, after in (
            ("a.stopModeWithIntent(native.ownedNode != nil || native.importedPlatform != nil)", "a.stopModeWithIntent(native.ownedNode != nil)"),
            ("startDesktopImportedPlatform(operation, a, sel, native)", "startDesktopImportedPlatform(context.Background(), a, sel, native)"),
            ("proofErr = native.importedPlatform.Activate(operation)", "proofErr = nil"),
        ):
            with self.subTest(before=before):
                self.changes.clear()
                self.replace(path, before, after)
                self.changes[path] += "\n// " + before + "\n"
                self.assert_multihop_chain(False)

    def test_platform_duplicate_or_missing_observer_cannot_supply_authority(self):
        self.assertFalse(_NATIVE.native_multihop_platform_chain(None))
        path = "cmd/client/desktop_imported_linux_lifecycle.go"
        self.changes[path] = self.body(path) + "\nfunc (owner *desktopLinuxImportedConnection) Current(ctx context.Context) error { return nil }\n"
        self.assert_backend_proof_admission(False)
        self.assert_speedlab_imported_platform(False)

    def assert_multihop_chain(self, expected):
        self.assert_multihop_scores(expected)
        # Exercise the actual backend audit hook, including its read/error path.
        backend = ast.parse((ROOT / "deploy/backend-session-transaction-audit.py").read_text())
        functions = [node for node in backend.body if isinstance(node, ast.FunctionDef)
                     and node.name == "require_native_multihop_shipping_chain"]
        self.assertEqual(len(functions), 1)
        invocations = [node for node in backend.body if isinstance(node, ast.Expr)
                       and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                       and node.value.func.id == "require_native_multihop_shipping_chain"]
        self.assertEqual(len(invocations), 1, "backend audit must execute its shipping-chain guard")
        scope = {"read": self.body, "errors": [],
                 "native_multihop_shipping_chain": _NATIVE.native_multihop_shipping_chain}
        exec(compile(ast.Module(body=functions + invocations, type_ignores=[]), "backend-native-closure", "exec"), scope)
        self.assertEqual(not scope["errors"], expected)

    def test_paired_and_imported_proof_calls_require_original_arguments(self):
        changes = (
            ("cmd/client/multihop_native_capture.go", "proveNativeMultihopCapture(ctx, sel, current, proveNativeMultihopLaneContext)",
             "proveNativeMultihopCapture(ctx, sel, current, proveMultihopLaneNodeContext)"),
            ("cmd/client/multihop_native_capture.go", "prove(ctx, sel.Entry, multihopEntryProofProxy)", "prove(ctx, sel.Exit, multihopEntryProofProxy)"),
            ("cmd/client/multihop_native_capture.go", "prove(ctx, sel.Exit, multihopProofProxy)", "prove(ctx, sel.Entry, multihopProofProxy)"),
            ("cmd/client/multihop_native_imported.go", 'if profile.NodeKind != "external" {', 'if profile.NodeKind == "external" {'),
            ("cmd/client/multihop_native_imported.go", "proveMultihopLaneNodeContext(ctx, profile, proxy)", "proveMultihopLaneNodeContext(context.Background(), profile, proxy)"),
            ("cmd/client/multihop_native_imported.go", "proxy != multihopEntryProofProxy", "proxy != multihopProofProxy"),
            ("cmd/client/multihop_native_imported.go", "!desktopImportedEntryProtocol(profile.External.Protocol)", "false"),
            ("cmd/client/multihop_native_imported.go", "newMultihopLaneHTTPClient(proxy, 2500*time.Millisecond)", "newMultihopLaneHTTPClient(multihopProofProxy, 2500*time.Millisecond)"),
            ("cmd/client/multihop_native_imported.go", 'profile.External.ExpectedPublicIP, "imported entry", 3*time.Second', '"", "imported entry", 3*time.Second'),
        )
        for path, before, after in changes:
            for replacement in (after, "/* " + before + " */", '"' + before.replace('"', '\\"') + '"'):
                with self.subTest(path=path, before=before, replacement=replacement):
                    self.changes.clear()
                    self.replace(path, before, replacement)
                    self.assert_multihop_scores(False)

    def test_original_runtime_profile_and_context_guards_are_required(self):
        path = "cmd/client/multihop_native_capture.go"
        changes = (
            ("a.nativeMultihopProofOwnerCurrentContext(ctx, sel, command)", "a.nativeMultihopProofOwnerCurrentContext(ctx, sel, other)"),
            ("a.connectionOperationContextOrBackground(), nativeMultihopProofTimeout(sel)", "context.Background(), nativeMultihopProofTimeout(sel)"),
            ("command != nil && a.cmd == command && !a.closing", "true"),
            ("a.profiles.SelectedID == sel.Control.ID", "true"),
            ("mtuProfileSnapshotToken(current) == mtuProfileSnapshotToken(captured)", "true"),
            ("mobilemtu.LockContext(ctx, &a.mu)", "mobilemtu.LockContext(context.Background(), &a.mu)"),
            ("a.observeImportedOpenVPN(ctx, sel, command) == nil", "true"),
            ("ctx.Err() != nil || !current()", "false"),
            ("!owns() || sel.Native == nil || sel.Native.validate(sel) != nil", "sel.Native == nil"),
            ("ctx.Err() != nil || !owns() || sel.Native.validate(sel) != nil", "ctx.Err() != nil"),
            ("err == nil && ctx.Err() == nil && owns() && sel.Native.validate(sel) == nil", "err == nil"),
        )
        for before, after in changes:
            with self.subTest(before=before):
                self.changes.clear()
                self.replace(path, before, after)
                self.changes[path] += "\n// " + before + "\n"
                self.assert_multihop_scores(False)

    def test_imported_selected_dns_is_required_after_transport_before_admission(self):
        capture = "cmd/client/multihop_native_capture.go"
        dns = "cmd/client/multihop_native_imported_dns.go"
        changes = (
            (capture, "if sel.Native.imported {", "if !sel.Native.imported {"),
            (capture, "a.proveImportedNativeDNS(ctx, sel, command)", "a.proveImportedNativeDNS(context.Background(), sel, command)"),
            (capture, "a.proveImportedNativeDNS(ctx, sel, command)", "a.proveImportedNativeDNS(ctx, sel, other)"),
            (dns, "owner.selection.Native != selection.Native", "false"),
            (dns, "!owner.launch.importedEntry", "false"),
            (dns, "!a.nativeMultihopProofOwnerCurrentContext(ctx, selection, command)", "false"),
            (dns, "desktopNodeProcessExited(owner.launch)", "false"),
            (dns, "actual != owner", "false"),
            (dns, "expectedDNSSelection(selection.Exit)", "expectedDNSSelection(selection.Entry)"),
            (dns, 'readDesktopRuntimeFileContext(ctx, owner.launch, "sing-box.json", 4<<20)', 'readDesktopRuntimeFileContext(ctx, other, "sing-box.json", 4<<20)'),
            (dns, "verifySingBoxDNSConfigBytes(raw, selected)", "nil"),
            (dns, "exchangeDesktopImportedDNS(parent, owner.launch, current)", "0, nil"),
            (dns, "a.observeImportedOpenVPN(parent, selection, command)", "a.observeImportedOpenVPN(context.Background(), selection, command)"),
            (dns, "a.observeImportedOpenVPN(parent, selection, command)", "nil"),
        )
        for path, before, after in changes:
            for replacement in (after, "/* " + before + " */"):
                with self.subTest(path=path, before=before, replacement=replacement):
                    self.changes.clear()
                    self.replace(path, before, replacement)
                    self.assert_multihop_scores(False)
        self.changes.clear()
        call = "if _, err := a.proveImportedNativeDNS(ctx, sel, command); err != nil {\n\t\t\treturn err\n\t\t}"
        self.replace(capture, call, "return nil /* " + call + " */")
        self.changes[capture] += "\nfunc unrelatedDNSWitness() { " + call + " }\n"
        self.assert_multihop_scores(False)

    def test_weighted_scores_require_both_graph_branches(self):
        for path, before, after in (
            ("cmd/client/multihop_native_capture.go", 'entryProofTag := "entry-wg"', 'entryProofTag := "entry-private"'),
            ("cmd/client/multihop_native_capture.go", 'entryProofTag = "entry-private"', 'entryProofTag = "proxy"'),
            ("cmd/client/multihop_native_imported.go", "nativeMultihopProofConfig(compiled.Config(), sel.Entry)", "nativeMultihopProofConfig(compiled.Config(), sel.Exit)"),
        ):
            with self.subTest(before=before):
                self.changes.clear()
                self.replace(path, before, after)
                self.assert_multihop_scores(False)

    def test_proof_guards_accept_formatting_but_not_duplicate_functions(self):
        path = "cmd/client/multihop_native_imported.go"
        self.replace(path, "proveMultihopLaneNodeContext(ctx, profile, proxy)", "proveMultihopLaneNodeContext(\nctx, /* original */ profile, proxy)")
        self.assert_multihop_scores(True)
        for path, declaration in (
            ("cmd/client/multihop_native_capture.go", "func (a *app) proveNativeMultihop(sel multihopSelection, command *exec.Cmd) error"),
            ("cmd/client/multihop_native_imported.go", "func proveNativeMultihopLaneContext(ctx context.Context, profile common.RouterProfile, proxy string) error"),
            ("cmd/client/multihop_native_imported_dns.go", "func (a *app) proveImportedNativeDNS(parent context.Context, selection multihopSelection, command *exec.Cmd) (float64, error)"),
        ):
            with self.subTest(declaration=declaration):
                self.changes.clear()
                self.changes[path] = self.body(path) + "\n" + declaration + " {}\n"
                self.assert_multihop_scores(False)

    def test_imported_compiler_requires_original_protected_host_and_legacy_wrapper(self):
        for path, before, after in (
            ("cmd/client/multihop_native_imported.go",
             "return captureDesktopImportedMultihopWithHost(ctx, root, sel, modes, lookup, nil)",
             "return unrelatedImportedCapture(ctx, root, sel, modes, lookup)"),
            ("cmd/client/multihop_native_capture.go",
             "captureDesktopImportedMultihopWithHost(ctx, owner.capture.dataRoot, sel, modes, owner.host.lookup, owner)",
             "captureDesktopImportedMultihopWithHost(ctx, owner.capture.dataRoot, sel, modes, owner.host.lookup, nil)"),
            ("cmd/client/multihop_native_capture.go",
             "verifiedDesktopImportedPackage(ctx, owner)",
             "verifiedDesktopImportedPackage(context.Background(), owner)"),
            ("cmd/client/multihop_native_capture.go",
             "owner, err := captureDesktopImportedConnectionOwner(parent, a, sel)",
             "owner, err := captureDesktopImportedConnectionOwner(context.Background(), a, sel)"),
        ):
            with self.subTest(before=before):
                self.changes.clear()
                self.replace(path, before, after)
                self.changes[path] += "\n// " + before + "\n"
                self.assert_multihop_scores(False)
        self.changes.clear()
        path = "cmd/client/multihop_native_imported.go"
        self.changes[path] = self.body(path) + "\nfunc captureDesktopImportedMultihopWithHost(ctx context.Context, root string, sel multihopSelection, modes []string, lookup applexray.Lookup, host *desktopNodeConnectionOwner) (multihopSelection, error) {}\n"
        self.assert_multihop_scores(False)

    def test_exact_public_adapters_are_required_by_every_consumer(self):
        path = "cmd/client/multihop_native_routes.go"
        adapters = (
            ("capture", "captureNativeMultihopForApp"),
            ("preflight", "preflightOwnedNativeMultihopCommand"),
            ("stage", "stageOwnedNativeMultihopCommand"),
            ("proof", "(*app).proveNativeMultihop"),
        )
        for index, (field, adapter) in enumerate(adapters):
            original = f"{field}: {adapter},"
            for replacement in ("", f"{field}: nil,", f"{field}: {adapters[(index + 1) % 4][1]},"):
                with self.subTest(field=field, replacement=replacement):
                    self.changes.clear()
                    self.replace(path, original, replacement)
                    self.changes[path] += f"\n// {original}\n"
                    self.assert_multihop_chain(False)

    def test_owned_driver_and_runtime_calls_cannot_move_to_comments_or_other_functions(self):
        path = "cmd/client/multihop_native_routes.go"
        calls = (
            "sel, err = driver.capture(a, sel, []string{sel.ExitMode})",
            "native, err := driver.preflight(a, sel, nil)",
            "err = driver.stage(a, sel, native)",
            "cmd := native.command",
            "err = cmd.Start()",
            "err = bindNativeMultihopRuntime(a, native, sel, network)",
            "proofErr := driver.proof(a, sel, cmd)",
        )
        for call in calls:
            with self.subTest(call=call):
                self.changes.clear()
                self.replace(path, call, "unrelatedCall() /* " + call + " */")
                self.changes[path] += "\nfunc unrelatedSourceWitness() { " + call + " }\n"
                self.assert_multihop_chain(False)

    def test_public_route_wrapper_and_captured_arguments_cannot_be_retargeted(self):
        path = "cmd/client/multihop_native_routes.go"
        changes = (
            ('h.HandleFunc("/api/multihop/connect", a.nativeMultihopConnect)',
             'h.HandleFunc("/api/multihop/connect", a.otherConnect)'),
            ("a.nativeMultihopConnectOwned(w, r, nativeMultihopConnectRuntime{",
             "a.otherConnectOwned(w, r, nativeMultihopConnectRuntime{"),
            ("driver.capture(a, sel, []string{sel.ExitMode})", "driver.capture(a, sel, []string{ModeBasic})"),
            ("driver.preflight(a, sel, nil)", "driver.preflight(a, other, nil)"),
            ("driver.stage(a, sel, native)", "driver.stage(a, sel, other)"),
            ("driver.proof(a, sel, cmd)", "driver.proof(a, sel, other)"),
            ("proofErr := driver.proof(a, sel, cmd)", "driver.proof = unrelatedProof\nproofErr := driver.proof(a, sel, cmd)"),
        )
        for before, after in changes:
            with self.subTest(before=before):
                self.changes.clear()
                self.replace(path, before, after)
                self.changes[path] += "\n// " + before + "\n"
                self.assert_multihop_chain(False)

    def test_typed_imported_child_keeps_original_publication_and_proof_order(self):
        path = "cmd/client/multihop_native_routes.go"
        changes = (
            ("protected := native.ownedNode != nil", "protected := false"),
            ("a.publishDesktopImportedMultihopStartLocked(operation, native, sel)",
             "a.publishDesktopImportedMultihopStartLocked(context.Background(), native, sel)"),
            ("a.publishDesktopImportedMultihopStartLocked(operation, native, sel)",
             "a.publishDesktopImportedMultihopStartLocked(operation, other, sel)"),
            ("startDesktopOwnedImportedLaunch(operation, operation, a, native)",
             "startDesktopOwnedImportedLaunch(context.Background(), operation, a, native)"),
            ("startDesktopOwnedImportedLaunch(operation, operation, a, native)",
             "startDesktopOwnedImportedLaunch(operation, context.Background(), a, native)"),
            ("startDesktopOwnedImportedLaunch(operation, operation, a, native)",
             "startDesktopOwnedImportedLaunch(operation, operation, a, other)"),
        )
        for before, after in changes:
            with self.subTest(before=before, after=after):
                self.changes.clear()
                self.replace(path, before, after)
                self.changes[path] += "\n// " + before + "\n"
                self.assert_multihop_chain(False)

    def test_duplicate_public_or_owned_definition_cannot_supply_missing_calls(self):
        path = "cmd/client/multihop_native_routes.go"
        for declaration in (
            "func (a *app) nativeMultihopConnect(w http.ResponseWriter, r *http.Request)",
            "func (a *app) nativeMultihopConnectOwned(w http.ResponseWriter, r *http.Request, driver nativeMultihopConnectRuntime)",
        ):
            with self.subTest(declaration=declaration):
                self.changes.clear()
                self.changes[path] = self.body(path) + "\n" + declaration + " {}\n"
                self.assert_multihop_chain(False)

    def test_owned_calls_must_be_unique_and_in_launch_order(self):
        path = "cmd/client/multihop_native_routes.go"
        capture = "sel, err = driver.capture(a, sel, []string{sel.ExitMode})"
        preflight = "native, err := driver.preflight(a, sel, nil)"
        self.replace(path, capture, "temporaryCaptureMarker")
        self.replace(path, preflight, capture)
        self.replace(path, "temporaryCaptureMarker", preflight)
        self.assert_multihop_chain(False)
        self.changes.clear()
        self.replace(path, capture, capture + "\n" + capture)
        self.assert_multihop_chain(False)

    def test_source_guard_accepts_formatting_but_not_string_only_calls(self):
        path = "cmd/client/multihop_native_routes.go"
        self.replace(path, "capture: captureNativeMultihopForApp,", "capture: /* actual adapter */\n captureNativeMultihopForApp,")
        self.assert_multihop_chain(True)
        call = "proofErr := driver.proof(a, sel, cmd)"
        self.replace(path, call, 'proofErr := errors.New("' + call + '")')
        self.assert_multihop_chain(False)

    def test_shared_source_guard_retriggers_both_backend_consumers(self):
        for workflow in ("recovered-native-ui-gate.yml", "recovered-map-first-ui-gate.yml"):
            text = (ROOT / ".github/workflows" / workflow).read_text()
            for event in ("push", "pull_request"):
                section = re.search(r"^  " + event + r":\n(.*?)(?=^  [a-z_]+:|^permissions:)", text, re.M | re.S)
                self.assertIsNotNone(section, (workflow, event))
                self.assertIn('"deploy/native_multihop_audit.py"', section.group(1))

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
            ("cmd/windows-app-launcher/main.go", "windowsapp.Main(false)", "windowsapp.Main(true)"),
            ("cmd/portable-bootstrap/main.go", "windowsapp.Main(true)", "windowsapp.Main(false)"),
            ("cmd/portable-launcher/main_windows.go", "windowsapp.Main(true)", "legacyMain()"),
            ("internal/windowsapp/session_windows.go", "s.controller.Wait(ctx)", "s.self.Wait(ctx)"),
            ("internal/windowsapp/session_windows.go", "s.controllerShell.Close()", "s.selfImage.Close()"),
            ("internal/controllertransport/client.go", "subtle.ConstantTimeCompare([]byte(receipt.Token), []byte(client.shutdown)) != 1", "false"),
            ("internal/controllertransport/client.go", "!receipt.Closed", "false"),
            ("internal/windowsapp/entry_windows.go", "session.Close(retirement)", "error(nil)"),
            ("deploy/test_windows_recovery_launcher.py", "check_package_session(shell)", "pass"),
            ("client/test-windows-package-session.ps1", "Invoke-PackagedNativeSelfTest $RelocateTo $true", "# omit relocated native execution"),
            ("client/test-windows-package-session.ps1", "[IO.FileShare]::None", "[IO.FileShare]::ReadWrite"),
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
            ("cmd/client/multihop_native_launch.go", "stageOwnedNativeMultihopCommandContext(ctx, a, sel, launch)", "stageOwnedNativeMultihopCommand(a, sel, launch)"),
            ("cmd/client/multihop_native_launch.go", "stageDesktopNodeLaunchContext(ctx, a, launch)", "stageDesktopNodeLaunch(a, launch)"),
            ("cmd/client/multihop_native_launch.go", "observe = launch.ownedNode.imported.readNetwork", "observe = physicalNetworkIdentityContext"),
            ("cmd/client/multihop_native_launch.go", "actual, err := observe(ctx)", "actual, err := observe(context.Background())"),
            ("cmd/client/multihop_native_launch.go", "actual != network", "false"),
            ("cmd/client/multihop_native_launch.go", "!a.ownsConnectionRuntime(launch.command)", "false"),
            ("cmd/client/desktop_node_native.go", "receipt.ConfigSHA256 != configSHA256", "false"),
            ("cmd/client/desktop_node_native.go", 'writeDesktopRuntimeFileContext(ctx, launch, "sing-box.json", launch.config, false)',
             'writeDesktopRuntimeFile(launch, "sing-box.json", launch.config, false)'),
            ("cmd/client/multihop_native_routes.go", "driver.proof(a, sel, cmd)", "proveUnrelatedPath()"),
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
            ("cmd/client/desktop_node_protection_windows.go", "owner := windowsOwnedCapture.Load()", "owner := unrelatedCapture.Load()"),
            ("cmd/client/desktop_node_protection_windows.go", "return desktopOwnedNodeProtectionBackendFor(owner)", "return desktopOwnedNodeProtectionBackendFor(nil)"),
            ("cmd/client/desktop_node_protection_windows.go", "if owner == nil || owner.Alive() != nil", "if false"),
            ("cmd/client/desktop_node_protection_windows.go", "bootstrap: desktopNodeRecoveryBootstrap(owner)", "bootstrap: desktopNodeRecoveryBootstrap(nil)"),
            ("cmd/client/desktop_node_protection_windows.go", "mobiletor.ReadDesktopWindowsProtectionExpectation", "readUnrelatedProtection"),
            ("cmd/client/desktop_node_protection_windows.go", "mobiletor.ReadDesktopWindowsPreparedProtection(ctx, target.Capture, target.Policy, target.BaselineSHA256)", "readUnrelatedPreparedProtection(ctx)"),
            ("cmd/client/desktop_node_protection_windows.go", "mobiletor.NewDesktopWindowsProtectionReleaseTarget(ctx, target)", "mobiletor.NewDesktopWindowsProtectionRelease(ctx)"),
            ("cmd/client/desktop_node_protection_windows.go", "mobiletor.NewDesktopWindowsProtectionReleaseTargetWithBarrier(ctx, target, barrier)", "mobiletor.NewDesktopWindowsProtectionReleaseTarget(ctx, target)"),
            ("cmd/client/desktop_node_protection_windows.go", "mobiletor.NewDesktopWindowsProtectionRecoveryTarget(ctx, target)", "mobiletor.NewDesktopWindowsProtectionRecovery(ctx)"),
            ("cmd/client/profile_protection_owned.go", "a.persistProtectionOffProfilesLocked(ctx)", "unprovedSave()"),
            ("cmd/client/profile_protection_owned.go", "atomicWritePrivateChecked(a.cfg.ProfilesFile, append(raw, '\\n'), ctx.Err)", "atomicWritePrivateChecked(a.cfg.ProfilesFile, append(raw, '\\n'), nil)"),
            ("cmd/client/profile_protection_owned.go", "errors.Join(errDesktopProtectionOffUnsaved, err)", "nil"),
            ("cmd/client/profile_protection.go", "capture.revision, capture.resultRevision, capture.token", "capture.revision, capture.revision, capture.token"),
            ("cmd/client/profile_protection_owned.go", "profileStartupSettingsToken(profile) != capture.currentProfileRevision()", "false"),
            ("cmd/client/profile_protection_owned.go", "capture.profileWritten.Store(true)", "capture.profileWritten.Store(false)"),
            ("cmd/client/profile_protection_owned.go", "readPrivateRegular(capture.savedPath, maxPrivateStoreBytes)", "readUnrelatedStore()"),
            ("cmd/client/profile_protection_owned.go", "!bytes.Equal(raw, append(want, '\\n'))", "false"),
            ("cmd/client/profile_protection_owned.go", "slot.finishOffSave(ctx, capture, current)", "finishUnprovedOff()"),
            ("cmd/client/desktop_node_protection_off.go", "!capture.profileSaved.Load()", "false"),
            ("cmd/client/desktop_node_protection_windows.go", "mobiletor.NewDesktopWindowsProtectionRecoveryTargetWithBarrier(ctx, target, barrier)", "mobiletor.NewDesktopWindowsProtectionRecoveryTarget(ctx, target)"),
            ("cmd/client/desktop_node_journal_off.go", 'change.Action != "off"', "false"),
            ("cmd/client/desktop_node_journal_off.go", "writeDesktopNodeJournalReleaseRecord(ctx, j.store, j.head, j.intent)", "unflushedIntent()"),
            ("cmd/client/desktop_node_journal_off.go", "s.backend.recoverWithBarrier(ctx, capture.target, j.barrier)", "s.backend.recover(ctx, capture.target)"),
            ("cmd/client/desktop_node_journal_off.go", "writeDesktopNodeJournalReleaseRecord(ctx, j.store, j.intent, j.settlement)", "unflushedSettlement()"),
            ("cmd/client/desktop_node_owned.go", "a.resumeDesktopProtectionOff(ctx, slot, pending, true)", "a.resumeUnrelatedOff(ctx)"),
            ("cmd/client/operation_guard.go", "a.guardDesktopProtectionOffPending(r.Context())", "unrelatedGuard(r.Context())"),
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
            ("cmd/client/desktop_tor_selection.go", "captureDesktopTorPredecessorContext(ctx, a, policy, lookup)", "unrelatedTorPredecessor(a, policy, lookup)"),
            ("cmd/client/desktop_tor_selection.go", "desktopTorSourceIdentityToken(entry) != selection.predecessor.profileToken", "false"),
            ("cmd/client/desktop_tor_selection.go", "policy, err = externalDNSPolicyForPath(policy, entry, direct)", "policy, err = externalDNSPolicyForPath(policy, common.RouterProfile{}, true)"),
            ("cmd/client/desktop_tor_selection.go", "policy, err = externalDNSPolicyForPath(policy, entry, direct)\n\tif err != nil {\n\t\treturn nil, err\n\t}", "policy, err = externalDNSPolicyForPath(policy, entry, direct)\n\terr = nil"),
            ("cmd/client/desktop_tor_predecessor_external.go", "if _, err := standardExitFromExternalProfile(entry); err != nil", "if _, err := standardExit{}, error(nil); err != nil"),
            ("cmd/client/desktop_tor_predecessor_external.go", 'mode != "" && mode != entry.External.Protocol', "false"),
            ("cmd/client/desktop_tor_predecessor_external.go", "copyDNSPolicy(&runtimeProfile, policy)", "copyDNSPolicy(&runtimeProfile, source)"),
            ("cmd/client/desktop_tor_predecessor_external.go", "entry: source, profileToken: desktopTorSourceIdentityToken(source)", "entry: runtimeProfile, profileToken: desktopTorSourceIdentityToken(runtimeProfile)"),
            ("cmd/client/desktop_tor_predecessor_external.go", "mobiletor.NewDesktopExternalPredecessor(mode, string(raw), string(launch.external.source), assets)", "mobiletor.NewDesktopExternalPredecessor(mode, string(raw), string(launch.config), assets)"),
            ("cmd/client/tor_bridge_routes.go", "lookup = desktopTorEndpointLookup", "lookup = nil"),
            ("cmd/client/tor_bridge_routes.go", "selection, err := captureDesktopTorSelectionContext(ctx, a, profile, capturedRequest, lookup)", "selection, err := captureDesktopTorSelectionContext(ctx, a, profile, capturedRequest, nil)"),
            ("cmd/client/tor_bridge_routes.go", "capturedRequest := cloneDesktopTorConnectRequest(q)", "capturedRequest := externalProfileConnectRequest{}"),
            ("cmd/client/tor_bridge_routes.go", "a.retainedExternalStartupExecution(startup) != driver.startupExecution", "false"),
            ("cmd/client/tor_bridge_routes.go", 'desktopTorExecution(driver.startupExecution) == ""', "false"),
            ("cmd/client/tor_bridge_routes.go", "capturedRequest.Execution = driver.startupExecution", "capturedRequest.Execution = q.Execution"),
            ("cmd/client/tor_bridge_routes.go", "a.torBridgeCompareSelectionOwned(w, profile, q, startup, driver)", "a.unrelatedTorCompare(w, profile, q)"),
            ("cmd/client/desktop_tor_comparison_driver.go", "captureDesktopTorSelectionContext(ctx, a, profile, choice, lookup)", "captureDesktopTorSelectionContext(ctx, a, profile, request, lookup)"),
            ("cmd/client/desktop_tor_comparison_driver.go", "!reflect.DeepEqual(localPolicy, serverPolicy)", "false"),
            ("cmd/client/desktop_tor_comparison_driver.go", "local.predecessor.profileToken != server.predecessor.profileToken", "false"),
            ("cmd/client/desktop_tor_comparison_routes.go", "winner.retainPath(cleanup)", "unrelatedRetainedProof()"),
            ("cmd/client/tor_bridge_routes.go", "prepareTorBridgeCommandWithRuntimeContext(ctx, a, policy, profile, selection.predecessor, driver)", "prepareTorBridgeCommandWithRuntimeContext(ctx, a, policy, profile, nil, driver)"),
            ("cmd/client/tor_bridge_routes.go", "a.validateExternalProfileExpectedProfilesLocked(q, profile)", "unrelatedSourceCheck(q, profile)"),
            ("cmd/client/tor_bridge_routes.go", "if err := check(); err != nil {\n\t\tfailure := errors.Join(err, prelaunch.cleanup())", "if err := unrelatedCheck(); err != nil {\n\t\tfailure := errors.Join(err, prelaunch.cleanup())"),
            ("cmd/client/desktop_tor_prepare.go", "driver.runtimeContext = prepareTorBridgeRuntimeWithPredecessorContext", "driver.runtime = unrelatedRuntime"),
            ("cmd/client/desktop_tor_prepare.go", "launch.tor.predecessor != predecessor", "false"),
            ("cmd/client/desktop_tor_prepare.go", "preflightDesktopTorLaunch(ctx, prepared.NativeBinary, launch, environment, run)", "unrelatedPreflight()"),
            ("cmd/client/tor_bridge_routes.go", "prelaunch.startContext(ctx, check)", "prelaunch.startContext(context.Background(), check)"),
            ("cmd/client/tor_bridge_prelaunch.go", "operation = owner.app.connectionOperationContextOrBackground()", "operation = context.Background()"),
            ("cmd/client/tor_bridge_prelaunch.go", "return owner.startContext(operation, check)", "return unrelatedStart(operation, check)"),
            ("cmd/client/tor_bridge_prelaunch.go", "captureDesktopNativeStartup(operation, owner.workspace)", "captureDesktopNativeStartup(context.Background(), owner.workspace)"),
            ("cmd/client/tor_bridge_prelaunch.go", "desktopNativeStartupEnvironment(startup, owner.workspace, owner.command.Env)", "unrelatedStartupEnvironment(startup, owner.workspace, owner.command.Env)"),
            ("cmd/client/tor_bridge_prelaunch.go", "desktopTorSourceIdentityToken(profile) == launch.tor.profileToken", "true"),
            ("cmd/client/tor_bridge_prelaunch.go", "launch.tor.entryCurrentContext(operation, owner.app)", "unrelatedEntryCheck(owner.app)"),
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
            # These mutate the contextual shipping calls themselves. Leaving
            # the legacy wrapper or an unattached old name cannot preserve the
            # original request, operation, captured node or final admission.
            ("cmd/client/tor_bridge_routes.go", "driver.requestContext = r.Context()", "driver.requestContext = context.Background()"),
            ("cmd/client/tor_bridge_routes.go", "a.beginConnectionOperationContext(r.Context())", "a.beginConnectionOperationContext(context.Background())"),
            ("cmd/client/tor_bridge_routes.go", "driver.operation = operation", "driver.operation = nil"),
            ("cmd/client/tor_bridge_routes.go", "desktopnetwork.LockContext(operation, &a.mu)", "desktopnetwork.LockContext(r.Context(), &a.mu)"),
            ("cmd/client/external_profile_connect.go", "driver.tor.requestContext = r.Context()", "driver.tor.requestContext = context.Background()"),
            ("cmd/client/external_profile_connect.go", "driver.tor.operation = operation", "driver.tor.operation = nil"),
            ("cmd/client/external_profile_connect.go", "desktopTorChoiceCaller(operation, admission)", "desktopTorChoiceCaller(admission, admission)"),
            ("cmd/client/external_profile_connect.go", "desktopnetwork.LockContext(admission, &a.mu)", "desktopnetwork.LockContext(context.Background(), &a.mu)"),
            ("cmd/client/desktop_tor_caller.go", "desktopTorChoiceCaller(operation, intent)", "desktopTorChoiceCaller(intent, intent)"),
            ("cmd/client/desktop_tor_caller.go", "desktopnetwork.LockContext(admission, &a.mu)", "desktopnetwork.LockContext(intent, &a.mu)"),
            ("cmd/client/desktop_tor_caller.go", "desktopTorOperationCurrentLocked(a, operation, selected)", "desktopTorOperationCurrentLocked(a, a.connectionContext, selected)"),
            ("cmd/client/desktop_tor_caller.go", "work: admission", "work: intent"),
            ("cmd/client/desktop_tor_selection.go", "desktopnetwork.LockContext(ctx, &a.mu)", "desktopnetwork.LockContext(context.Background(), &a.mu)"),
            ("cmd/client/desktop_tor_selection.go", "captureDesktopTorPredecessorContext(ctx, a, policy, lookup)", "captureDesktopTorPredecessorContext(context.Background(), a, policy, lookup)"),
            ("cmd/client/desktop_tor_selection.go", "selection.currentContext(ctx, a)", "selection.current(a)"),
            ("cmd/client/desktop_tor_predecessor.go", "mobilemtu.LockContext(ctx, &a.mu)", "mobilemtu.LockContext(context.Background(), &a.mu)"),
            ("cmd/client/desktop_tor_predecessor.go", "compileDesktopTorExternalPredecessor(ctx, entry, profile, mode, lookup)", "compileDesktopTorExternalPredecessor(context.Background(), entry, profile, mode, lookup)"),
            ("cmd/client/desktop_tor_predecessor.go", "compileDesktopTorPredecessor(ctx, entry, mode, files, start, lookup)", "compileDesktopTorPredecessor(context.Background(), entry, mode, files, start, lookup)"),
            ("cmd/client/desktop_tor_predecessor.go", "captured.currentContext(ctx, a)", "captured.current(a)"),
            ("cmd/client/tor_bridge_routes.go", "captureDesktopTorCaller(a, driver.operation, driver.requestContext)", "captureDesktopTorCaller(a, nil, driver.requestContext)"),
            ("cmd/client/tor_bridge_routes.go", "ctx, operation, selected := caller.work, caller.operation, caller.selected", "ctx, operation, selected := caller.intent, caller.operation, caller.selected"),
            ("cmd/client/tor_bridge_routes.go", "selection.adoption = caller.intent", "selection.adoption = nil"),
            ("cmd/client/tor_bridge_routes.go", "captureDesktopTorSelectionContext(ctx, a, profile, capturedRequest, lookup)", "captureDesktopTorSelection(a, profile, capturedRequest, lookup)"),
            ("cmd/client/tor_bridge_routes.go", "prepareTorBridgeCommandWithRuntimeContext(ctx, a, policy, profile, selection.predecessor, driver)", "prepareTorBridgeCommandWithRuntime(a, policy, profile, selection.predecessor, driver)"),
            ("cmd/client/desktop_tor_comparison_driver.go", "operation, selected := runtime.operation, a.profiles.SelectedID", "operation, selected := a.connectionContext, a.profiles.SelectedID"),
            ("cmd/client/desktop_tor_comparison_driver.go", "network, err := readNetwork(ctx)", "network, err := readNetwork(context.Background())"),
            ("cmd/client/desktop_tor_comparison_driver.go", "captureDesktopTorSelectionContext(ctx, a, profile, choice, lookup)", "captureDesktopTorSelection(a, profile, choice, lookup)"),
            ("cmd/client/desktop_tor_comparison_routes.go", "runtime.operation = caller.operation", "runtime.operation = nil"),
            ("cmd/client/desktop_tor_comparison_routes.go", "newDesktopTorComparisonDriverContext(caller.work, a, profile, q, startup, runtime)", "newDesktopTorComparisonDriver(a, profile, q, startup, runtime)"),
            ("cmd/client/desktop_tor_comparison_routes.go", "context.WithTimeout(caller.work, 8*time.Minute)", "context.WithTimeout(context.Background(), 8*time.Minute)"),
            ("cmd/client/desktop_tor_comparison_routes.go", "selection.adoption = ctx", "selection.adoption = nil"),
            ("cmd/client/desktop_tor_comparison_routes.go", "context.WithTimeout(ctx, 30*time.Second)", "context.WithTimeout(context.Background(), 30*time.Second)"),
            ("cmd/client/desktop_tor_prepare.go", "driver.runtimeContext(ctx, root, policy, profile, predecessor)", "driver.runtimeContext(context.Background(), root, policy, profile, predecessor)"),
            ("cmd/client/desktop_tor_prepare.go", "network, err := driver.readNetwork(ctx)", "network, err := driver.readNetwork(context.Background())"),
            ("cmd/client/desktop_tor_prepare.go", "launch.tor.networkIdentityContext = driver.readNetwork", "launch.tor.networkIdentityContext = physicalNetworkIdentityContext"),
            ("cmd/client/desktop_tor_prepare.go", "captureTorBridgePrelaunchContext(ctx, a, profile.ID, prepared.RuntimeDir, launch)", "captureTorBridgePrelaunch(a, profile.ID, prepared.RuntimeDir, launch)"),
            ("cmd/client/desktop_tor_prepare.go", "desktopTorLaunchEnvironmentContext(ctx, os.Environ(), root, prepared)", "desktopTorLaunchEnvironment(os.Environ(), root, prepared)"),
            ("cmd/client/desktop_tor_prepare.go", "desktopTorPreparationCallerCurrent(call, a, driver)", "desktopTorPreparationCallerCurrent(context.Background(), a, driver)"),
            ("cmd/client/desktop_tor_prepare.go", "driver.preflight(call, binary, arguments, environment, directory)", "driver.preflight(context.Background(), binary, arguments, environment, directory)"),
            ("cmd/client/tor_bridge_prelaunch.go", "owner.validateContext(operation)", "owner.validate()"),
            ("cmd/client/tor_bridge_prelaunch.go", "launch.tor.currentNetworkIdentityContext(operation)", "launch.tor.currentNetworkIdentityContext(context.Background())"),
            ("cmd/client/tor_bridge_prelaunch.go", "desktopnetwork.LockContext(operation, &owner.app.mu)", "desktopnetwork.LockContext(context.Background(), &owner.app.mu)"),
            ("cmd/client/tor_bridge_prelaunch.go", "launch.tor.entryCurrentContext(operation, owner.app)", "launch.tor.entryCurrent(owner.app)"),
            ("cmd/client/tor_bridge_prelaunch.go", "finalErr := operation.Err()", "finalErr := error(nil)"),
            ("cmd/client/tor_bridge_prelaunch.go", "finalErr = check()", "finalErr = nil"),
            ("cmd/client/tor_bridge_prelaunch.go", "errors.Join(finalErr, operation.Err())", "errors.Join(finalErr, nil)"),
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
            ("cmd/client/tor_bridge_prelaunch.go",
             "\t\tstartup, err := captureDesktopNativeStartup(operation, owner.workspace)\n",
             "\t\tif err := registerActiveDNSRuntimeConfig(owner.app, owner.dns.ProfileID, owner.dns.RuntimeID, owner.dns.Config); err != nil {"),
        ):
            with self.subTest(path=relative, reordered=block):
                original = (ROOT / relative).read_text(encoding="utf-8")
                self.assertEqual(original.count(block), 1)
                self.assertEqual(original.count(later), 1)
                changes.clear(); errors.clear()
                changes[relative] = original.replace(block, "").replace(later, block + later)
                scope["captured_tor_dns_policy"]()
                self.assertTrue(errors, "Reordered captured DNS or startup admission passed the real product audit")


class StandardExitCapturedAuditTests(unittest.TestCase):
    """Run the actual backend hook against mutated shipping source, never copies of its predicate."""

    def setUp(self):
        self.paths = ("cmd/client/standard_exit_platform_routes.go",
                      "cmd/client/linux_standard_service_speed_lab_linux.go")
        self.sources = {path: (ROOT / path).read_text() for path in self.paths}
        tree = ast.parse((ROOT / "deploy/backend-session-transaction-audit.py").read_text())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in ("standard_exit_captured_chain", "require_standard_exit_captured_chain")]
        calls = [node for node in tree.body if isinstance(node, ast.Expr)
                 and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                 and node.value.func.id == "require_standard_exit_captured_chain"]
        self.assertEqual(len(functions), 2)
        self.assertEqual(len(calls), 1, "backend must execute the captured-chain audit")
        self.code = compile(ast.Module(body=functions + calls, type_ignores=[]), "backend-standard-captured", "exec")

    def check(self, changes=None, expected=False):
        sources = dict(self.sources)
        sources.update(changes or {})
        scope = {"read": sources.__getitem__, "errors": [], "_native_module": _NATIVE}
        exec(self.code, scope)
        self.assertEqual(not scope["errors"], expected, scope["errors"])

    def mutation(self, path, before, after, occurrence=None):
        source = self.sources[path]
        self.assertIn(before, source)
        if occurrence is None:
            changed = source.replace(before, after)
        else:
            offsets = [m.start() for m in re.finditer(re.escape(before), source)]
            self.assertLess(occurrence, len(offsets))
            at = offsets[occurrence]
            changed = source[:at] + after + source[at + len(before):]
        # A stale marker outside the shipping function cannot restore closure.
        self.check({path: changed + "\n/* " + before + " */\n"})

    def test_current_chain_and_formatting_pass(self):
        self.check(expected=True)
        path = self.paths[0]
        self.check({path: self.sources[path].replace("retained.Start(operation)", "retained . Start( /* original */ operation )")}, expected=True)

    def test_owned_admission_cleanup_and_original_delegation_are_required(self):
        path = self.paths[0]
        for before, after in (
            ('h.HandleFunc("/api/standard-exit/connect", a.platformStandardExitConnect)', 'h.HandleFunc("/api/standard-exit/connect", a.unrelatedConnect)'),
            ("operation, finish, guardErr := a.beginConnectionOperation()", "operation, finish, guardErr := unrelatedOperation()"),
            ("defer finish()", "unrelatedCleanup()"),
            ("a.platformStandardExitConnectCaptured(w, r, adapter, operation)", "a.platformStandardExitConnectCaptured(w, r, adapter, context.Background())"),
            ("a.platformStandardExitConnectOwned(w, r, defaultPlatformStandardExitRuntime())", "a.platformStandardExitConnectCaptured(w, r, defaultPlatformStandardExitRuntime(), context.Background())"),
        ):
            with self.subTest(before=before):
                self.mutation(path, before, after)

    def test_each_original_stage_guard_is_required(self):
        path = self.paths[0]
        call = "a.checkCapturedConnectionOperation(operation)"
        self.assertEqual(self.sources[path].count(call), 4)
        for stage in range(4):
            for replacement in ("a.checkConnectionOperation()", "a.checkCapturedConnectionOperation(context.Background())", "unrelatedCheck()"):
                with self.subTest(stage=stage, replacement=replacement):
                    self.mutation(path, call, replacement, stage)
        self.mutation(path, "a.checkCapturedConnectionOperationLocked(operation)", "a.checkCapturedConnectionOperationLocked(context.Background())")

    def test_guard_requires_actual_rejection_not_only_a_call(self):
        path = self.paths[0]
        for guard in (
            "if err := a.checkCapturedConnectionOperation(operation); err != nil {",
            "if err = a.checkCapturedConnectionOperation(operation); err != nil {",
            "if cancelErr := a.checkCapturedConnectionOperation(operation); cancelErr != nil {",
        ):
            with self.subTest(guard=guard):
                self.mutation(path, guard, guard.replace("!= nil", "== nil"))
        before = 'if err := a.checkCapturedConnectionOperation(operation); err != nil {\n\t\thttp.Error(w, err.Error(), http.StatusConflict)\n\t\treturn\n\t}'
        self.mutation(path, before, before.replace("\n\t\treturn", ""))

    def test_start_proof_and_adoption_keep_original_order_and_context(self):
        path = self.paths[0]
        for call in ("retained.Start(operation)", "adapter.proveDNS(operation, retained)", "adapter.current(retained, operation)"):
            with self.subTest(call=call):
                self.mutation(path, call, call.replace("operation", "context.Background()"))
        self.mutation(path, "err = retained.Start(operation)", 'err = errors.New("err = retained.Start(operation)")')
        self.mutation(path, "proofErr = adapter.proveDNS(operation, retained)", "proofErr = adapter.current(retained, operation)")
        self.mutation(path, "a.state.Connected = true", "a.state.Connected = false")
        self.mutation(path, "err = retained.Start(operation)", "if false { err = retained.Start(operation) }")

    def test_nested_or_replaced_intents_are_rejected(self):
        path = self.paths[0]
        signature = "func (a *app) platformStandardExitConnectCaptured(w http.ResponseWriter, r *http.Request, adapter platformStandardExitRuntime, operation context.Context) {"
        for statement in ("a.beginConnectionOperation()", "operation = context.Background()", "operation, cancel := context.WithCancel(operation)", "var operation context.Context"):
            with self.subTest(statement=statement):
                self.mutation(path, signature, signature + "\n" + statement)

    def test_prelaunch_guard_cannot_move_after_start(self):
        path = self.paths[0]
        block = '\tif err = a.checkCapturedConnectionOperation(operation); err != nil {\n\t\ttracker.markRequestFailure(err.Error())\n\t\thttp.Error(w, err.Error(), http.StatusConflict)\n\t\treturn\n\t}\n'
        self.assertEqual(self.sources[path].count(block), 1)
        changed = self.sources[path].replace(block, "")
        self.assertEqual(changed.count("\tvar proofErr error"), 1)
        changed = changed.replace("\tvar proofErr error", block + "\tvar proofErr error")
        self.check({path: changed})

    def test_speed_lab_restore_cannot_create_or_substitute_an_operation(self):
        path = self.paths[1]
        call = "a.platformStandardExitConnectCaptured(response, request, defaultPlatformStandardExitRuntime(), ctx)"
        for replacement in (
            "a.platformStandardExitConnectOwned(response, request, defaultPlatformStandardExitRuntime())",
            call.replace(", ctx)", ", context.Background())"),
            "unrelatedRestore()",
        ):
            with self.subTest(replacement=replacement):
                self.mutation(path, call, replacement)
        signature = "func (s *linuxStandardServiceSpeedLabRestore) restart(ctx context.Context, a *app) error {"
        for statement in ("a.beginConnectionOperation()", "ctx, cancel := context.WithCancel(ctx)"):
            with self.subTest(statement=statement):
                self.mutation(path, signature, signature + "\n" + statement)
        self.mutation(path, "http.NewRequestWithContext(ctx,", "http.NewRequestWithContext(context.Background(),")
        for index in (0, 1):
            self.mutation(path, "s.sourceCurrent(ctx, a, ctx)", "s.sourceCurrent(ctx, a, context.Background())", index)

    def test_duplicate_shipping_function_is_rejected(self):
        path = self.paths[0]
        signature = "func (a *app) platformStandardExitConnectCaptured(w http.ResponseWriter, r *http.Request, adapter platformStandardExitRuntime, operation context.Context)"
        self.check({path: self.sources[path] + "\n" + signature + " {}\n"})


if __name__ == "__main__":
    unittest.main()
