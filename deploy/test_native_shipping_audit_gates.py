#!/usr/bin/env python3
"""Execute actual native shipping audit predicates against broken call paths."""
from __future__ import annotations

import ast
from pathlib import Path
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
            ("cmd/client/multihop_native_launch.go", "verifyBundledNative(desktopAmneziaPackageRoot())", "findUnverifiedEngine()"),
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


if __name__ == "__main__":
    unittest.main()
