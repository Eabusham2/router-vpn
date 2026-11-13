#!/usr/bin/env python3
"""Strict receipt/source tests; these are not Windows kernel acceptance."""
from pathlib import Path
import importlib.util
import json
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("windows_prefix_native_gate", ROOT / "deploy/test_windows_candidate_prefix.py")
GATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(GATE)


def receipt():
    value = "\n".join("=== RUN   " + name for name in GATE.REQUIRED) + "\n"
    value += "\n".join("verified installed Windows selected prefix: " + case for case in GATE.CASES) + "\n"
    value += "\n".join("--- PASS: " + name + " (0.01s)" for name in GATE.REQUIRED) + "\nPASS\n"
    return value


class PrefixRunner(unittest.TestCase):
    def test_exact_inventory(self):
        self.assertEqual(len(GATE.CASES), 6)
        GATE.require_verdicts(receipt())

    def test_each_original_verdict_required(self):
        for name in GATE.REQUIRED:
            for text in ("=== RUN   " + name + "\n", "--- PASS: " + name + " (0.01s)\n"):
                with self.subTest(name=name, text=text):
                    with self.assertRaises(ValueError): GATE.require_verdicts(receipt().replace(text, ""))

    def test_duplicate_verdict_refused(self):
        with self.assertRaises(ValueError): GATE.require_verdicts(receipt() + "--- PASS: " + GATE.ROOT_TEST + " (0.01s)\n")

    def test_missing_lifecycle_refused(self):
        for case in GATE.CASES:
            with self.subTest(case=case):
                with self.assertRaises(ValueError): GATE.require_verdicts(receipt().replace("verified installed Windows selected prefix: " + case + "\n", ""))

    def test_failure_skip_race_footer(self):
        for value in (receipt()+"--- FAIL: unrelated\n", receipt()+"--- SKIP: unrelated\n", receipt()+"WARNING: DATA RACE\n", receipt().removesuffix("PASS\n")):
            with self.assertRaises(ValueError): GATE.require_verdicts(value)

    def test_exact_public_scope_inventory(self):
        result = GATE.SCOPE.scope_sources(ROOT / "internal/mobiletor", r"C:\owned\runtime\native\sing-box-routervpn.exe")
        self.assertEqual(set(result), set(GATE.SCOPE.REPLACEMENTS) | {"routervpn_candidate_prefix_scope_windows.go"})
        for name, substitutions in GATE.SCOPE.REPLACEMENTS.items():
            raw = result[name].decode()
            for before, after in substitutions:
                self.assertIn(after, raw)
        # Actual native socket creation, TUN, BFE transaction and journal code
        # remain original: only the listed wrapper calls and localhost rule.
        self.assertEqual(sum(len(rows) for rows in GATE.SCOPE.REPLACEMENTS.values()), 16)

    def test_foreign_scope_path_refused(self):
        for path in ("sing-box-routervpn.exe", r"C:\owned\peer.exe", "C:\\owned\\sing-box-routervpn.exe\n", r"\relative\sing-box-routervpn.exe"):
            with self.assertRaises(ValueError): GATE.SCOPE.scope_sources(ROOT / "internal/mobiletor", path)

    def test_changed_anchor_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in GATE.SCOPE.REPLACEMENTS:
                (directory / name).write_bytes((ROOT / "internal/mobiletor" / name).read_bytes())
            path = directory / "desktop_socket_windows_prepared.go"
            path.write_text(path.read_text().replace("baselineSHA256, nil)", "baselineSHA256, changed)"))
            with self.assertRaises(ValueError): GATE.SCOPE.scope_sources(directory, r"C:\owned\sing-box-routervpn.exe")

    def test_original_peer_crypto_preserved(self):
        values = GATE.SCOPE.peer_sources()
        self.assertEqual(len(values), len(GATE.SCOPE.PEERS)+1)
        for name in GATE.SCOPE.PEERS:
            key = "routervpn_windows_prefix_" + name.removesuffix(".tmpl").replace("_linux", "")
            original = (ROOT / "mobile/desktop" / name).read_text().split("\n", 1)[1]
            projected = values[key].decode().split("\n", 1)[1]
            if name == "node_chain_peer_linux_test.go.tmpl":
                projected = projected.replace('\tif runtime.GOOS == "windows" { return desktopWindowsPrefixReferenceAddressPair(address, client) }\n', "")
            self.assertEqual(projected, original)

    def test_overlapping_overlay_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("a", "b"):
                (root/name).write_text(json.dumps({"Replace": {"one": name}}))
            with self.assertRaises(ValueError): GATE.merge_overlays([root/"a", root/"b"], root/"merged")

    def test_actual_host_required(self):
        with patch.object(GATE.platform,"system",return_value="Linux"):
            with self.assertRaisesRegex(ValueError,"actual elevated Windows"):
                GATE.execute(ROOT,ROOT)

    def test_build_gate_requires_exact_native_receipt(self):
        build=GATE.BUILD
        with tempfile.TemporaryDirectory() as temporary:
            bundle=Path(temporary)
            (bundle/"NATIVE-RUNTIME.json").write_bytes(b"original verified bundle")
            original={"policy_sha256":"a"*64}
            value={"schema":1,"native":True,"target":"windows/amd64","source_sha256":"a"*64,
                   "bundle_sha256":GATE.hashlib.sha256((bundle/"NATIVE-RUNTIME.json").read_bytes()).hexdigest(),
                   "cases":list(GATE.CASES),"unmodified_shipping_image":False,"test_scope":"captured-native-child-app-id",
                   "application_open":False,"dns_open":False,"samples_per_case":50,"original_final_unreachable":True,
                   "native_down_before_review":True,"sources":{"actual":"b"*64},
                   "scope_sources":{name:"c"*64 for name in (*GATE.SCOPE.REPLACEMENTS,"routervpn_candidate_prefix_scope_windows.go")},
                   "images":{"controller":"d"*64,"peer":"e"*64,"scoped_engine":"f"*64}}
            def invoke(record):
                with patch.object(build.platform,"system",return_value="Windows"),patch.object(build,"native_host_target",return_value="windows/amd64"), \
                     patch.object(build,"reuse",return_value=original),patch.object(build,"run",side_effect=["",GATE.PREFIX+json.dumps(record)]) as run:
                    build.verify_installed_windows_prefix(ROOT,bundle,"windows/amd64",{})
                    self.assertEqual(Path(run.call_args_list[0].args[0][1]).name,"test_windows_candidate_prefix_runner.py")
                    self.assertEqual(Path(run.call_args_list[1].args[0][1]).name,"test_windows_candidate_prefix.py")
            invoke(value)
            for key in value:
                with self.subTest(field=key):
                    changed=dict(value);changed.pop(key)
                    with self.assertRaises(ValueError): invoke(changed)
            for key, replacement in (("schema",True),("native",1),("native_down_before_review",1),
                                     ("original_final_unreachable",1),("application_open",0),("dns_open",0),
                                     ("unmodified_shipping_image",0),("samples_per_case",49),("samples_per_case",50.0),
                                     ("sources",None),("images",[]),("scope_sources",{"one":"c"*64}),
                                     ("images",{"controller":"d"*64,"peer":"e"*64,"scoped_engine":"not-a-sha"})):
                with self.subTest(field=key,replacement=replacement):
                    changed=dict(value);changed[key]=replacement
                    with self.assertRaises(ValueError): invoke(changed)

    def test_builder_cold_and_cache_paths_require_prefix(self):
        import ast
        module=ast.parse((ROOT/"deploy/build-native-runtime.py").read_text())
        build=next(value for value in module.body if isinstance(value,ast.FunctionDef) and value.name=="build")
        calls=[value.func.id for value in ast.walk(build) if isinstance(value,ast.Call) and isinstance(value.func,ast.Name)]
        self.assertEqual(calls.count("verify_installed_windows_prefix"),1)
        self.assertEqual(calls.count("verify_reused_windows_prefix"),1)

    def cached(self, arch="amd64", source_failure=None, native_failure=None):
        import contextlib
        build=GATE.BUILD
        calls=[]
        def checkout(path,repository,revision):
            path.mkdir();calls.append(("checkout",path.name,repository,revision))
        def prepare(source,xray,env):
            calls.append(("prepare",source.name,xray.name))
            if source_failure is not None: raise source_failure
        def native(source,bundle,target,env):
            calls.append(("native",target))
            self.assertTrue(source.is_dir())
            self.assertEqual(target,"windows/"+arch)
            self.assertIn("-static",env["CGO_LDFLAGS"])
            self.assertIn("-loriginal",env["CGO_LDFLAGS"])
            if native_failure is not None: raise native_failure
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(build.platform,"system",return_value="Windows"))
            stack.enter_context(patch.object(build,"native_host_target",return_value="windows/"+arch))
            stack.enter_context(patch.object(build,"checkout",side_effect=checkout))
            pristine=stack.enter_context(patch.object(build,"pristine"))
            stack.enter_context(patch.object(build,"prepare_native_sources",side_effect=prepare))
            pq=stack.enter_context(patch.object(build.PQ,"build"))
            stack.enter_context(patch.object(build.PQ,"verify",return_value={"native_static_libs":["-loriginal"]}))
            gate=stack.enter_context(patch.object(build,"verify_installed_windows_prefix",side_effect=native))
            if source_failure or native_failure:
                expected=source_failure or native_failure
                with self.assertRaises(type(expected)) as caught:
                    build.verify_reused_windows_prefix(ROOT,"windows/"+arch,{"GOOS":"windows","GOARCH":arch})
                self.assertIs(caught.exception,expected)
            else:
                build.verify_reused_windows_prefix(ROOT,"windows/"+arch,{"GOOS":"windows","GOARCH":arch})
            self.assertEqual(pristine.call_count,2)
            self.assertEqual(calls[:3],[("checkout","core","https://github.com/SagerNet/sing-box.git",build.PIN),
                                      ("checkout","xray","https://github.com/XTLS/Xray-core.git",build.POLICY.XRAY.XRAY_PIN),
                                      ("prepare","core","xray")])
            if source_failure:
                pq.assert_not_called();gate.assert_not_called()
            else:
                pq.assert_called_once();gate.assert_called_once()
                self.assertEqual(calls[-1],("native","windows/"+arch))

    def test_cached_bundle_runs_same_native_gate_for_both_targets(self):
        for arch in ("amd64","arm64"):
            with self.subTest(architecture=arch): self.cached(arch)

    def test_cached_preparation_refusal_prevents_native_gate(self):
        self.cached(source_failure=ValueError("exact source unavailable"))

    def test_cached_native_failure_is_not_an_accepted_bundle(self):
        self.cached(native_failure=ValueError("actual native prefix refused"))


if __name__ == "__main__":
    unittest.main()
