#!/usr/bin/env python3
"""Refusal and exact projection tests; no Darwin/native success is simulated."""
from pathlib import Path
import importlib.util
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("darwin_socks_child_gate", ROOT/"deploy/test_darwin_socks_child_tun.py")
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)

def verdict():
    lines = ["=== RUN   "+G.HARNESS, "=== RUN   "+G.NATIVE]
    for name in G.CASES:
        lines += ["=== RUN   "+G.NATIVE+"/"+name,
                  "    native.go:1: verified original Darwin child retirement: "+name]
    lines += ["--- PASS: "+G.NATIVE+" (1.00s)"]
    lines += ["    --- PASS: "+G.NATIVE+"/"+name+" (0.10s)" for name in G.CASES]
    lines += ["PASS", "--- PASS: "+G.HARNESS+" (2.00s)", "PASS"]
    return "\n".join(lines)+"\n"

class DarwinSOCKSNativeGate(unittest.TestCase):
    def test_exact_independent_inventory(self):
        G.check_verdict(verdict())
        self.assertEqual(len(G.CASES), 8)
        self.assertEqual(len(G.BASE.CASES), 8)
        self.assertEqual(len(set(G.CASES)), 8)
        self.assertNotEqual(G.HARNESS, G.BASE.HARNESS)
        self.assertNotEqual(G.NATIVE, G.BASE.NATIVE)

    def test_missing_duplicate_wrong_family_and_failed_verdict(self):
        good = verdict()
        faults = [
            good.replace("=== RUN   "+G.NATIVE+"/"+G.CASES[0]+"\n", ""),
            good + "--- PASS: "+G.NATIVE+" (1.00s)\n",
            good.replace(G.HARNESS, G.BASE.HARNESS),
            good.replace(G.NATIVE, G.BASE.NATIVE),
            good.replace("verified original Darwin child retirement: "+G.CASES[0], "unjoined"),
            good + "WARNING: DATA RACE\n",
            good + "--- SKIP: "+G.NATIVE+" (0.00s)\n",
            good + "panic: actual original failure\n",
            good.replace("=== RUN   "+G.HARNESS, "--- PASS: "+G.HARNESS+" (0.00s)"),
        ]
        for broken in faults:
            with self.subTest(broken=broken[-100:]):
                with self.assertRaises(ValueError):
                    G.check_verdict(broken)

    def test_exact_native_purpose_is_required(self):
        with mock.patch.object(G.BASE, "required_host", return_value=("arm64", 501)) as host:
            with self.assertRaises(ValueError):
                G.required_host({G.BASE.FLAG: "1"})
            host.assert_not_called()
            self.assertEqual(G.required_host({G.FLAG: "1", G.BASE.FLAG: "1"}), ("arm64", 501))

    def test_actual_peer_projection_and_original_platform_guard(self):
        prep = G.BASE.NODE.PREP
        copies = prep.darwin_node_chain_peer_copies()
        for name in ("node_chain_socks_peer_test.go.tmpl", "node_chain_socks_process_test.go.tmpl"):
            target = prep.DARWIN_NODE_CHAIN_PEERS[name]
            source = (ROOT/"mobile/desktop"/name).read_bytes()
            before = b"//go:build linux && !android\n\npackage routervpnamnezia\n"
            after = b"//go:build darwin && routervpn_darwin_node_chain && routervpn_darwin_external_host\n\npackage routervpnamnezia\n"
            self.assertTrue(source.startswith(before))
            self.assertEqual(copies[target], after+source[len(before):])
            original = Path.read_bytes
            selected = ROOT/"mobile/desktop"/name
            def read(path):
                return source.replace(before, b"package routervpnamnezia\n", 1) if path == selected else original(path)
            with mock.patch.object(Path, "read_bytes", read):
                with self.assertRaisesRegex(ValueError, "selector"):
                    prep.darwin_node_chain_peer_copies()
        with tempfile.TemporaryDirectory() as td:
            prep.copy_encrypted_peer_templates(Path(td))
            for name in ("node_chain_socks_peer_test.go.tmpl", "node_chain_socks_process_test.go.tmpl"):
                self.assertEqual((Path(td)/prep.PEER_TEMPLATES[name]).read_bytes(),
                                 (ROOT/"mobile/desktop"/name).read_bytes())

    def test_missing_typed_native_closure_rejected(self):
        with mock.patch.object(G.BASE, "checked_sources", return_value=(Path("/core"), {})):
            with self.assertRaisesRegex(ValueError, "omitted"):
                G.checked_sources(Path("/core"))

    def test_real_executor_selection_and_elevation(self):
        source = Path("/core")
        before = {"exact": "source"}
        child, peer = Path("/child.test"), Path("/peer.test")
        identities = {child: (1, 2, 300, "a"*64), peer: (3, 4, 500, "b"*64)}
        with mock.patch.object(G, "checked_sources", return_value=(source, before)), \
             mock.patch.object(G.BASE, "image_identity", side_effect=lambda path: identities[path]), \
             mock.patch.object(G.BASE, "native_output", return_value=verdict()) as execute:
            result = G.execute_images(source, before, {}, "/usr/bin/sudo", "arm64", 501, child, peer, identities)
            command = execute.call_args.args[0]
            self.assertEqual(command[:4], ["/usr/bin/sudo", "-n", "--", "/usr/bin/env"])
            self.assertIn(G.FLAG+"=1", command)
            self.assertIn("-test.run=^"+G.HARNESS+"$", command)
            self.assertIn("-test.timeout=930s", command)
            self.assertEqual(execute.call_args.kwargs["timeout"], 960)
            self.assertEqual(execute.call_args.kwargs["sudo"], "/usr/bin/sudo")
            self.assertEqual(result["public_darwin_admission"], "closed")
            self.assertEqual(result["target"], "darwin/arm64")
            self.assertEqual(result["toolchain"], G.BASE.UID.RACE.TOOLCHAIN)
            self.assertEqual(result["cases"], list(G.CASES))
            self.assertEqual(result["artifacts"]["independent-encrypted-peer"]["sha256"], "b"*64)

    def test_standalone_prepares_with_original_production_compiler(self):
        stop = RuntimeError("stop before native preparation")
        with mock.patch.object(G, "required_host", return_value=("arm64", 501)), \
             mock.patch.object(G.BASE, "repository_identity", return_value={}), \
             mock.patch.object(G.BASE, "receipt_path", return_value=None), \
             mock.patch.object(G.BASE, "preparation_compiler", side_effect=stop) as prepare, \
             mock.patch.object(G.BASE, "selected_compiler") as race:
            with self.assertRaises(RuntimeError) as caught:
                G.standalone("/production/go", environment={})
            self.assertIs(caught.exception, stop)
            prepare.assert_called_once_with("/production/go", G.ROOT, {})
            race.assert_not_called()

    def test_source_or_native_image_drift_refused(self):
        source = Path("/core")
        child, peer = Path("/child.test"), Path("/peer.test")
        identities = {child: (1, 2, 300, "a"*64), peer: (3, 4, 500, "b"*64)}
        for source_changed in (True, False):
            with mock.patch.object(G, "checked_sources", return_value=(source, {"changed": "source"} if source_changed else {})), \
                 mock.patch.object(G.BASE, "image_identity", return_value=("replaced",)), \
                 mock.patch.object(G.BASE, "native_output", return_value=verdict()):
                with self.assertRaisesRegex(ValueError, "changed"):
                    G.execute_images(source, {}, {}, None, "amd64", 501, child, peer, identities)

    def test_successful_workspace_retires_only_its_original_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(G.tempfile, "tempdir", directory):
                with G.JoinedWorkspace(prefix="joined-") as original:
                    (original/"source").write_text("original source")
                self.assertFalse(original.exists())

    def test_failed_or_unknown_join_retains_original_workspace(self):
        failures = (RuntimeError("original process group could not be joined"),
                    TimeoutError("unknown compile join"), KeyboardInterrupt())
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(G.tempfile, "tempdir", directory):
                for failure in failures:
                    with self.subTest(failure=type(failure).__name__):
                        with self.assertRaises(type(failure)) as caught:
                            with G.JoinedWorkspace(prefix="retained-") as original:
                                (original/"evidence").write_text("original captured bytes")
                                raise failure
                        self.assertIs(caught.exception, failure)
                        self.assertEqual((original/"evidence").read_text(), "original captured bytes")

    def test_replaced_workspace_never_consumes_replacement_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(G.tempfile, "tempdir", directory):
                for symlink in (False, True):
                    with self.subTest(symlink=symlink):
                        with self.assertRaisesRegex(ValueError, "replaced"):
                            with G.JoinedWorkspace(prefix="original-") as original:
                                (original/"evidence").write_text("original")
                                retained = root/(original.name+"-retained")
                                original.rename(retained)
                                if symlink:
                                    replacement = root/(original.name+"-replacement")
                                    replacement.mkdir()
                                    original.symlink_to(replacement, target_is_directory=True)
                                else:
                                    original.mkdir()
                                (original/"foreign").write_text("replacement")
                        self.assertEqual((retained/"evidence").read_text(), "original")
                        self.assertEqual((original/"foreign").read_text(), "replacement")

    def test_native_errors_never_become_receipts(self):
        with mock.patch.object(G.BASE, "native_output", side_effect=RuntimeError("unjoined original child")):
            with self.assertRaisesRegex(RuntimeError, "unjoined"):
                G.execute_images(Path("/core"), {}, {}, None, "amd64", 501,
                                 Path("/child"), Path("/peer"),
                                 {Path("/child"): (1, 2, 3, "a"*64), Path("/peer"): (1, 2, 3, "b"*64)})

if __name__ == "__main__":
    unittest.main()
