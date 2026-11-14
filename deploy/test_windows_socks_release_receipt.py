#!/usr/bin/env python3
"""Verify publication requires both actual Windows native receipts.

These are receipt and invocation controls, not native kernel acceptance.
"""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy" / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


BUILD = load("windows_socks_release_build", "build-native-runtime.py")
PARENT = load("windows_socks_release_parent", "test_desktop_socks_parent.py")
FULL = "Native Windows typed SOCKS full-path acceptance: "
PREFIX = "Native Windows selected-prefix acceptance: "


def receipts(digest):
    scope = {"desktop_socket_windows_" + name + ".go": "c" * 64
             for name in ("policy", "transfer", "commit", "baseline", "status", "prepared", "probe", "observation")}
    scope["routervpn_candidate_prefix_scope_windows.go"] = "c" * 64
    original = {"schema": 1, "native": True, "target": "windows/amd64", "source_sha256": "a" * 64,
                "bundle_sha256": digest, "cases": ["wg-save", "wg-cancel", "awg-fast-save", "awg-fast-cancel", "awg-strong-save", "awg-strong-cancel"],
                "unmodified_shipping_image": False, "test_scope": "captured-native-child-app-id",
                "application_open": False, "dns_open": False, "samples_per_case": 50, "original_final_unreachable": True,
                "native_down_before_review": True, "sources": {"actual": "b" * 64}, "scope_sources": scope,
                "images": {"controller": "d" * 64, "peer": "e" * 64, "scoped_engine": "f" * 64}}
    typed = {"schema": 2, "native": True, "target": "windows/amd64", "source_sha256": "a" * 64,
             "bundle_sha256": digest,
             "cases": ["wg-connect", "awg-fast-connect", "awg-strong-connect", "wg-wrong-middle-key", "wg-wrong-middle-public", "wg-final-dns-failure", "wg-final-node-failure", "wg-middle-source"],
             "unmodified_shipping_image": False, "test_scope": "captured-native-child-app-id",
             "typed_full_path": True, "positive_application_and_selected_dns_proved": True,
             "measurement_bytes_per_direction_per_hop": 8 << 20, "measurement_hops": 3,
             "native_joined": True, "command_job_joined": True, "tun_absent_all_outcomes": True,
             "remote_associations_after_retirement": 0, "public_admission": "enabled", "public_connect_path": "/api/multihop/connect",
             "original_prefix_acceptance": copy.deepcopy(original), "sources": {"actual": "1" * 64},
             "scope_sources": {name: "2" * 64 for name in scope},
             "images": {"controller": "3" * 64, "peer": "4" * 64, "scoped_engine": "5" * 64},
             "typed_socks_parent_controls": {"scope": "compiled-parent-model-and-source-controls", "native_kernel_acceptance": False,
                                              "target": "windows", "cases": list(PARENT.inventory("windows")[1]), "output_sha256": "6" * 64}}
    return original, typed


class WindowsSOCKSReleaseReceipt(unittest.TestCase):
    def verify(self, typed, original):
        return BUILD.verify_installed_windows_socks_receipt(FULL + json.dumps(typed), "windows/amd64",
                                                          {"policy_sha256": "a" * 64}, "7" * 64, original)

    def test_exact_complete_native_receipt(self):
        original, typed = receipts("7" * 64)
        self.assertEqual(self.verify(typed, original), typed)
        for field in typed:
            broken = copy.deepcopy(typed)
            del broken[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                self.verify(broken, original)

    def test_failure_or_substitution_cannot_publish(self):
        original, typed = receipts("7" * 64)
        faults = (("schema", True), ("schema", 1), ("native", 1), ("target", "windows/arm64"), ("source_sha256", "8" * 64),
                  ("bundle_sha256", "9" * 64), ("cases", typed["cases"][:-1]),
                  ("unmodified_shipping_image", True), ("test_scope", "modeled"),
                  ("typed_full_path", 1), ("positive_application_and_selected_dns_proved", False),
                  ("measurement_bytes_per_direction_per_hop", float(8 << 20)),
                  ("measurement_bytes_per_direction_per_hop", 4 << 20), ("measurement_hops", 2), ("measurement_hops", 3.0),
                  ("native_joined", 1), ("command_job_joined", False), ("command_job_joined", 1),
                  ("tun_absent_all_outcomes", False), ("tun_absent_all_outcomes", 1),
                  ("remote_associations_after_retirement", 1), ("remote_associations_after_retirement", False),
                  ("public_admission", "complete"), ("public_admission", "closed"),
                  ("public_connect_path", "/api/native-socks/connect"), ("original_prefix_acceptance", {}),
                  ("sources", {}), ("images", {"controller": "3" * 64}), ("scope_sources", {"foreign": "2" * 64}),
                  ("sources", {"actual": "invalid"}))
        for field, value in faults:
            broken = copy.deepcopy(typed)
            broken[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.verify(broken, original)
        for case in typed["cases"]:
            broken = copy.deepcopy(typed)
            broken["cases"].remove(case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.verify(broken, original)

    def test_parent_models_cannot_replace_native_or_drop_controls(self):
        original, typed = receipts("7" * 64)
        for field in typed["typed_socks_parent_controls"]:
            broken = copy.deepcopy(typed)
            del broken["typed_socks_parent_controls"][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(broken, original)
        for field, value in (("native_kernel_acceptance", True), ("target", "linux"), ("cases", []),
                             ("scope", "native"), ("output_sha256", "bad")):
            broken = copy.deepcopy(typed)
            broken["typed_socks_parent_controls"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(broken, original)

    def test_unique_structured_receipt_required(self):
        original, typed = receipts("7" * 64)
        good = FULL + json.dumps(typed)
        for output in ("", good + "\n" + good, FULL + "[]", good.replace('"native": true', '"native": true, "native": true', 1)):
            with self.subTest(output=output[:80]), self.assertRaises(ValueError):
                BUILD.verify_installed_windows_socks_receipt(output, "windows/amd64", {"policy_sha256": "a" * 64}, "7" * 64, original)

    def test_real_builder_requires_both_receipts_before_bundle_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            (bundle / "NATIVE-RUNTIME.json").write_bytes(b"original completed native bundle")
            digest = hashlib.sha256((bundle / "NATIVE-RUNTIME.json").read_bytes()).hexdigest()
            original, typed = receipts(digest)
            good = PREFIX + json.dumps(original) + "\n" + FULL + json.dumps(typed)
            for output, accepted in ((good, True), (PREFIX + json.dumps(original), False), (FULL + json.dumps(typed), False),
                                     (good + "\n" + PREFIX + json.dumps(original), False)):
                with patch.object(BUILD.platform, "system", return_value="Windows"), \
                     patch.object(BUILD, "native_host_target", return_value="windows/amd64"), \
                     patch.object(BUILD, "reuse", return_value={"policy_sha256": "a" * 64}) as reuse, \
                     patch.object(BUILD, "run", side_effect=["", "", "", "", "", "", output]) as run, \
                     patch.object(BUILD, "verify_installed_windows_connect_receipt") as connect:
                    if accepted:
                        BUILD.verify_installed_windows_prefix(ROOT, bundle, "windows/amd64", {})
                        self.assertEqual(reuse.call_count, 2)
                        # This unit keeps every original prefix/SOCKS check;
                        # the separate CONNECT receipt suite exercises all three.
                        connect.assert_called_once_with(output, "windows/amd64", {"policy_sha256": "a" * 64}, digest, typed)
                    else:
                        with self.assertRaises(ValueError):
                            BUILD.verify_installed_windows_prefix(ROOT, bundle, "windows/amd64", {})
                        self.assertEqual(reuse.call_count, 1)
                        connect.assert_not_called()
                    self.assertEqual([Path(call.args[0][1]).name for call in run.call_args_list], [
                        "test_windows_candidate_prefix_runner.py", "test_windows_socks_node_chain_host_runner.py",
                        "test_windows_socks_release_receipt.py", "test_desktop_connect_parent_runner.py",
                        "test_windows_connect_node_chain_host_runner.py", "test_windows_connect_release_receipt.py",
                        "test_windows_connect_node_chain_host.py"])
                    self.assertEqual(run.call_args_list[-1].kwargs["timeout"], 3000 + 4200 + 4200)

    def test_native_process_failure_cannot_reach_receipt_or_reuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            (bundle / "NATIVE-RUNTIME.json").write_bytes(b"original")
            failure = subprocess.CalledProcessError(1, ["actual-native-gate"])
            with patch.object(BUILD.platform, "system", return_value="Windows"), \
                 patch.object(BUILD, "native_host_target", return_value="windows/amd64"), \
                 patch.object(BUILD, "reuse", return_value={"policy_sha256": "a" * 64}) as reuse, \
                 patch.object(BUILD, "run", side_effect=["", "", "", "", "", "", failure]), \
                 patch.object(BUILD, "verify_installed_windows_socks_receipt") as verify:
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    BUILD.verify_installed_windows_prefix(ROOT, bundle, "windows/amd64", {})
                self.assertIs(caught.exception, failure)
                self.assertEqual(reuse.call_count, 1)
                verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
