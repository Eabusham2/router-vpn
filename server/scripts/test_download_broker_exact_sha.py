#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

HERE = Path(__file__).resolve().parent
BROKER_PATH = HERE / "download-broker.py"
spec = importlib.util.spec_from_file_location("routervpn_download_broker_exact_sha_test", BROKER_PATH)
assert spec and spec.loader
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)

SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER = "89abcdef0123456789abcdef0123456789abcdef"


class DownloadBrokerExactSHATests(unittest.TestCase):
    def test_github_scope_requires_full_sha(self):
        with mock.patch.dict(os.environ, {
            "ROUTER_VPN_GITHUB_REPO": "Eabusham2/router-vpn",
            "ROUTER_VPN_GITHUB_BRANCH": "main",
        }, clear=True):
            with self.assertRaisesRegex(RuntimeError, "is required and must be a full 40-character commit SHA"):
                broker._github_scope()
        with mock.patch.dict(os.environ, {"ROUTER_VPN_GITHUB_SHA": "abc123"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "is required and must be a full 40-character commit SHA"):
                broker._github_scope()

    def test_github_scope_preserves_exact_release_sha(self):
        with mock.patch.dict(os.environ, {
            "ROUTER_VPN_GITHUB_REPO": "Eabusham2/router-vpn",
            "ROUTER_VPN_GITHUB_BRANCH": "main",
            "ROUTER_VPN_GITHUB_SHA": SHA.upper(),
        }, clear=True):
            repo, branch, head = broker._github_scope()
        self.assertEqual((repo, branch, head), ("Eabusham2/router-vpn", "main", SHA))

    def test_artifact_candidates_never_float_to_other_main_sha(self):
        meta = {"artifacts": [
            {"id": 1, "name": "RouterVPN-iOS-release-candidate", "expired": False, "created_at": "2026-08-22T01:00:00Z", "workflow_run": {"head_branch": "main", "head_sha": SHA}},
            {"id": 2, "name": "RouterVPN-iOS-release-candidate", "expired": False, "created_at": "2026-08-22T02:00:00Z", "workflow_run": {"head_branch": "main", "head_sha": OTHER}},
            {"id": 3, "name": "RouterVPN-iOS-release-candidate", "expired": True, "created_at": "2026-08-22T03:00:00Z", "workflow_run": {"head_branch": "main", "head_sha": SHA}},
            {"id": 4, "name": "RouterVPN-iOS-release-candidate", "expired": False, "created_at": "2026-08-22T04:00:00Z", "workflow_run": {"head_branch": "other", "head_sha": SHA}},
        ]}
        got = broker._artifact_candidates(meta, "RouterVPN-iOS-release-candidate", "main", SHA)
        self.assertEqual([item["id"] for item in got], [1])

    def test_artifact_member_scan_rejects_encryption_count_and_duplicates(self):
        class FakeZip:
            def __init__(self, items):
                self._items = items
            def infolist(self):
                return self._items

        encrypted = zipfile.ZipInfo("RouterVPN-Windows-amd64.zip")
        encrypted.flag_bits = 0x1
        encrypted.file_size = 16
        encrypted.compress_size = 16
        with self.assertRaisesRegex(RuntimeError, "encrypted member"):
            broker._pick_member(FakeZip([encrypted]), "RouterVPN-Windows-amd64.zip")

        first = zipfile.ZipInfo("one.txt")
        second = zipfile.ZipInfo("two.txt")
        for item in (first, second):
            item.file_size = 1
            item.compress_size = 1
        with mock.patch.object(broker, "MAX_ARTIFACT_MEMBERS", 1):
            with self.assertRaisesRegex(RuntimeError, "too many members"):
                broker._pick_member(FakeZip([first, second]), "one.txt")

        dup1 = zipfile.ZipInfo("a/RouterVPN-Windows-amd64.zip")
        dup2 = zipfile.ZipInfo("b/RouterVPN-Windows-amd64.zip")
        for item in (dup1, dup2):
            item.file_size = 1
            item.compress_size = 1
        with self.assertRaisesRegex(RuntimeError, "2 copies"):
            broker._pick_member(FakeZip([dup1, dup2]), "RouterVPN-Windows-amd64.zip")

    def test_desktop_can_fall_back_to_router_local_same_image_builder(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-broker-sha-test-") as td:
            temp = Path(td)
            expected = temp / "router-vpn-windows-amd64.zip"
            expected.write_bytes(b"fake-local-package")
            with mock.patch.object(broker, "fetch_github_package", side_effect=RuntimeError("exact SHA unavailable")), \
                 mock.patch.object(broker, "_run_builder", return_value=expected) as run_builder:
                result, source = broker.build_package(Path(td), "router-vpn-windows-amd64.zip", temp)
            self.assertEqual(result, expected)
            self.assertEqual(source, "router-local-generic-build")
            self.assertIsNone(run_builder.call_args.args[3])

    def test_mobile_missing_sha_fails_before_any_github_network_call(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-broker-mobile-sha-test-") as td, \
             mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(broker, "_read_limited_json", side_effect=AssertionError("network must not be reached without exact SHA")):
            with self.assertRaisesRegex(RuntimeError, "same-SHA GitHub mobile artifact") as caught:
                broker.fetch_direct_mobile("router-vpn-ios.ipa", Path(td))
            self.assertIn("ROUTER_VPN_GITHUB_SHA is required", str(caught.exception))

    def test_mobile_binary_is_reverified_after_exact_sha_artifact_selection(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-broker-mobile-prov-test-") as td:
            temp = Path(td)
            selected = temp / "router-vpn-ios.ipa"
            selected.write_bytes(b"synthetic-ipa")
            with mock.patch.object(broker, "_github_scope", return_value=("Eabusham2/router-vpn", "main", SHA)), \
                 mock.patch.object(broker, "fetch_artifact_member", return_value=selected), \
                 mock.patch.object(broker._mobile_provenance, "verify") as verify:
                got = broker.fetch_direct_mobile("router-vpn-ios.ipa", temp)
            self.assertEqual(got, selected)
            verify.assert_called_once_with("router-vpn-ios.ipa", selected, SHA, "Eabusham2/router-vpn")

    def test_mobile_binary_provenance_failure_blocks_delivery(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-broker-mobile-prov-fail-") as td:
            temp = Path(td)
            selected = temp / "router-vpn-android.apk"
            selected.write_bytes(b"synthetic-apk")
            with mock.patch.object(broker, "_github_scope", return_value=("Eabusham2/router-vpn", "main", SHA)), \
                 mock.patch.object(broker, "fetch_artifact_member", return_value=selected), \
                 mock.patch.object(broker._mobile_provenance, "verify", side_effect=RuntimeError("mobile artifact source SHA mismatch")):
                with self.assertRaisesRegex(RuntimeError, "same-SHA GitHub mobile artifact.*source SHA mismatch"):
                    broker.fetch_direct_mobile("router-vpn-android.apk", temp)
            self.assertFalse(selected.exists(), "rejected mobile artifact survived provenance failure")

    def test_corrupt_preferred_mobile_artifact_falls_through_to_second_same_sha_source(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-broker-mobile-prov-fallback-") as td:
            temp = Path(td)
            selected = temp / "router-vpn-ios.ipa"
            calls = []

            def fetch(artifact_name, wanted, root, output_name, progress=None):
                calls.append(artifact_name)
                selected.write_bytes(("candidate-" + artifact_name).encode())
                return selected

            def verify(name, path, sha, repo):
                if len(calls) == 1:
                    raise RuntimeError("preferred artifact has wrong embedded source")
                self.assertEqual((name, sha, repo), ("router-vpn-ios.ipa", SHA, "Eabusham2/router-vpn"))
                self.assertTrue(path.is_file())

            with mock.patch.object(broker, "_github_scope", return_value=("Eabusham2/router-vpn", "main", SHA)), \
                 mock.patch.object(broker, "fetch_artifact_member", side_effect=fetch), \
                 mock.patch.object(broker._mobile_provenance, "verify", side_effect=verify):
                got = broker.fetch_direct_mobile("router-vpn-ios.ipa", temp)
            self.assertEqual(got, selected)
            self.assertEqual(calls, ["RouterVPN-iOS-release-candidate", "RouterVPN-iOS-Native-CI"])
            self.assertIn(b"RouterVPN-iOS-Native-CI", selected.read_bytes())


if __name__ == "__main__":
    unittest.main()
