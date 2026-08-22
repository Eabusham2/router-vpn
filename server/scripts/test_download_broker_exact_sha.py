#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

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


if __name__ == "__main__":
    unittest.main()
