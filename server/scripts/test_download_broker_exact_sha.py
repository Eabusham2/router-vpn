#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import io
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
            {"id": 1, "name": "RouterVPN-iOS-release-candidate", "expired": False, "created_at": "2026-08-22T01:00:00Z", "workflow_run": {"id": 101, "head_branch": "main", "head_sha": SHA}},
            {"id": 2, "name": "RouterVPN-iOS-release-candidate", "expired": False, "created_at": "2026-08-22T02:00:00Z", "workflow_run": {"id": 101, "head_branch": "main", "head_sha": OTHER}},
            {"id": 3, "name": "RouterVPN-iOS-release-candidate", "expired": True, "created_at": "2026-08-22T03:00:00Z", "workflow_run": {"id": 101, "head_branch": "main", "head_sha": SHA}},
            {"id": 4, "name": "RouterVPN-iOS-release-candidate", "expired": False, "created_at": "2026-08-22T04:00:00Z", "workflow_run": {"id": 101, "head_branch": "other", "head_sha": SHA}},
            {"id": 5, "name": "RouterVPN-iOS-release-candidate", "expired": False, "created_at": "2026-08-22T05:00:00Z", "workflow_run": {"id": 99, "head_branch": "main", "head_sha": SHA}},
        ]}
        got = broker._artifact_candidates(meta, "RouterVPN-iOS-release-candidate", "main", SHA, 101)
        self.assertEqual([item["id"] for item in got], [1])

    def test_newest_meaningful_producer_run_controls_artifact_evidence(self):
        base = [{"id": 10, "head_sha": SHA, "head_branch": "main", "status": "completed", "conclusion": "success"}]
        self.assertEqual(broker._newest_meaningful_workflow_run(base, "main", SHA)["id"], 10)

        failed = base + [{"id": 11, "head_sha": SHA, "head_branch": "main", "status": "completed", "conclusion": "failure"}]
        self.assertEqual(broker._newest_meaningful_workflow_run(failed, "main", SHA)["conclusion"], "failure")

        pending = base + [{"id": 12, "head_sha": SHA, "head_branch": "main", "status": "in_progress", "conclusion": ""}]
        self.assertIsNone(broker._newest_meaningful_workflow_run(pending, "main", SHA))

        cancelled = base + [{"id": 13, "head_sha": SHA, "head_branch": "main", "status": "completed", "conclusion": "cancelled"}]
        self.assertEqual(broker._newest_meaningful_workflow_run(cancelled, "main", SHA)["id"], 10)

        wrong = [
            {"id": 20, "head_sha": OTHER, "head_branch": "main", "status": "completed", "conclusion": "success"},
            {"id": 21, "head_sha": SHA, "head_branch": "other", "status": "completed", "conclusion": "success"},
        ]
        self.assertIsNone(broker._newest_meaningful_workflow_run(wrong, "main", SHA))

    def test_successful_producer_run_requires_settled_success_and_closed_mapping(self):
        success_meta = {"workflow_runs": [
            {"id": 44, "head_sha": SHA, "head_branch": "main", "status": "completed", "conclusion": "success"},
        ]}
        with mock.patch.object(broker, "_read_limited_json", return_value=success_meta) as read:
            got = broker._successful_producer_run_id(
                "Eabusham2/router-vpn", "RouterVPN-iOS-release-candidate", "main", SHA
            )
        self.assertEqual(got, 44)
        self.assertIn("/actions/workflows/build-all.yml/runs?", read.call_args.args[0])

        failed_meta = {"workflow_runs": [
            {"id": 45, "head_sha": SHA, "head_branch": "main", "status": "completed", "conclusion": "failure"},
        ]}
        with mock.patch.object(broker, "_read_limited_json", return_value=failed_meta):
            with self.assertRaisesRegex(RuntimeError, "no settled successful exact-SHA run"):
                broker._successful_producer_run_id(
                    "Eabusham2/router-vpn", "RouterVPN-iOS-release-candidate", "main", SHA
                )

        with self.assertRaisesRegex(RuntimeError, "no closed producer-workflow mapping"):
            broker._successful_producer_run_id(
                "Eabusham2/router-vpn", "Unknown-RouterVPN-artifact", "main", SHA
            )

    def test_fetch_artifact_member_rejects_artifact_from_older_producer_run(self):
        artifact_meta = {"artifacts": [
            {"id": 1, "name": "RouterVPN-iOS-release-candidate", "expired": False,
             "created_at": "2026-08-22T01:00:00Z",
             "workflow_run": {"id": 40, "head_branch": "main", "head_sha": SHA}},
        ]}
        with tempfile.TemporaryDirectory(prefix="routervpn-artifact-run-test-") as td, \
             mock.patch.object(broker, "_github_scope", return_value=("Eabusham2/router-vpn", "main", SHA)), \
             mock.patch.object(broker, "_successful_producer_run_id", return_value=41), \
             mock.patch.object(broker, "_read_limited_json", return_value=artifact_meta), \
             mock.patch.object(broker, "_download_limited", side_effect=AssertionError("stale producer artifact must not download")):
            with self.assertRaisesRegex(RuntimeError, "expected exactly one unexpired RouterVPN-iOS-release-candidate artifact"):
                broker.fetch_artifact_member(
                    "RouterVPN-iOS-release-candidate",
                    "RouterVPN-native-unsigned-resignable.ipa",
                    Path(td),
                    "router-vpn-ios.ipa",
                )

    def test_fetch_artifact_member_scopes_lookup_to_exact_producer_run_and_rejects_duplicate_artifacts(self):
        base_item = {
            "id": 9,
            "name": "RouterVPN-iOS-release-candidate",
            "expired": False,
            "created_at": "2026-08-22T01:00:00Z",
            "archive_download_url": "https://example.invalid/artifact",
            "workflow_run": {"id": 77, "head_branch": "main", "head_sha": SHA},
        }
        with tempfile.TemporaryDirectory(prefix="routervpn-artifact-scope-test-") as td, \
             mock.patch.object(broker, "_github_scope", return_value=("Eabusham2/router-vpn", "main", SHA)), \
             mock.patch.object(broker, "_successful_producer_run_id", return_value=77), \
             mock.patch.object(broker, "_read_limited_json", return_value={"artifacts": [base_item, dict(base_item, id=10)}) as read, \
             mock.patch.object(broker, "_download_limited", side_effect=AssertionError("ambiguous artifacts must not download")):
            with self.assertRaisesRegex(RuntimeError, "found 2"):
                broker.fetch_artifact_member(
                    "RouterVPN-iOS-release-candidate",
                    "RouterVPN-native-unsigned-resignable.ipa",
                    Path(td),
                    "router-vpn-ios.ipa",
                )
        self.assertIn("/actions/runs/77/artifacts?", read.call_args.args[0])

    def test_artifact_digest_metadata_is_mandatory_and_strict(self):
        digest = "a" * 64
        self.assertEqual(broker._artifact_sha256({"digest": "sha256:" + digest}), digest)
        for item in (
            {},
            {"digest": ""},
            {"digest": "md5:" + ("a" * 32)},
            {"digest": "sha256:short"},
            {"digest": "sha256:" + ("g" * 64)},
        ):
            with self.assertRaisesRegex(RuntimeError, "SHA-256 digest"):
                broker._artifact_sha256(item)

    def test_verified_artifact_zip_hashes_and_uses_same_descriptor(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-artifact-digest-") as td:
            root = Path(td)
            outer = root / "artifact.zip"
            with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("payload.txt", b"hello")
            expected = hashlib.sha256(outer.read_bytes()).hexdigest()
            with broker._verified_artifact_zip(outer, expected) as stream:
                with zipfile.ZipFile(stream) as zf:
                    self.assertEqual(zf.read("payload.txt"), b"hello")
            with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                with broker._verified_artifact_zip(outer, "0" * 64):
                    pass

    def test_verified_artifact_zip_rejects_replacement_between_lstat_and_open(self):
        if os.name == "nt":
            self.skipTest("POSIX replacement identity semantics required")
        with tempfile.TemporaryDirectory(prefix="routervpn-artifact-open-race-") as td:
            root = Path(td)
            outer = root / "artifact.zip"
            foreign = root / "foreign.zip"
            for path, value in ((outer, b"owned"), (foreign, b"foreign")):
                path.write_bytes(value)
                os.chmod(path, 0o600)
            expected = hashlib.sha256(b"owned").hexdigest()
            real_open = broker.os.open
            swapped = False

            def swap_then_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if Path(path) == outer and not swapped:
                    swapped = True
                    os.replace(foreign, outer)
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(broker.os, "open", side_effect=swap_then_open):
                with self.assertRaisesRegex(RuntimeError, "changed during verification open"):
                    with broker._verified_artifact_zip(outer, expected):
                        pass
            self.assertEqual(outer.read_bytes(), b"foreign")

    def test_download_limited_cleans_partial_and_length_mismatched_artifacts(self):
        class FakeResponse:
            def __init__(self, chunks, length):
                self._chunks = iter(chunks)
                self.headers = {"Content-Length": str(length)}
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def read(self, _size):
                value = next(self._chunks)
                if isinstance(value, BaseException):
                    raise value
                return value

        with tempfile.TemporaryDirectory(prefix="routervpn-artifact-partial-") as td:
            root = Path(td)
            partial = root / "partial.zip"
            with mock.patch.object(
                broker, "_urlopen",
                return_value=FakeResponse([b"abc", OSError("network reset")], 6),
            ):
                with self.assertRaisesRegex(OSError, "network reset"):
                    broker._download_limited("https://api.github.com/fake", partial)
            self.assertFalse(partial.exists(), "partial failed download survived")

            mismatch = root / "mismatch.zip"
            with mock.patch.object(
                broker, "_urlopen",
                return_value=FakeResponse([b"abc", b""], 4),
            ):
                with self.assertRaisesRegex(RuntimeError, "Content-Length mismatch"):
                    broker._download_limited("https://api.github.com/fake", mismatch)
            self.assertFalse(mismatch.exists(), "length-mismatched download survived")

    def test_fetch_artifact_member_verifies_outer_digest_before_extraction(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-artifact-fetch-digest-") as td:
            temp = Path(td)
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("RouterVPN-native-unsigned-resignable.ipa", b"ipa-bytes")
            archive = buf.getvalue()
            good_digest = hashlib.sha256(archive).hexdigest()
            base_item = {
                "id": 9,
                "name": "RouterVPN-iOS-release-candidate",
                "expired": False,
                "created_at": "2026-08-22T01:00:00Z",
                "archive_download_url": "https://api.github.com/artifacts/9/zip",
                "digest": "sha256:" + good_digest,
                "workflow_run": {"id": 77, "head_branch": "main", "head_sha": SHA},
            }

            def write_archive(_url, path, progress=None):
                path.write_bytes(archive)
                os.chmod(path, 0o600)

            with mock.patch.object(broker, "_github_scope", return_value=("Eabusham2/router-vpn", "main", SHA)), \
                 mock.patch.object(broker, "_successful_producer_run_id", return_value=77), \
                 mock.patch.object(broker, "_read_limited_json", return_value={"artifacts": [base_item]}), \
                 mock.patch.object(broker, "_download_limited", side_effect=write_archive):
                selected = broker.fetch_artifact_member(
                    "RouterVPN-iOS-release-candidate",
                    "RouterVPN-native-unsigned-resignable.ipa",
                    temp,
                    "router-vpn-ios.ipa",
                )
            self.assertEqual(selected.read_bytes(), b"ipa-bytes")

            bad_item = dict(base_item, digest="sha256:" + ("0" * 64))
            with mock.patch.object(broker, "_github_scope", return_value=("Eabusham2/router-vpn", "main", SHA)), \
                 mock.patch.object(broker, "_successful_producer_run_id", return_value=77), \
                 mock.patch.object(broker, "_read_limited_json", return_value={"artifacts": [bad_item]}), \
                 mock.patch.object(broker, "_download_limited", side_effect=write_archive):
                with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                    broker.fetch_artifact_member(
                        "RouterVPN-iOS-release-candidate",
                        "RouterVPN-native-unsigned-resignable.ipa",
                        temp,
                        "router-vpn-ios-bad.ipa",
                    )
            self.assertFalse((temp / "router-vpn-ios-bad.ipa").exists())

            missing = dict(base_item)
            missing.pop("digest")
            with mock.patch.object(broker, "_github_scope", return_value=("Eabusham2/router-vpn", "main", SHA)), \
                 mock.patch.object(broker, "_successful_producer_run_id", return_value=77), \
                 mock.patch.object(broker, "_read_limited_json", return_value={"artifacts": [missing]}), \
                 mock.patch.object(broker, "_download_limited", side_effect=AssertionError("missing digest must fail before download")):
                with self.assertRaisesRegex(RuntimeError, "missing a SHA-256 digest"):
                    broker.fetch_artifact_member(
                        "RouterVPN-iOS-release-candidate",
                        "RouterVPN-native-unsigned-resignable.ipa",
                        temp,
                        "router-vpn-ios-missing.ipa",
                    )

    def test_digest_failure_falls_through_to_next_exact_sha_desktop_producer(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-digest-fallback-") as td:
            temp = Path(td)
            name = "router-vpn-macos-arm64.zip"
            result = temp / name
            calls = []

            def fetch(artifact_name, wanted, root, output_name, progress=None):
                calls.append(artifact_name)
                if len(calls) == 1:
                    raise RuntimeError("GitHub artifact archive SHA-256 digest mismatch")
                candidate = root / output_name
                candidate.write_bytes(b"second-producer")
                return candidate

            def validate(base, request_name, root, candidate, progress=None):
                result.write_bytes(b"validated-second-producer")
                return result

            with mock.patch.object(broker, "fetch_artifact_member", side_effect=fetch), \
                 mock.patch.object(broker, "_run_builder", side_effect=validate):
                got = broker.build_github_package(Path(td), name, temp)
            self.assertEqual(got.read_bytes(), b"validated-second-producer")
            self.assertEqual(
                calls,
                ["RouterVPN-macOS-release-candidate", "RouterVPN-macOS-Native-CI"],
            )

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
            with mock.patch.object(broker, "build_github_package", side_effect=RuntimeError("exact SHA unavailable")), \
                 mock.patch.object(broker, "_run_builder", return_value=expected) as run_builder:
                result, source = broker.build_package(Path(td), "router-vpn-windows-amd64.zip", temp)
            self.assertEqual(result, expected)
            self.assertEqual(source, "router-local-generic-build")
            self.assertIsNone(run_builder.call_args.args[3])

    def test_corrupt_preferred_desktop_artifact_falls_through_to_second_same_sha_source(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-desktop-prov-fallback-") as td:
            temp = Path(td)
            name = "router-vpn-macos-arm64.zip"
            generic = broker._builder.generic_name(name)
            self.assertIsNotNone(generic)
            calls = []
            result = temp / name

            def fetch(artifact_name, wanted, root, output_name, progress=None):
                calls.append(artifact_name)
                candidate = root / output_name
                candidate.write_bytes(("candidate-" + artifact_name).encode())
                return candidate

            def validate(base, request_name, root, candidate, progress=None):
                self.assertEqual(request_name, name)
                if len(calls) == 1:
                    raise RuntimeError("preferred artifact embedded source SHA mismatch")
                result.write_bytes(b"validated-second-source")
                return result

            with mock.patch.object(broker, "fetch_artifact_member", side_effect=fetch), \
                 mock.patch.object(broker, "_run_builder", side_effect=validate):
                got = broker.build_github_package(Path(td), name, temp)
            self.assertEqual(got, result)
            self.assertEqual(
                calls,
                ["RouterVPN-macOS-release-candidate", "RouterVPN-macOS-Native-CI"],
            )
            self.assertEqual(result.read_bytes(), b"validated-second-source")
            self.assertFalse((temp / generic).exists(), "rejected/consumed source artifact survived")

    def test_desktop_does_not_use_local_fallback_when_second_github_candidate_validates(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-desktop-second-source-") as td:
            temp = Path(td)
            expected = temp / "router-vpn-linux-arm64.zip"
            expected.write_bytes(b"validated-native-ci")
            with mock.patch.object(broker, "build_github_package", return_value=expected), \
                 mock.patch.object(broker, "_run_builder", side_effect=AssertionError("local fallback must not run")):
                got, source = broker.build_package(Path(td), "router-vpn-linux-arm64.zip", temp)
            self.assertEqual(got, expected)
            self.assertEqual(source, "github")

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
