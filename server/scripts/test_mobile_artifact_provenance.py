#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "routervpn_mobile_artifact_provenance_test",
    HERE / "mobile-artifact-provenance.py",
)
assert SPEC and SPEC.loader
prov = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prov)

SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER = "89abcdef0123456789abcdef0123456789abcdef"
REPO = "Eabusham2/router-vpn"


def android_body(sha: str = SHA, repo: str = REPO, family: str = "android-apk") -> bytes:
    return (json.dumps({
        "schema_version": 1,
        "repository": repo,
        "source_sha": sha,
        "artifact_family": family,
    }) + "\n").encode()


def ios_plist(sha: str, repo: str, family: str) -> bytes:
    return plistlib.dumps({
        "CFBundleIdentifier": "com.eabusham.routervpn.test",
        "RouterVPNSourceSHA": sha,
        "RouterVPNSourceRepository": repo,
        "RouterVPNArtifactFamily": family,
    })


def write_apk(path: Path, body: bytes = b"", duplicate: bool = False) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("classes.dex", b"dex")
        if body:
            zf.writestr(prov.ANDROID_MEMBER, body)
            if duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    zf.writestr(prov.ANDROID_MEMBER, body)


def write_ipa(
    path: Path,
    app_sha: str = SHA,
    tunnel_sha: str = SHA,
    repo: str = REPO,
    app_family: str = "ios-app",
    tunnel_family: str = "ios-packet-tunnel",
    duplicate_app: bool = False,
    omit_tunnel: bool = False,
) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        app = ios_plist(app_sha, repo, app_family)
        zf.writestr(prov.IOS_APP_INFO, app)
        if duplicate_app:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                zf.writestr(prov.IOS_APP_INFO, app)
        if not omit_tunnel:
            zf.writestr(prov.IOS_TUNNEL_INFO, ios_plist(tunnel_sha, repo, tunnel_family))


class MobileArtifactProvenanceTests(unittest.TestCase):
    def test_exact_android_apk_is_accepted(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-mobile-prov-") as td:
            path = Path(td) / "app.apk"
            write_apk(path, android_body())
            prov.verify("router-vpn-android.apk", path, SHA, REPO)

    def test_android_wrong_identity_and_missing_or_duplicate_manifest_fail(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-mobile-prov-") as td:
            root = Path(td)
            cases = [
                ("wrong-sha.apk", android_body(OTHER), "source SHA mismatch"),
                ("wrong-repo.apk", android_body(repo="other/repo"), "repository mismatch"),
                ("wrong-family.apk", android_body(family="desktop"), "family mismatch"),
            ]
            for filename, body, message in cases:
                path = root / filename
                write_apk(path, body)
                with self.assertRaisesRegex(RuntimeError, message):
                    prov.verify("router-vpn-android.apk", path, SHA, REPO)

            missing = root / "missing.apk"
            write_apk(missing)
            with self.assertRaisesRegex(RuntimeError, "0 copies"):
                prov.verify("router-vpn-android.apk", missing, SHA, REPO)

            duplicate = root / "duplicate.apk"
            write_apk(duplicate, android_body(), duplicate=True)
            with self.assertRaisesRegex(RuntimeError, "2 copies"):
                prov.verify("router-vpn-android.apk", duplicate, SHA, REPO)

    def test_exact_ios_app_and_packet_tunnel_are_both_required(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-mobile-prov-") as td:
            path = Path(td) / "RouterVPN.ipa"
            write_ipa(path)
            prov.verify("router-vpn-ios.ipa", path, SHA, REPO)
            prov.verify("router-vpn-ios-preview.ipa", path, SHA, REPO)

    def test_ios_wrong_or_missing_extension_identity_fails(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-mobile-prov-") as td:
            root = Path(td)
            wrong_tunnel = root / "wrong-tunnel.ipa"
            write_ipa(wrong_tunnel, tunnel_sha=OTHER)
            with self.assertRaisesRegex(RuntimeError, "source SHA mismatch"):
                prov.verify("router-vpn-ios.ipa", wrong_tunnel, SHA, REPO)

            wrong_family = root / "wrong-family.ipa"
            write_ipa(wrong_family, app_family="not-ios-app")
            with self.assertRaisesRegex(RuntimeError, "family mismatch"):
                prov.verify("router-vpn-ios.ipa", wrong_family, SHA, REPO)

            missing = root / "missing-tunnel.ipa"
            write_ipa(missing, omit_tunnel=True)
            with self.assertRaisesRegex(RuntimeError, "0 copies"):
                prov.verify("router-vpn-ios.ipa", missing, SHA, REPO)

            duplicate = root / "duplicate-app.ipa"
            write_ipa(duplicate, duplicate_app=True)
            with self.assertRaisesRegex(RuntimeError, "2 copies"):
                prov.verify("router-vpn-ios.ipa", duplicate, SHA, REPO)

    def test_cli_verifies_packaged_ios_artifact(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-mobile-prov-cli-") as td:
            path = Path(td) / "RouterVPN.ipa"
            write_ipa(path)
            argv = [
                "mobile-artifact-provenance.py",
                "--name", "router-vpn-ios.ipa",
                "--path", str(path),
                "--sha", SHA,
                "--repo", REPO,
            ]
            with mock.patch("sys.argv", argv):
                self.assertEqual(prov.main(), 0)

    def test_unsupported_request_and_invalid_expected_identity_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-mobile-prov-") as td:
            path = Path(td) / "app.apk"
            write_apk(path, android_body())
            with self.assertRaisesRegex(RuntimeError, "unsupported mobile artifact"):
                prov.verify("unknown.apk", path, SHA, REPO)
            with self.assertRaisesRegex(RuntimeError, "full 40-character"):
                prov.verify("router-vpn-android.apk", path, "short", REPO)
            with self.assertRaisesRegex(RuntimeError, "repository is invalid"):
                prov.verify("router-vpn-android.apk", path, SHA, "invalid")


if __name__ == "__main__":
    unittest.main()
