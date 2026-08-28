#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import plistlib
import tarfile
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "routervpn_release_candidate_provenance_test",
    HERE / "verify-release-candidate-provenance.py",
)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER = "89abcdef0123456789abcdef0123456789abcdef"


def manifest(family: str, sha: str = SHA) -> bytes:
    return (json.dumps({
        "schema_version": 1,
        "repository": mod.REPO,
        "source_sha": sha,
        "artifact_family": family,
    }) + "\n").encode()


def zip_desktop(path: Path, family: str, sha: str = SHA, duplicate: bool = False) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        name = f"RouterVPN-{family}/ROUTER-VPN-SOURCE.json"
        zf.writestr(name, manifest(family, sha))
        zf.writestr(f"RouterVPN-{family}/payload.bin", b"payload")
        if duplicate:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                zf.writestr(name, manifest(family, sha))


def tar_desktop(path: Path, family: str, sha: str = SHA) -> None:
    with tempfile.TemporaryDirectory(prefix="routervpn-release-prov-tar-") as td:
        root = Path(td) / f"RouterVPN-{family}"
        root.mkdir()
        (root / "ROUTER-VPN-SOURCE.json").write_bytes(manifest(family, sha))
        (root / "payload.bin").write_bytes(b"payload")
        with tarfile.open(path, "w:gz") as tf:
            tf.add(root, arcname=root.name)


def android(path: Path, sha: str = SHA) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("classes.dex", b"dex")
        zf.writestr("assets/ROUTER-VPN-SOURCE.json", manifest("android-apk", sha))


def ios_plist(family: str, sha: str = SHA) -> bytes:
    return plistlib.dumps({
        "RouterVPNSourceSHA": sha,
        "RouterVPNSourceRepository": mod.REPO,
        "RouterVPNArtifactFamily": family,
    })


def ios(path: Path, sha: str = SHA) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Payload/RouterVPN.app/Info.plist", ios_plist("ios-app", sha))
        zf.writestr(
            "Payload/RouterVPN.app/PlugIns/RouterVPNPacketTunnel.appex/Info.plist",
            ios_plist("ios-packet-tunnel", sha),
        )


def build_tree(root: Path) -> None:
    for filename, (kind, family) in mod.EXPECTED.items():
        out = root / family / filename
        out.parent.mkdir(parents=True, exist_ok=True)
        if kind == "zip":
            zip_desktop(out, family)
        elif kind == "tar":
            tar_desktop(out, family)
        elif kind == "android":
            android(out)
        elif kind == "ios":
            ios(out)
        else:
            raise AssertionError(kind)


class ReleaseCandidateProvenanceTests(unittest.TestCase):
    def test_one_exact_sha_tree_passes(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-release-prov-") as td:
            root = Path(td)
            build_tree(root)
            mod.verify_tree(root, SHA)

    def test_one_wrong_package_sha_fails_whole_tree(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-release-prov-") as td:
            root = Path(td)
            build_tree(root)
            path = next(root.rglob("RouterVPN-Windows-amd64.zip"))
            zip_desktop(path, "windows-amd64", OTHER)
            with self.assertRaisesRegex(RuntimeError, "SHA mismatch"):
                mod.verify_tree(root, SHA)

    def test_duplicate_expected_package_fails(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-release-prov-") as td:
            root = Path(td)
            build_tree(root)
            duplicate = root / "duplicate" / "RouterVPN-Windows-amd64.zip"
            duplicate.parent.mkdir()
            zip_desktop(duplicate, "windows-amd64")
            with self.assertRaisesRegex(RuntimeError, "exactly one RouterVPN-Windows-amd64.zip"):
                mod.verify_tree(root, SHA)

    def test_symlinked_root_and_expected_package_fail_closed(self):
        if os.name == "nt":
            self.skipTest("symlink semantics are platform-specific")
        with tempfile.TemporaryDirectory(prefix="routervpn-release-prov-link-") as td:
            base = Path(td)
            real = base / "real"
            real.mkdir()
            build_tree(real)
            linked = base / "linked"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "root is missing or redirected"):
                mod.verify_tree(linked, SHA)

            package = next(real.rglob("RouterVPN-Windows-amd64.zip"))
            outside = base / "outside.zip"
            package.replace(outside)
            package.symlink_to(outside)
            with self.assertRaisesRegex(RuntimeError, "redirected or not a regular file"):
                mod.verify_tree(real, SHA)

    def test_outer_desktop_package_replacement_race_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-release-prov-race-") as td:
            root = Path(td)
            build_tree(root)
            package = next(root.rglob("RouterVPN-Windows-amd64.zip"))
            replacement = root / "replacement.zip"
            zip_desktop(replacement, "windows-amd64")
            real_open = Path.open
            swapped = False

            def swap_before_open(path_obj, *args, **kwargs):
                nonlocal swapped
                if path_obj == package and not swapped:
                    swapped = True
                    os.replace(replacement, package)
                return real_open(path_obj, *args, **kwargs)

            with mock.patch.object(Path, "open", new=swap_before_open):
                with self.assertRaisesRegex(RuntimeError, "changed identity during verification open"):
                    mod.verify_tree(root, SHA)
            self.assertTrue(swapped)

    def test_duplicate_embedded_manifest_fails(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-release-prov-") as td:
            root = Path(td)
            build_tree(root)
            path = next(root.rglob("RouterVPN-Windows-amd64.zip"))
            zip_desktop(path, "windows-amd64", duplicate=True)
            with self.assertRaisesRegex(RuntimeError, "expected one ROUTER-VPN-SOURCE.json, found 2"):
                mod.verify_tree(root, SHA)


if __name__ == "__main__":
    unittest.main()
