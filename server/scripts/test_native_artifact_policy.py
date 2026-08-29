#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = load("native_artifact_policy_test", "native_artifact_policy.py")
builder = load("download_builder_test", "build-download-on-demand.py")


class NativeArtifactPolicyTests(unittest.TestCase):
    def test_every_desktop_request_has_exact_member_mapping(self):
        expected = {name: spec[0] for name, spec in builder.PACKAGE_MAP.items() if spec[1] != "bundle"}
        self.assertEqual(set(policy.NATIVE_PACKAGE_ARTIFACTS), set(expected))
        for request, member in expected.items():
            sources = policy.NATIVE_PACKAGE_ARTIFACTS[request]
            self.assertGreaterEqual(len(sources), 2)
            self.assertEqual(sources[0][1], member)
            self.assertTrue(sources[0][0].endswith("release-candidate"), sources[0])

    def test_native_macos_and_linux_do_not_prefer_controller_only_artifact(self):
        for request in ("router-vpn-macos-amd64.zip", "router-vpn-macos-arm64.zip"):
            names = [x[0] for x in policy.NATIVE_PACKAGE_ARTIFACTS[request]]
            self.assertEqual(names[0], "RouterVPN-macOS-release-candidate")
            self.assertEqual(names[1], "RouterVPN-macOS-Native-CI")
            self.assertNotIn("RouterVPN-client-desktop-unix-ci", names)
        for arch in ("amd64", "arm64"):
            request = f"router-vpn-linux-{arch}.zip"
            names = [x[0] for x in policy.NATIVE_PACKAGE_ARTIFACTS[request]]
            self.assertEqual(names[0], f"RouterVPN-Linux-{arch}-release-candidate")
            self.assertEqual(names[1], f"RouterVPN-Linux-Native-{arch}-CI")
            self.assertNotIn("RouterVPN-client-desktop-unix-ci", names)

    def test_windows_native_wpf_uses_generic_release_artifact_then_desktop_ci(self):
        for request in (
            "router-vpn-windows-amd64.zip", "router-vpn-windows-arm64.zip",
            "router-vpn-windows-portable-amd64.zip", "router-vpn-windows-portable-arm64.zip",
        ):
            names = [x[0] for x in policy.NATIVE_PACKAGE_ARTIFACTS[request]]
            self.assertEqual(names, ["RouterVPN-generic-release-candidate", "RouterVPN-client-desktop-unix-ci"])

    def test_every_download_artifact_has_closed_producer_workflow_mapping(self):
        expected = {}
        for sources in policy.NATIVE_PACKAGE_ARTIFACTS.values():
            for artifact, _member in sources:
                expected.setdefault(artifact, None)
        for spec in policy.DIRECT_ARTIFACTS.values():
            for artifact, _member in spec["sources"]:
                expected.setdefault(artifact, None)
        self.assertEqual(set(policy.ARTIFACT_PRODUCER_WORKFLOWS), set(expected))
        for artifact, workflow in policy.ARTIFACT_PRODUCER_WORKFLOWS.items():
            self.assertIn(workflow, {
                "build-all.yml",
                "client-apps-ci.yml",
                "macos-native-app.yml",
                "linux-native-app.yml",
            }, artifact)
        for artifact in (
            "RouterVPN-generic-release-candidate",
            "RouterVPN-macOS-release-candidate",
            "RouterVPN-Linux-amd64-release-candidate",
            "RouterVPN-Linux-arm64-release-candidate",
            "RouterVPN-Android-release-candidate",
            "RouterVPN-iOS-release-candidate",
        ):
            self.assertEqual(policy.ARTIFACT_PRODUCER_WORKFLOWS[artifact], "build-all.yml")
        self.assertEqual(policy.ARTIFACT_PRODUCER_WORKFLOWS["RouterVPN-macOS-Native-CI"], "macos-native-app.yml")
        self.assertEqual(policy.ARTIFACT_PRODUCER_WORKFLOWS["RouterVPN-Linux-Native-amd64-CI"], "linux-native-app.yml")
        self.assertEqual(policy.ARTIFACT_PRODUCER_WORKFLOWS["RouterVPN-Linux-Native-arm64-CI"], "linux-native-app.yml")

    def test_mobile_is_same_sha_artifact_only_and_ios_preview_is_alias(self):
        android = policy.DIRECT_ARTIFACTS["router-vpn-android.apk"]["sources"]
        self.assertEqual(android[0], ("RouterVPN-Android-release-candidate", "app-debug.apk"))
        ios = policy.DIRECT_ARTIFACTS["router-vpn-ios.ipa"]["sources"]
        self.assertEqual(ios[0], ("RouterVPN-iOS-release-candidate", "RouterVPN-native-unsigned-resignable.ipa"))
        self.assertEqual(ios[1], ("RouterVPN-iOS-Native-CI", "RouterVPN-native-unsigned-resignable.ipa"))
        self.assertEqual(policy.DIRECT_ARTIFACTS["router-vpn-ios-preview.ipa"]["sources"], ios)


if __name__ == "__main__":
    unittest.main()
