#!/usr/bin/env python3
"""Exercise release SDK readback without compiling or claiming a native SDK."""
from pathlib import Path
import importlib.util
import json
import plistlib
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ios_generated_sdk", ROOT / "deploy/verify-ios-generated-sdk.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)
SDK = VERIFY.SDK
SHA = "a" * 40


def header():
    text = "".join(SDK.PLAN_DECL.replace("SOCKS", kind) + "\n" + "\n".join(SDK.PLAN_METHODS) + "\n@end\n" for kind in ("SOCKS", "CONNECT"))
    if hasattr(SDK, "LATENCY_DECL"):
        text += SDK.LATENCY_DECL + "\n" + "\n".join(SDK.LATENCY_METHODS) + "\n@end\n"
    text += "\n".join("FOUNDATION_EXPORT " + result + " " + name + "(" + ", ".join(arg + " p" + str(i) for i, arg in enumerate(args)) + ");" for name, result, args in SDK.C_FUNCTIONS)
    return text.encode()


class ReleaseSDKReadback(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.app_root = self.root / "ios/RouterVPN"
        self.framework = self.app_root / ".deps/Libbox.xcframework"
        self.headers = []
        libraries = []
        for identity, variant, arches in (("ios-arm64", "", ["arm64"]), ("ios-arm64_x86_64-simulator", "simulator", ["arm64", "x86_64"])):
            location = self.framework / identity / "Libbox.framework"
            (location / "Headers").mkdir(parents=True)
            (location / "Modules").mkdir()
            (location / "Libbox").write_bytes(b"fixture-binary")
            path = location / "Headers/Libbox.objc.h"
            path.write_bytes(header())
            self.headers.append(path)
            (location / "Modules/module.modulemap").write_text("framework module Libbox {}")
            item = dict(LibraryIdentifier=identity, LibraryPath="Libbox.framework", SupportedPlatform="ios", SupportedArchitectures=arches)
            if variant:
                item["SupportedPlatformVariant"] = variant
            libraries.append(item)
        (self.framework / "Info.plist").write_bytes(plistlib.dumps({"AvailableLibraries": libraries}))
        (self.app_root / ".deps/Libbox.xcframework.pin").write_text(SDK.LIBBOX_PIN)
        app = self.app_root / "build/DerivedData/Build/Products/Release-iphoneos/RouterVPN.app"
        for bundle, family, identifier, executable in ((app, "ios-app", "com.eabusham.routervpn", "RouterVPN"), (app / "PlugIns/RouterVPNPacketTunnel.appex", "ios-packet-tunnel", "com.eabusham.routervpn.PacketTunnel", "RouterVPNPacketTunnel")):
            bundle.mkdir(parents=True)
            info = dict(RouterVPNSourceSHA=SHA, RouterVPNSourceRepository="Eabusham2/router-vpn", RouterVPNArtifactFamily=family, CFBundleIdentifier=identifier, UIDeviceFamily=[1, 2], NSExtension=dict(NSExtensionPointIdentifier="com.apple.networkextension.packet-tunnel", NSExtensionPrincipalClass="RouterVPNPacketTunnel.PacketTunnelProvider"))
            (bundle / "Info.plist").write_bytes(plistlib.dumps(info))
            (bundle / executable).write_bytes(b"fixture-executable")
        self.ipa = self.app_root / "build/RouterVPN-native-unsigned-resignable.ipa"
        self.ipa.write_bytes(b"fixture-ipa")
        self.output = self.root / "receipt"
        self.root_patch = mock.patch.object(VERIFY, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.commands = []
        def execute(command, **kwargs):
            self.commands.append(command)
            if command[0] == "git":
                return SHA + "\n"
            self.assertEqual(command[:3], ["xcrun", "lipo", "-archs"])
            return "arm64 x86_64\n" if "simulator" in command[-1] else "arm64\n"
        self.process = mock.patch.object(VERIFY.subprocess, "check_output", side_effect=execute)
        self.process.start()
        self.addCleanup(self.process.stop)

    def test_source_bound_headers_and_sdk_ipa_hashes_without_rebuild(self):
        record = VERIFY.verify(SHA, self.output)
        self.assertEqual(record, json.loads((self.output / "receipt.json").read_text()))
        self.assertEqual(record["source_sha"], SHA)
        self.assertEqual(record["ipa_sha256"], SDK.sha_file(self.ipa))
        self.assertEqual(len(record["slices"]), 2)
        for item, original in zip(record["slices"], self.headers):
            self.assertEqual((self.output / item["header_file"]).read_bytes(), original.read_bytes())
            self.assertEqual(item["header_sha256"], SDK.sha_file(original))
        self.assertEqual([command[0] for command in self.commands], ["git", "xcrun", "xcrun"])
        self.assertFalse(record["physical_device_accepted"])

    def test_missing_connect_method_in_either_slice_refused(self):
        for path in self.headers:
            with self.subTest(slice=path.parent.parent.parent.name):
                original = path.read_bytes()
                marker = SDK.PLAN_DECL.replace("SOCKS", "CONNECT").encode()
                prefix, body = original.split(marker, 1)
                path.write_bytes(prefix + marker + body.replace(SDK.PLAN_METHODS[-1].encode(), b"", 1))
                with self.assertRaises(ValueError):
                    VERIFY.verify(SHA, self.output)
                self.assertFalse(self.output.exists())
                path.write_bytes(original)

    def test_wrong_source_missing_ipa_and_wrong_architecture_refused(self):
        with self.assertRaisesRegex(ValueError, "checkout"):
            VERIFY.verify("b" * 40, self.output)
        self.ipa.unlink()
        with self.assertRaises(ValueError):
            VERIFY.verify(SHA, self.output)
        self.ipa.write_bytes(b"fixture-ipa")
        with mock.patch.object(VERIFY.subprocess, "check_output", side_effect=[SHA, "x86_64"]):
            with self.assertRaisesRegex(ValueError, "architecture"):
                VERIFY.verify(SHA, self.output)
        self.assertFalse(self.output.exists())

    def test_framework_and_header_symlinks_refused(self):
        original = self.headers[0].read_bytes()
        target = self.root / "outside.h"
        target.write_bytes(original)
        self.headers[0].unlink()
        self.headers[0].symlink_to(target)
        with self.assertRaises(ValueError):
            VERIFY.verify(SHA, self.output)

    def test_release_workflow_requires_build_then_readback_and_separate_evidence(self):
        text = (ROOT / ".github/workflows/release-candidate.yml").read_text()
        ios = text.split("\n  ios:\n", 1)[1].split("\n  macos:\n", 1)[0]
        self.assertLess(ios.index("xcodebuild -project"), ios.index("verify-ios-generated-sdk.py"))
        self.assertLess(ios.index("mobile-artifact-provenance.py"), ios.index("verify-ios-generated-sdk.py"))
        self.assertIn('verify-ios-generated-sdk.py --source-sha "$GITHUB_SHA"', ios)
        self.assertIn("name: RouterVPN-iOS-generated-sdk-${{ github.sha }}", ios)
        self.assertIn("name: RouterVPN-iOS-release-candidate, path: ios/RouterVPN/build/RouterVPN-native-unsigned-resignable.ipa", ios)


if __name__ == "__main__":
    unittest.main()
