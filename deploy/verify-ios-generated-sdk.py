#!/usr/bin/env python3
"""Read back generated headers from the SDK used by the release Xcode build."""
from pathlib import Path
import argparse
import importlib.util
import json
import re
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PARSER_PATH = ROOT / "deploy/validate-ios-sdk-source.py"
SPEC = importlib.util.spec_from_file_location("release_ios_sdk_parser", PARSER_PATH)
SDK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SDK)


def verify(source_sha, output):
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("Exact release source SHA required")
    actual = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True, timeout=30
    ).strip()
    if actual != source_sha:
        raise ValueError("Release checkout differs from requested source")
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("Generated SDK receipt output must be fresh")
    app_root = ROOT / "ios/RouterVPN"
    framework = app_root / ".deps/Libbox.xcframework"
    pin = SDK.regular(app_root / ".deps/Libbox.xcframework.pin")
    if pin.read_text().strip() != SDK.LIBBOX_PIN:
        raise ValueError("Generated SDK pin differs from release source")
    app = app_root / "build/DerivedData/Build/Products/Release-iphoneos/RouterVPN.app"
    extension = app / "PlugIns/RouterVPNPacketTunnel.appex"
    # The workflow executes this after mandatory Xcode build and IPA packaging.
    # Verify their identities here without claiming device execution.
    for bundle, family, identifier, executable in (
        (app, "ios-app", "com.eabusham.routervpn", "RouterVPN"),
        (extension, "ios-packet-tunnel", "com.eabusham.routervpn.PacketTunnel", "RouterVPNPacketTunnel"),
    ):
        SDK.require_plist(bundle / "Info.plist", source_sha, family, identifier)
        SDK.regular(bundle / executable)
    ipa = SDK.regular(app_root / "build/RouterVPN-native-unsigned-resignable.ipa")
    slices = []
    headers = []
    for index, item in enumerate(SDK.framework_slices(framework)):
        raw = item["header"].read_bytes()
        api = SDK.require_headers(raw)
        actual_arches = sorted(subprocess.check_output(
            ["xcrun", "lipo", "-archs", str(item["binary"])], text=True, timeout=30
        ).split())
        if actual_arches != item["architectures"]:
            raise ValueError("Generated SDK binary architecture differs from slice metadata")
        name = "slice-" + str(index) + ".objc.h"
        slices.append(dict(
            identity=item["identity"], variant=item["variant"], architectures=actual_arches,
            header_file=name, generated_api=api,
            header_sha256=SDK.sha_file(item["header"]),
            binary_sha256=SDK.sha_file(item["binary"]),
            module_sha256=SDK.sha_file(item["module"]),
        ))
        headers.append((name, raw))
    receipt = dict(
        schema=1, status="passed", source_sha=source_sha,
        scope="generated SDK API readback from the release Xcode build",
        generated_sdk_headers_verified=True, physical_device_accepted=False,
        parser_sha256=SDK.sha_file(PARSER_PATH), verifier_sha256=SDK.sha_file(__file__),
        libbox_pin=SDK.LIBBOX_PIN, framework_info_sha256=SDK.sha_file(framework / "Info.plist"),
        ipa_sha256=SDK.sha_file(ipa), ipa_bytes=ipa.stat().st_size, slices=slices,
    )
    output.mkdir(parents=True)
    for name, raw in headers:
        (output / name).write_bytes(raw)
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.source_sha, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
