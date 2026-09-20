#!/usr/bin/env python3
"""Type-check the real forwarding transport with the real Apple SDK, no mocks."""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TUNNEL = ROOT / "ios/RouterVPN/PacketTunnel"
HEADER = TUNNEL / "RVPNTunnelTCPConnection.h"


def main():
    # Linux can run the pure policy and async UI tests, not substitute an SDK.
    if platform.system() != "Darwin":
        print("iOS forwarding real-SDK type-check: SKIP (requires Apple SDK; native CI runs this gate)")
        return
    if not shutil.which("xcrun"):
        raise SystemExit("xcrun is required on the native forwarding lane")
    sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="routervpn-forwarding-sdk-") as tmp:
        subprocess.run([
            "xcrun", "--sdk", "iphoneos", "clang", "-fsyntax-only", "-fobjc-arc",
            "-target", "arm64-apple-ios17.0", "-isysroot", sdk,
            str(TUNNEL / "RVPNTunnelTCPConnection.m"),
        ], check=True, timeout=90)
        subprocess.run([
            "xcrun", "--sdk", "iphoneos", "swiftc", "-typecheck", "-swift-version", "6",
            "-strict-concurrency=complete", "-target", "arm64-apple-ios17.0", "-sdk", sdk,
            "-module-cache-path", str(Path(tmp) / "modules"),
            "-import-objc-header", str(HEADER),
            str(TUNNEL / "RouterVPNForwardingPolicy.swift"),
            str(TUNNEL / "RouterVPNForwardingChannel.swift"),
        ], check=True, timeout=120)
    print("iOS forwarding real-SDK type-check: PASS (Objective-C adapter + unchanged Swift channel/policy, iOS 17 floor)")


if __name__ == "__main__":
    main()
