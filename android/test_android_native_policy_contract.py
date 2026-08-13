#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent
JAVA = ROOT / "app/src/main/java/com/eabusham/routervpn"

def read(name):
    text = (JAVA / name).read_text(encoding="utf-8")
    assert text.strip(), f"{name} is empty"
    return text

policy = read("AndroidNativeProfilePolicy.java")
wg = read("NativeWireGuardController.java")
awg = read("NativeAmneziaWGController.java")
xray = read("NativeXrayController.java")
monitor = read("AndroidUnderlyingNetworkMonitor.java")
main = read("MainActivity.java")

for marker in (
    "patchWireGuardLikeConfig",
    "selectedPlainUdpDns",
    '"home".equals(mode)',
    '"fastest".equals(mode)',
    '"custom".equals(mode)',
    'if (!"udp".equals(protocol))',
    "requires an encrypted/transport-aware resolver",
    "cannot be enforced by Android's address-only native VPN DNS API",
    "isLiteralIp",
    '"manual".equals(policy)',
    '"auto".equals(policy)',
    "return base;",
):
    assert marker in policy, f"native profile policy missing {marker}"

for name, source in (("WireGuard", wg), ("AmneziaWG", awg)):
    for marker in (
        "AndroidNativeProfilePolicy.patchWireGuardLikeConfig",
        "AndroidPathProbe.prove(privateBundle, 8000)",
        "AndroidUnderlyingNetworkMonitor",
        "recoverAfterNetworkChange",
        "backend.setState(this, State.DOWN, null)",
        "AndroidPathProbe.prove(bundle, 10000)",
        "network-transition recovery failed closed",
        "String getError()",
    ):
        assert marker in source, f"{name} missing native proof/recovery marker {marker}"

for marker in (
    "AndroidNativeProfilePolicy.selectedPlainUdpDns(root)",
    "AndroidNativeProfilePolicy.selectedMtu(root, 1380)",
):
    assert marker in xray, f"Xray native policy not wired: {marker}"

for marker in (
    "NET_CAPABILITY_NOT_VPN",
    "initialized && (current == null || !current.equals(network))",
    "if (current != null && current.equals(network)) current = null",
):
    assert marker in monitor, f"underlying-network monitor missing {marker}"

for marker in (
    "Native WG/AWG/Xray enforce only literal-IP UDP DNS",
    "String we = wireGuard.getError(), ae = amneziaWG.getError();",
    "Last WireGuard error:",
    "Last AmneziaWG error:",
    "AUTO/SMART/CUSTOM/ALL: testing/proving",
    "Disconnect the current VPN before adding/selecting router data",
    "VPN became active; router import was cancelled to preserve the running session identity",
    "Disconnect the current VPN before changing the active router",
):
    assert marker in main, f"MainActivity missing native truth/identity marker {marker}"

print("Android native DNS/MTU/recovery contract: PASS")
