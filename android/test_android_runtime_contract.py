#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent
JAVA = ROOT / "app" / "src" / "main" / "java" / "com" / "eabusham" / "routervpn"


def text(name: str) -> str:
    value = (JAVA / name).read_text(encoding="utf-8")
    if not value.strip():
        raise AssertionError(f"{name} is empty")
    return value


service = text("LayeredVpnService.java")
xray_service = text("XrayVpnService.java")
policy = text("AndroidKillSwitchPolicy.java")
wg = text("NativeWireGuardController.java")
awg = text("NativeAmneziaWGController.java")
sing = text("NativeSingBoxController.java")
xray = text("NativeXrayController.java")
orch = text("AndroidModeOrchestrator.java")
probe = text("AndroidPathProbe.java")
store = text("AndroidNodeStore.java")
main = text("MainActivity.java")
gradle = (ROOT / "app" / "build.gradle").read_text(encoding="utf-8")
xray_build = (ROOT / "build-xray-libxray.sh").read_text(encoding="utf-8")
manifest = (ROOT / "app" / "src" / "main" / "AndroidManifest.xml").read_text(encoding="utf-8")

# Strict Android policy must be enforced by the actual VpnService, not UI text.
for marker in (
    "AndroidKillSwitchPolicy.SESSION_MARKER",
    "isAlwaysOn()",
    "isLockdownEnabled()",
    "VpnService.prepare(this)",
    'shutdown("REVOKED"',
    'publish("FAILED"',
):
    assert marker in service, f"LayeredVpnService missing strict/lifecycle marker: {marker}"

# Network transitions must reach libbox rather than only repainting UI state.
assert "updateDefaultInterface" in service
assert "resetNetwork()" in service
assert "registerDefaultNetworkCallback" in service

# Native Xray is pinned to the wrapper commit that itself pins Xray-core v26.7.11.
for marker in (
    "294fb37343205b9b0cb7b7b1b423d3d4b60d9998",
    "50231eaff98c",
    "MOBILE_VERSION=v0.0.0-20260709172247-6129f5bee9d5",
    "libgojni.so",
):
    assert marker in xray_build, f"Pinned Xray build missing marker: {marker}"
assert "prepareXrayLibXray" in gradle and "libs/libxray.aar" in gradle
assert 'android:name=".XrayVpnService"' in manifest

# Xray VpnService must own the TUN, protect core sockets, inject only the
# app-owned fd, enforce strict lockdown, prove the selected node, and re-prove
# after an underlying-network transition.
for marker in (
    "implements" if False else "new DialerController()",
    "protect((int) fd)",
    "registerDialerController",
    "registerListenerController",
    'env.put("xray.tun.fd"',
    '"runXrayFromJson"',
    '"getXrayState"',
    "builder.establish()",
    "isAlwaysOn()",
    "isLockdownEnabled()",
    "AndroidPathProbe.prove(activeBundle",
    "NET_CAPABILITY_NOT_VPN",
    "restartAfterNetworkChange",
    'publish("FAILED"',
):
    assert marker in xray_service, f"XrayVpnService missing runtime marker: {marker}"

# Controller accepts only a real generated remote proxy, replaces local-only
# ingress with the Android TUN, explicitly routes that TUN to proxy, and stages
# bounded app-private data.
for marker in (
    "validatedProxyTag",
    '"routervpn-tun"',
    '"outboundTag"',
    "MAX_PROFILE_FILE",
    "MAX_PROFILE_TOTAL",
    "cleanupOldSessions",
    "AndroidKillSwitchPolicy.strictRequested(root)",
    "isLoopbackHost",
):
    assert marker in xray, f"NativeXrayController missing safety marker: {marker}"

# Raw backend strict-policy behavior is intentionally fail closed until its own
# lockdown state can be proven by Router VPN.
for name, source in (("WireGuard", wg), ("AmneziaWG", awg)):
    assert "AndroidKillSwitchPolicy.strictRequested(privateBundle)" in source, f"{name} no longer checks strict policy"
    assert "AndroidKillSwitchPolicy.requirementMessage()" in source, f"{name} no longer explains strict refusal"

# AUTO/SMART/CUSTOM may only claim success after a selected-node private proof.
assert "AndroidPathProbe.prove(bundle" in orch
assert "No candidate passed selected-node path proof" in orch
assert 'if(!strict&&"wg".equals(id)' in orch
assert 'else if(!strict&&"awg2-fast".equals(id)' in orch
assert "Kind { WG, AWG, LIBBOX, XRAY }" in orch
assert "xray.listDirectXrayModes" in orch
assert "startXray(bundle,c.id)" in orch
assert "SMART AUTO could not restore its last-known-good mode" in orch

# Embedded libbox candidates must be full-device and self-contained, and staged
# private state must remain bounded.
for marker in (
    "isDirectFullDeviceConfig",
    '"127.0.0.1".equals(server)',
    "MAX_PROFILE_FILE",
    "MAX_PROFILE_TOTAL",
    "cleanupOldSessions",
):
    assert marker in sing, f"NativeSingBoxController missing safety marker: {marker}"

# Path proof is private-node proof, not a public-IP-only or generic {ok:true}
# success heuristic. New bundles carry the stable public node fingerprint and
# legacy bundles derive the exact same value from their WireGuard server public
# key; supplied and derived identities must agree.
for marker in (
    "isPrivate(address)",
    "AndroidNodeStore.stableNodeIdentity(bundle)",
    'expectedNode.matches("[0-9a-f]{64}")',
    'expectedNode.equals(body.optString("node_id"',
    'PROOF_KIND.equals(body.optString("proof"',
    "HTTP/1.1 200",
):
    assert marker in probe, f"AndroidPathProbe missing selected-node identity marker: {marker}"
for marker in (
    'NODE_PROOF_DOMAIN = "router-vpn-node-proof-v1\\n"',
    'bundle.optString("nodeProofId"',
    'profile.optString("node_proof_id"',
    "wireGuardPeerPublicKey(bundle)",
    "!supplied.equals(derived)",
):
    assert marker in store, f"AndroidNodeStore missing stable identity marker: {marker}"
assert 'return body.optBoolean("ok", false);' not in probe, "generic ok-only proof must not return success"

# UI/onboarding must describe the actually implemented strict/multihop/Xray boundary.
assert "Strict embedded libbox/Xray sessions require" in main
assert "Always-on" in main and "Block connections without VPN" in main
assert "WireGuard entry plus a different stored node" in main
assert "Shadowsocks or Hysteria2 exit" in main
assert "AWG-entry multihop" in main
assert "private NativeXrayController xray;" in main
assert "private void chooseXrayMode()" in main
assert "Native Xray:" in main
assert "strict-kill-switch branches remain visibly gated" not in main

# The policy marker must be staged only when the selected router requests it.
assert "SESSION_MARKER" in policy
assert '"always".equals(policy)' in policy
assert '"lockdown".equals(policy)' in policy
assert "libbox or native Xray mode" in policy

print("Android runtime truth contract: PASS")
