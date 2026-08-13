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
policy = text("AndroidKillSwitchPolicy.java")
wg = text("NativeWireGuardController.java")
awg = text("NativeAmneziaWGController.java")
sing = text("NativeSingBoxController.java")
orch = text("AndroidModeOrchestrator.java")
probe = text("AndroidPathProbe.java")
main = text("MainActivity.java")

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
# success heuristic. The bundle's stable public node fingerprint must match the
# private router-agent response exactly.
for marker in (
    "isPrivate(address)",
    'bundle.optString("nodeProofId"',
    'profile.optString("node_proof_id"',
    'expectedNode.matches("[0-9a-f]{64}")',
    'expectedNode.equals(body.optString("node_id"',
    'PROOF_KIND.equals(body.optString("proof"',
    "HTTP/1.1 200",
):
    assert marker in probe, f"AndroidPathProbe missing selected-node identity marker: {marker}"
assert 'return body.optBoolean("ok", false);' not in probe, "generic ok-only proof must not return success"

# UI/onboarding must describe the actually implemented strict/multihop boundary.
assert "Strict embedded libbox sessions require" in main
assert "Always-on" in main and "Block connections without VPN" in main
assert "WireGuard entry plus a different stored node" in main
assert "Shadowsocks or Hysteria2 exit" in main
assert "AWG-entry multihop" in main
assert "strict-kill-switch branches remain visibly gated" not in main

# The policy marker must be staged only when the selected router requests it.
assert "SESSION_MARKER" in policy
assert '"always".equals(policy)' in policy
assert '"lockdown".equals(policy)' in policy

print("Android runtime truth contract: PASS")
