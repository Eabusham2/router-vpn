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
multihop = text("AndroidMultihopController.java")
multihop_runtime = text("AndroidMultihopRuntime.java")
main = text("MainActivity.java")
gradle = (ROOT / "app" / "build.gradle").read_text(encoding="utf-8")
combined_build = (ROOT / "build-sing-box-libbox.sh").read_text(encoding="utf-8")
bridge = (ROOT / "routervpn_xray_bridge.go").read_text(encoding="utf-8")
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
assert "updateDefaultInterface" in service
assert "resetNetwork()" in service
assert "registerDefaultNetworkCallback" in service

# Android must package exactly one gomobile Go runtime. The combined libbox AAR
# includes sing-box plus the exact libXray revision whose go.mod pins Xray-core
# v26.7.11; a standalone libxray.aar dependency would reintroduce duplicate
# go.Seq/JNI runtime classes.
for marker in (
    "1086ab2563320e0da0c23b3a491d8dfa0939dff4",
    "294fb37343205b9b0cb7b7b1b423d3d4b60d9998",
    "v1.260327.1-0.20260711155151-50231eaff98c",
    "GO_TOOLCHAIN=go1.26.3",
    'GOSUMDB="${GOSUMDB:-sum.golang.org}"',
    "go_retry()",
    "RouterXrayDialerController.class",
    "exactly one gomobile go.Seq runtime class",
    "github.com/xtls/libxray=$XRAY_VENDOR",
):
    assert marker in combined_build, f"Combined Android Go build missing marker: {marker}"
assert "GOSUMDB=off" not in combined_build, "Android Go build must not disable checksum verification"
assert "GONOSUMDB=*" not in combined_build, "Android Go build must not bypass checksum verification"
for marker in (
    "RouterXrayDialerController",
    "RouterXrayRegisterDialerController",
    "RouterXrayRegisterListenerController",
    "RouterXraySetDNS",
    "RouterXrayResetDNS",
    "RouterXrayInvoke",
    "net.DefaultResolver",
    "controller.ProtectFd(int64(fd))",
):
    assert marker in bridge, f"Combined Xray bridge missing marker: {marker}"
assert "libs/libbox.aar" in gradle
assert "libs/libxray.aar" not in gradle
assert "prepareXrayLibXray" not in gradle
# Verification must not stream jar/unzip/javap producers into grep -q while
# pipefail is enabled: an early successful grep can SIGPIPE the producer and
# turn a present class/API into a false missing-bridge failure.
for forbidden in (
    'jar tf "$classes" | grep',
    'unzip -l "$AAR" | grep',
    'javap -classpath "$classes" io.nekohasekai.libbox.Libbox | grep',
):
    assert forbidden not in combined_build, f"pipefail-sensitive AAR verifier pipeline returned: {forbidden}"
for marker in ('aar_list="$tmp/aar.list"', 'class_list="$tmp/classes.list"', 'api_list="$tmp/libbox.javap"'):
    assert marker in combined_build, f"AAR verifier no longer snapshots producer output: {marker}"
assert 'android:name=".XrayVpnService"' in manifest

# Xray VpnService must own the TUN, protect core and bootstrap-DNS sockets,
# inject only the app-owned fd, enforce strict lockdown, prove the selected
# node, and re-prove after an underlying-network transition.
for marker in (
    "new RouterXrayDialerController()",
    "protect((int) fd)",
    "routerXrayRegisterDialerController",
    "routerXrayRegisterListenerController",
    "routerXraySetDNS",
    "routerXrayResetDNS",
    "routerXrayBridgeRevision",
    'env.put("xray.tun.fd"',
    '"runXrayFromJson"',
    '"getXrayState"',
    "builder.establish()",
    "isAlwaysOn()",
    "isLockdownEnabled()",
    "AndroidPathProbe.prove(activeBundle",
    "AndroidUnderlyingNetworkMonitor",
    "restartAfterNetworkChange",
    'shutdown("FAILED"',
):
    assert marker in xray_service, f"XrayVpnService missing runtime marker: {marker}"
assert "import libXray." not in xray_service, "Xray service must not bind a second gomobile package"

# Native Xray must never silently reinterpret one sidecar of split/MAX as the
# full mode. Direct profiles get a real Android TUN and bounded private staging.
for marker in (
    "validatedProxyTag",
    '"routervpn-tun"',
    '"outboundTag"',
    "MAX_PROFILE_FILE",
    "MAX_PROFILE_TOTAL",
    "cleanupOldSessions",
    "AndroidKillSwitchPolicy.strictRequested(root)",
    "isLoopbackHost",
    "isCompositeProfile",
    'profile.has("stack.json")',
    'profile.has("chain.env")',
    "cannot be represented truthfully by native Xray alone",
):
    assert marker in xray, f"NativeXrayController missing safety/truth marker: {marker}"

# Raw backend strict-policy behavior is intentionally fail closed until its own
# lockdown state can be proven by Router VPN.
for name, source in (("WireGuard", wg), ("AmneziaWG", awg)):
    assert "AndroidKillSwitchPolicy.strictRequested(privateBundle)" in source, f"{name} no longer checks strict policy"
    assert "AndroidKillSwitchPolicy.requirementMessage()" in source, f"{name} no longer explains strict refusal"

# AUTO/SMART/CUSTOM/ALL may only claim success after selected-node private proof.
for marker in (
    "AndroidPathProbe.prove(bundle",
    "No candidate passed selected-node path proof",
    'if(!strict&&"wg".equals(id)',
    'else if(!strict&&"awg2-fast".equals(id)',
    "Kind { WG, AWG, LIBBOX, XRAY }",
    "xray.listDirectXrayModes",
    "startXray(bundle,c.id)",
    "SMART AUTO could not restore its last-known-good mode",
    "void all(File bundle,Callback cb)",
    "protectionRank",
    "vless-pq",
    "ALL failed closed because no Android-native branch passed selected-node path proof",
    "Composite desktop MAX chains remain separate and are never faked on Android",
):
    assert marker in orch, f"AndroidModeOrchestrator missing truth marker: {marker}"
assert "collect(bundle,false,false)" in orch, "ALL must inspect all actually native candidates, not just AUTO ordering"
assert "comparingInt(AndroidModeOrchestrator::protectionRank).reversed()" in orch, "ALL must try strongest native policy first"

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

# Real Android multihop is one graph: WG entry endpoint -> supported remote exit
# outbound -> Internet. Entry/exit must differ and exit proof is mandatory.
for marker in (
    'proxy.put("detour", "entry-wg")',
    '"type", "wireguard"',
    '"tag", "entry-wg"',
    "stableNodeIdentity(entry)",
    "stableNodeIdentity(exit)",
    "Entry and exit resolve to the same Router VPN node identity",
    '"shadowsocks".equals(exitMode)',
    '"hysteria2".equals(exitMode)',
    "Exit proxy already has a detour",
    "MAX_TOTAL",
):
    assert marker in multihop, f"AndroidMultihopController missing graph/safety marker: {marker}"
for marker in (
    "AndroidPathProbe.prove(prepared.exitBundle",
    "Exit-node private path proof failed",
    "WireGuard entry →",
    "if (started) singBox.stop()",
):
    assert marker in multihop_runtime, f"AndroidMultihopRuntime missing exit-proof/fail-closed marker: {marker}"

# Path proof is private-node proof, not a public-IP-only or generic {ok:true}
# success heuristic. Supplied and derived stable identities must agree.
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

# UI/onboarding must describe the actually implemented strict/multihop/Xray/ALL boundary.
for marker in (
    "Strict embedded libbox/Xray sessions require",
    "Always-on",
    "Block connections without VPN",
    "WireGuard entry plus a different stored node",
    "Shadowsocks or Hysteria2 exit",
    "AWG-entry multihop",
    "private NativeXrayController xray;",
    "private void chooseXrayMode()",
    "Native Xray:",
    "private Button allButton",
    "private boolean pendingAll",
    "private void requestAll()",
    "orchestrator.all(",
    "ALL — strongest proven Android-native branch",
):
    assert marker in main, f"MainActivity missing runtime-truth UX marker: {marker}"
assert "strict-kill-switch branches remain visibly gated" not in main

assert "SESSION_MARKER" in policy
assert '"always".equals(policy)' in policy
assert '"lockdown".equals(policy)' in policy
assert "libbox or native Xray mode" in policy

print("Android runtime truth contract: PASS")
