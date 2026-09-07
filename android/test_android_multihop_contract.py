#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
store = (PKG / "AndroidNodeStore.java").read_text()
private_store = (PKG / "AndroidPrivateFileStore.java").read_text()
builder = (PKG / "AndroidMultihopController.java").read_text()
runtime = (PKG / "AndroidMultihopRuntime.java").read_text()
probe = (PKG / "AndroidPathProbe.java").read_text()
hop_meter = (PKG / "AndroidSpeedLabHopMeter.java").read_text()
main = (PKG / "MainActivity.java").read_text()

required_store = [
    "MAX_NODES = 24",
    "MAX_BUNDLE = 32 * 1024 * 1024",
    "router-nodes-v1",
    "stableNodeIdentity",
    'NODE_PROOF_DOMAIN = "router-vpn-node-proof-v1\\n"',
    "wireGuardPeerPublicKey",
    'top.matches("[0-9a-f]{64}")',
    'nested.matches("[0-9a-f]{64}")',
    "!top.equals(nested)",
    "!supplied.equals(derived)",
    "return stable.substring(0, 32)",
    'matches("[0-9a-f]{32}")',
    "AndroidPrivateFileStore.write",
    "AndroidPrivateFileStore.read",
    "ACTIVE_BUNDLE",
]
for token in required_store:
    assert token in store, f"node store lost contract: {token}"
for token in (
    "Os.chmod(temporary.getAbsolutePath(), 0600)",
    "out.getFD().sync()",
    "requireTargetUnchanged",
    "Os.rename(temporary.getAbsolutePath(), target.getAbsolutePath())",
):
    assert token in private_store, f"shared Android private store lost durable publication: {token}"
assert 'profile.optString("id"' not in store.split("deriveId", 1)[1].split("private static String wireGuardPeerPublicKey", 1)[0], "local node identity must not trust repeated server profile id"

required_builder = [
    '"shadowsocks".equals(exitMode)',
    '"hysteria2".equals(exitMode)',
    'entryBundle.getCanonicalFile().equals(exitBundle.getCanonicalFile())',
    "AndroidNodeStore.stableNodeIdentity(entry)",
    "AndroidNodeStore.stableNodeIdentity(exit)",
    "entryIdentity.equals(exitIdentity)",
    '"entry-wg"',
    'put("type", "wireguard")',
    'proxy.put("detour", "entry-wg")',
    'config.put("endpoints"',
    '"proxy".equals(finalTag)',
    'AndroidKillSwitchPolicy.strictRequested(entry) || AndroidKillSwitchPolicy.strictRequested(exit)',
    'peers > 1',
    'MAX_SESSION_DIRS = 32',
    'MAX_TOTAL = 32 * 1024 * 1024',
    'ENTRY_PROOF_PORT = 1098',
    'EXIT_PROOF_PORT = 1099',
    'put("tag", "entry-private")',
    'put("detour", "entry-wg")',
    'put("tag", "multihop-entry-proof")',
    'put("listen_port", ENTRY_PROOF_PORT)',
    'put("tag", "multihop-proof")',
    'put("listen_port", EXIT_PROOF_PORT)',
    'put("outbound", "entry-private")',
    'put("outbound", "proxy")',
]
for token in required_builder:
    assert token in builder, f"multihop builder lost contract: {token}"
for unsupported in ['"all".equals(exitMode)', '"max".equals(exitMode)', '"awg2-fast".equals(exitMode)', '"awg2-strong".equals(exitMode)']:
    assert unsupported not in builder, f"unsupported Android multihop branch became accepted: {unsupported}"
assert "persistent_keepalive_interval" not in builder, "pinned sing-box 1.13.12 WireGuardPeer has no persistent keepalive option"

required_runtime = [
    "AndroidPathProbe.prove(prepared.exitBundle",
    "if (!AndroidPathProbe.prove",
    "Exit-node private path proof failed; multihop was disconnected.",
    "boolean stopped = !started || stopEmbeddedAndProve();",
    '"FAILED".equals(state)',
    '"REVOKED".equals(state)',
    "START_TIMEOUT_MS",
    "PROBE_TIMEOUT_MS",
]
for token in required_runtime:
    assert token in runtime, f"multihop runtime lost fail-closed proof: {token}"
assert '"ERROR".equals(state)' not in runtime, "LayeredVpnService never publishes ERROR; runtime must use FAILED/REVOKED"

# Requesting STOP is not proof of teardown. Cancellation and start failure must
# both retain ownership when the embedded service does not reach a terminal state.
assert runtime.count("boolean stopped = !started || stopEmbeddedAndProve();") == 2
for token in (
    "transitioning = !stopped;",
    "if (stopped) {",
    "clearActiveGraphLocked();",
    "runtime ownership retained",
    "if (!stopped) throw new IllegalStateException",
):
    assert token in runtime, f"multihop teardown ownership lost contract: {token}"
stop = runtime.split("private boolean stopEmbeddedAndProve() {", 1)[1].split("private static boolean terminal", 1)[0]
for token in (
    "boolean interrupted = Thread.interrupted();",
    "singBox.stop();",
    "STOP_TIMEOUT_MS",
    "if (terminal(singBox.getState())) return true;",
    "return terminal(singBox.getState());",
    "if (interrupted) Thread.currentThread().interrupt();",
):
    assert token in stop, f"multihop teardown proof missing: {token}"
terminal = runtime.split("private static boolean terminal", 1)[1].split("private static boolean runtimeBusy", 1)[0]
assert "if (state == null) return false;" in terminal
assert 'return "DOWN".equals(normalized) || "FAILED".equals(normalized) || "REVOKED".equals(normalized);' in terminal

required_ui = [
    "PREPARE_MULTIHOP",
    "chooseMultihop()",
    "chooseMultihopExit(",
    "chooseMultihopExitMode(",
    "requestMultihop(",
    "startPendingMultihop()",
    "nodeStore.importBundle(bytes)",
    "nodes.size() < 2",
    "!node.id.equals(entry.id)",
    "Shadowsocks or Hysteria2",
    "AWG entry remains gated",
    "Multihop normally adds latency",
]
for token in required_ui:
    assert token in main, f"Android multihop UI lost integration marker: {token}"

# The exit proof must identify the actual selected exit node, not accept a
# generic private health response from whichever node happened to answer.
for token in [
    "AndroidNodeStore.stableNodeIdentity(bundle)",
    'expectedNode.matches("[0-9a-f]{64}")',
    'expectedNode.equals(body.optString("node_id"',
    'PROOF_KIND.equals(body.optString("proof"',
]:
    assert token in probe, f"Android multihop exit proof lost identity marker: {token}"

# Per-hop Speed Lab cannot address entry/exit by their overlapping private IP.
# It must use the exact local 1098/1099 lanes built above and validate the
# cryptographic Router VPN node identity before accepting RTT/Mbps.
for token in [
    "ENTRY_PROOF_PORT=1098",
    "EXIT_PROOF_PORT=1099",
    "Proxy.Type.HTTP",
    'new InetSocketAddress("127.0.0.1",proofPort)',
    "AndroidNodeStore.stableNodeIdentity(bundle)",
    'body.optString("node_id"',
    'body.optString("proof"',
    "Hop proof lane reached the wrong Router VPN node identity",
    "prove(privateNode,proofPort)",
    "/api/benchmark/download",
    "/api/benchmark/upload",
    "stale results were discarded",
]:
    assert token in hop_meter, f"Android exact per-hop Speed Lab proof lost marker: {token}"

print("android multihop source contract: OK")
