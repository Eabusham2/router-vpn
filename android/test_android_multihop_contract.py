#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
store = (PKG / "AndroidNodeStore.java").read_text()
builder = (PKG / "AndroidMultihopController.java").read_text()
runtime = (PKG / "AndroidMultihopRuntime.java").read_text()
probe = (PKG / "AndroidPathProbe.java").read_text()
main = (PKG / "MainActivity.java").read_text()

required_store = [
    "MAX_NODES = 24",
    "MAX_BUNDLE = 32 * 1024 * 1024",
    "router-nodes-v1",
    "deriveId",
    "wireGuardPeerPublicKey",
    'matches("[0-9a-f]{32}")',
    "atomicWrite",
    "getFD().sync()",
    "ACTIVE_BUNDLE",
]
for token in required_store:
    assert token in store, f"node store lost contract: {token}"
assert 'profile.optString("id"' not in store.split("deriveId", 1)[1].split("private static String wireGuardPeerPublicKey", 1)[0], "local node identity must not trust repeated server profile id"

required_builder = [
    '"shadowsocks".equals(exitMode)',
    '"hysteria2".equals(exitMode)',
    'entryBundle.getCanonicalFile().equals(exitBundle.getCanonicalFile())',
    '"entry-wg"',
    'put("type", "wireguard")',
    'proxy.put("detour", "entry-wg")',
    'config.put("endpoints"',
    '"proxy".equals(finalTag)',
    'AndroidKillSwitchPolicy.strictRequested(entry) || AndroidKillSwitchPolicy.strictRequested(exit)',
    'peers > 1',
    'MAX_SESSION_DIRS = 32',
    'MAX_TOTAL = 32 * 1024 * 1024',
]
for token in required_builder:
    assert token in builder, f"multihop builder lost contract: {token}"
for unsupported in ['"all".equals(exitMode)', '"max".equals(exitMode)', '"awg2-fast".equals(exitMode)', '"awg2-strong".equals(exitMode)']:
    assert unsupported not in builder, f"unsupported Android multihop branch became accepted: {unsupported}"

required_runtime = [
    "AndroidPathProbe.prove(prepared.exitBundle",
    "if (!AndroidPathProbe.prove",
    "Exit-node private path proof failed; multihop was disconnected.",
    "if (started) singBox.stop()",
    '"FAILED".equals(state)',
    '"REVOKED".equals(state)',
    "START_TIMEOUT_MS",
    "PROBE_TIMEOUT_MS",
]
for token in required_runtime:
    assert token in runtime, f"multihop runtime lost fail-closed proof: {token}"
assert '"ERROR".equals(state)' not in runtime, "LayeredVpnService never publishes ERROR; runtime must use FAILED/REVOKED"

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
    'bundle.optString("nodeProofId"',
    'expectedNode.matches("[0-9a-f]{64}")',
    'expectedNode.equals(body.optString("node_id"',
    'PROOF_KIND.equals(body.optString("proof"',
]:
    assert token in probe, f"Android multihop exit proof lost identity marker: {token}"

print("android multihop source contract: OK")
