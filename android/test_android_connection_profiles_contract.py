#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent
JAVA = ROOT / "app" / "src" / "main" / "java" / "com" / "eabusham" / "routervpn"

def read(name: str) -> str:
    value = (JAVA / name).read_text(encoding="utf-8")
    assert value.strip(), f"{name} is empty"
    return value

store = read("AndroidConnectionProfileStore.java")
dialog = read("AndroidConnectionProfilesDialog.java")
settings = read("AndroidProfileSettingsDialog.java")
node_store = read("AndroidNodeStore.java")

for marker in (
    'SCHEMA_VERSION=4',
    'FILE_NAME="connection-profiles-v4.json"',
    'LEGACY_FILE_NAME="connection-profiles-v1.json"',
    'schema < 1 || schema > SCHEMA_VERSION',
    'legacyPath || schema < SCHEMA_VERSION',
    'MAX_PROFILES=64', 'MAX_STORE=512*1024',
    'AndroidPrivateFileStore.read(source, MAX_STORE)',
    'AndroidPrivateFileStore.write(file, raw, MAX_STORE)',
    'AndroidPrivateFileStore.remove(legacyFile, MAX_STORE)',
    '"multihop_enabled"', '"multihop_entry_id"', '"multihop_exit_id"', '"multihop_exit_mode"',
    'normalizeMultiMode', '"shadowsocks"', '"hysteria2"',
    'AndroidNodeStore.deriveId(bundle,updatedBundle)',
    'legacy Router node has no stable proof-bound identity',
    'All validation above is complete before any selection, node-file, preset or preference mutation.',
    'nodes.importBundle(updatedBundle)', 'putString(MULTI_MODE,multiMode)',
    'Could not persist the loaded connection profile; prior Router node state was restored.',
    'nodes.importBundle(originalBundle)',
    'requireIdle("saving a connection profile")', 'requireIdle("loading a connection profile")',
    'requireIdle("updating a connection profile")', 'requireIdle("deleting a connection profile")',
):
    assert marker in store, f"Android connection-profile store missing {marker!r}"

# All connection-profile durable writes/removals must stay on the shared private
# publication primitive; old direct filesystem paths cannot become authoritative.
for forbidden in ('Os.rename(', 'FileOutputStream', 'requirePrivateRegularFile', '.delete()'):
    assert forbidden not in store, f"Android connection-profile store retains private-write bypass: {forbidden}"

# The exact saved graph, transport and custom data must be validated before the
# first node mutation in load().
load = store.split('synchronized Record load(String id)', 1)[1].split('synchronized void delete', 1)[0]
for validation in ('normalizeMultiMode', 'findNode(entry)', 'findNode(exit)', 'prepareCustomPresetJSON', 'AndroidNodeStore.deriveId'):
    assert validation in load, f"Android profile load lost preflight validation {validation!r}"
first_mutation = load.find('nodes.importBundle(updatedBundle)')
assert first_mutation > 0
for validation in ('normalizeMultiMode', 'findNode(entry)', 'findNode(exit)', 'prepareCustomPresetJSON', 'AndroidNodeStore.deriveId'):
    assert load.find(validation) < first_mutation, f"{validation} moved after node mutation"
assert 'nodes.select(nodeId)' not in load, "Android connection-profile load must not select before validation/apply"

# Only explicitly whitelisted policy fields may be copied; node/dataplane secrets
# stay in the private linked node stores.
policy_block = store.split('private static final String[] POLICY_KEYS={', 1)[1].split('};', 1)[0]
for forbidden in ('api_token', 'private_key', 'socks_password', 'socks_username', 'preshared', 'password', 'wireguard'):
    assert forbidden not in policy_block.lower(), f"secret-like field entered Android profile policy whitelist: {forbidden}"
for marker in ('allowedPolicyKey', 'Connection profile contains non-whitelisted node data'):
    assert marker in store

for marker in (
    'Native Android Add / Load / Update / Delete UI',
    'Button add=button("Add")', 'load=button("Load")', 'update=button("Update")', 'delete=button("Delete")',
    'Load restores choices only; Connect still has to establish and prove the real VPN path.',
    'Linked node keys, API tokens and external credentials are never copied',
):
    assert marker in dialog, f"Android connection-profile dialog missing {marker!r}"

for marker in (
    'Connection profiles — Add / Load / Update / Delete',
    'AndroidConnectionProfilesDialog.show',
    'AndroidNodeStore.deriveId(bundle,updated)',
    'legacy Router node has no stable proof-bound identity',
    'store.importBundle(updated)',
):
    assert marker in settings, f"Android Settings/profile integration missing {marker!r}"

# Node mutation remains session-gated below every UI caller.
for marker in ('requireMutable("importing or replacing a Router VPN node")', 'requireSelectable(id)', 'live node identity and proof must remain immutable'):
    assert marker in node_store, f"Android node-store mutation gate missing {marker!r}"

print("Android connection profile safety contract: PASS")
