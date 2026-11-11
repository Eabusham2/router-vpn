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
    'SCHEMA_VERSION=7',
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
    'nodes.applyProfileBundle(update.id,update.original,updatedBundle)', 'nextPreferences.put(MULTI_MODE,multiMode)',
    'prior connection state was restored.', 'rollback is incomplete',
    'nodes.snapshotSelection()', 'nodes.restoreSelection(originalSelection)',
    'snapshotPreferences()', 'rollbackPreferences(preferenceUpdate)', 'publishPreferences(preferenceUpdate)', 'if(!ownsPreferences(preferenceUpdate))',
    '"external_policy"', '"entry_policy"', '"exit_policy"',
    'requireExternalIdentity', 'selectExternalPath', 'currentExternalPath',
    'AndroidConnectionProfilePolicy.external', 'exits.saveIfUnchanged(updatedExternal', 'restoreExternal(originalExternal,updatedExternal)',
    '"multihop_entry_kind"', '"ordinary_entry_protocol"', '"ordinary_entry_public_ip"',
    '"ordinary_entry_policy"', '"ordinary_entry_startup"', 'requireOrdinaryIdentity', 'selectOrdinaryTorPath',
    'return entry==null&&ordinaryEntry==null', 'AndroidTorProfile.compileOrdinary(ordinaryEntry,exit,"selection-validation",execution)',
    'exits.saveIfUnchanged(updatedOrdinary', 'restoreExternal(originalOrdinary,updatedOrdinary)',
    'currentImportedRouterPath', 'selectImportedRouterPath',
    'AndroidImportedRouterPath.compile(updatedOrdinary,finalBundle,multiMode,execution)',
    'routerFinal?schema<6', 'The imported path lost its independent paired final policy.',
    'if(!ours.equals(current))', 'exits.saveIfUnchanged(original,ours)',
    'nodes.restoreProfileBundle(update.id,update.original,update.updated)',
    'nodes.restoreProfileSelection(originalSelection,attemptedSelections)',
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
for validation in ('normalizeMultiMode', 'findNode(entry)', 'findNode(exit)', 'prepareCustomPresetJSON', 'stageNode', 'validateExternalGraph'):
    assert validation in load, f"Android profile load lost preflight validation {validation!r}"
first_mutation = load.find('nodes.applyProfileBundle(update.id,update.original,updatedBundle)')
assert first_mutation > 0
for validation in ('normalizeMultiMode', 'findNode(entry)', 'findNode(exit)', 'prepareCustomPresetJSON', 'stageNode', 'validateExternalGraph'):
    assert load.find(validation) < first_mutation, f"{validation} moved after node mutation"
assert load.index('nodes.select(nodeId)') > first_mutation, "Final Router selection must follow all staged policy validation and apply"
stage = store.split('private void stageNode(', 1)[1].split('private static void requireEntryMode', 1)[0]
assert 'AndroidNodeStore.deriveId(bundle,updatedBundle)' in stage and 'nodes.importBundle' not in stage
assert 'conflicting policies to the same Router node' in stage
assert 'profile.remove(key)' in stage, "Loading saved choices must also restore defaults that were absent when captured"

product = read('ProductActivity.java')
activity = read('StandardExitActivity.java')
assert 'connection.connectExternal(path,callback())' in product
assert 'if(openSelectedExternal(true))return;' in product
assert 'rememberExternalPath(entry,exit,entryMode)' in activity
assert 'selectExternalPath(exit,entry,mode,pendingExecution)' in activity
assert 'if(selectionOnly()){clearPending();' in activity
assert 'connection.connectImportedMultihop(path.entry,path.exit,path.exitMode,path.execution,callback())' in product

# The imported entry owns only its external credential reference. Its paired
# final retains independent Router policy, and the original schema-five Tor
# direction remains readable without being reinterpreted as a private entry.
rows = store.split('private JSONArray readRows()', 1)[1]
for marker in ('schema<5', 'AndroidTorProfile.isTor', 'entry_policy', 'entry_profile_id', 'exit_policy', 'exit_profile_id'):
    assert marker in rows, f"Imported Router migration lost existing typed policy guard {marker!r}"
select_imported = store.split('synchronized void selectImportedRouterPath(', 1)[1].split('static final class ExternalSelection', 1)[0]
assert select_imported.index('AndroidImportedRouterPath.compile(') < select_imported.index('nodes.select(last.id)')
assert 'PreferenceUpdate(previous,next)' in select_imported
assert 'synchronized(prefs())' in select_imported and 'if(ownsPreferences(preferenceUpdate))' in select_imported
assert 'nodes.restoreProfileSelection(selected,java.util.Collections.singletonList(new AndroidNodeStore.SelectionSnapshot(last.id,originalFinal)))' in select_imported
assert 'rollbackPreferences(preferenceUpdate)' in select_imported

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

# Imported paths must use the compiler's exact directional pair predicate at
# all durable boundaries; nested packet readiness still requires the actual captured compiler.
assert store.count('AndroidImportedRouterPath.supports(') == 3, "imported pair validation missing from load/snapshot/readRows"
product = read("ProductActivity.java")
assert "Imported Shadowsocks 2022, Hysteria2, WireGuard, AmneziaWG and OpenVPN entries can use a complete paired final transport. Packet finals require the captured entry capacity to fit their data and handshake envelope; Auto may reduce the final endpoint MTU, while Fixed overflow is refused. These configured bounds are not a measured path MTU." in product
chooser = product.split('private void chooseImportedRouterTransport(', 1)[1].split('private ', 1)[0]
assert '"shadowsocks","hysteria2","wg","awg2-fast","awg2-strong"' in chooser
assert 'AndroidImportedRouterPath.compile(' in chooser
assert 'no complete supported final transport for the selected entry and layers' in chooser
harness = (ROOT / "test_android_connection_profiles.py").read_text(encoding="utf-8")
for family in ('imported-router', 'imported-wireguard-router', 'imported-amneziawg-router', 'imported-final-wg', 'imported-final-awg2-fast', 'imported-final-awg2-strong', 'imported-nested-wg', 'imported-nested-awg2-fast', 'imported-nested-awg2-strong'):
    assert harness.count('"' + family + '"') >= 2, f"mandatory profile family missing: {family}"

for marker in ('"multihop_nodes"', 'stageOrderedNodes(updates,row)', 'currentOrderedPath()',
               'validateOrderedRow(row,schema)', 'nodes.captureChain(', 'orderedReferences(members)',
               'saved ordered control differs from its exact final member policy'):
    assert marker in store, f"Android ordered profile capture missing: {marker}"
assert 'args.case_family in ("all", "ordered-chain")' in harness and 'chain.run(ROOT, work, app, classes, jar, env)' in harness
workflow = (ROOT.parent / '.github/workflows/android-multihop-contract.yml').read_text()
for dependency in ('android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainCapture.java',
                   'android/test_android_node_chain_capture.py'):
    assert workflow.count("- '" + dependency + "'") == 2, f"ordered source push/PR trigger missing: {dependency}"
assert workflow.count('          python3 android/test_android_node_chain_capture.py') == 1, "actual ordered compiler/capture gate is required"

# The original final aggregate now runs as complete bounded JVM groups. The
# selected Java inventory and the post-execution receipt must both be checked.
for family in ('store-tor', 'store-external', 'store-openvpn', 'store-router'):
    assert 'case "' + family + '" -> java.util.List.of(' in harness
for marker in ('validate_general_inventory(inventory)', 'for fault in ("omitted", "duplicated"):',
               'for family, selected in GENERAL_FAMILIES.items():', 'general_command + [family]',
               'json.loads(receipts[0]) != list(selected)',
               'independent store instances both adopted the same obsolete editor source'):
    assert marker in harness, f"original bounded profile inventory/control missing: {marker}"

print("Android connection profile safety contract: PASS")
