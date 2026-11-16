#!/usr/bin/env python3
from pathlib import Path
import ast
import contextlib
import io
import os
import re
import subprocess
import tempfile
from unittest.mock import patch
import test_android_node_chain_capture as ORDERED

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
# The complete ordered family still runs every paired and imported case. The
# imported-only selector is a separate focused entry point, never a substitute
# for the all/ordered-chain compiler, source composition or original controls.
ORDERED_DISPATCH_MARKERS = (
    'args.case_family in ("all", "ordered-chain", "ordered-imported", "ordered-openvpn", "fixture-transport")',
    'if args.case_family == "ordered-execution":\n        import test_android_node_chain_execution_capture as chain',
    'if args.case_family == "ordered-connect-execution":\n        import test_android_connect_execution_capture as chain',
    'if args.case_family == "ordered-socks-execution":\n        import test_android_socks_execution_capture as chain',
    'if args.case_family == "ordered-imported-execution":\n        import test_android_imported_prefix_execution_capture as chain',
    'if args.case_family == "ordered-openvpn-execution":\n        import test_android_openvpn_execution_capture as chain',
    'chain.compiler_source(GO) if chain else GO',
    'chain.prepare_sources(src, app, JAVA)',
    'chain.run(ROOT, work, app, classes, jar, env, imported_only=args.case_family == "ordered-imported")',
    'if args.case_family == "ordered-openvpn":\n                chain.run(ROOT, work, app, classes, jar, env, openvpn_only=True)',
    'if args.case_family in ("ordered-chain", "ordered-imported", "ordered-openvpn", "ordered-execution", "ordered-connect-execution", "ordered-socks-execution", "ordered-openvpn-execution", "ordered-imported-execution"):',
)


def validate_ordered_dispatch(source: str) -> None:
    for marker in ORDERED_DISPATCH_MARKERS:
        assert source.count(marker) == 1, f"complete ordered profile compiler/case dispatch missing or duplicated: {marker}"


validate_ordered_dispatch(harness)
# Exercise the actual source contract: the new family must reach its own
# compiler, and extending the return inventory must preserve every old family.
connect_dispatch = ORDERED_DISPATCH_MARKERS[2]
socks_dispatch = ORDERED_DISPATCH_MARKERS[3]
prefix_dispatch = ORDERED_DISPATCH_MARKERS[4]
openvpn_dispatch = ORDERED_DISPATCH_MARKERS[5]
return_dispatch = ORDERED_DISPATCH_MARKERS[-1]
dispatch_controls = (
    ("OpenVPN compiler omitted", openvpn_dispatch, ""),
    ("OpenVPN compiler substituted", openvpn_dispatch,
     openvpn_dispatch.replace("test_android_openvpn_execution_capture", "test_android_node_chain_execution_capture")),
    ("OpenVPN return omitted", return_dispatch,
     return_dispatch.replace(', "ordered-openvpn-execution"', "")),
    ("OpenVPN compiler duplicated", openvpn_dispatch, openvpn_dispatch + "\n" + openvpn_dispatch),
    ("imported-prefix compiler omitted", prefix_dispatch, ""),
    ("imported-prefix compiler substituted", prefix_dispatch,
     prefix_dispatch.replace("test_android_imported_prefix_execution_capture", "test_android_node_chain_execution_capture")),
    ("imported-prefix return omitted", return_dispatch,
     return_dispatch.replace(', "ordered-imported-execution"', "")),
    ("imported-prefix compiler duplicated", prefix_dispatch, prefix_dispatch + "\n" + prefix_dispatch),
    ("SOCKS compiler omitted", socks_dispatch, ""),
    ("SOCKS compiler substituted", socks_dispatch,
     socks_dispatch.replace("test_android_socks_execution_capture", "test_android_node_chain_execution_capture")),
    ("SOCKS return omitted", return_dispatch,
     return_dispatch.replace(', "ordered-socks-execution"', "")),
    ("SOCKS compiler duplicated", socks_dispatch, socks_dispatch + "\n" + socks_dispatch),
    ("CONNECT compiler omitted", connect_dispatch, ""),
    ("CONNECT compiler substituted", connect_dispatch,
     connect_dispatch.replace("test_android_connect_execution_capture", "test_android_node_chain_execution_capture")),
    ("CONNECT return omitted", return_dispatch,
     return_dispatch.replace(', "ordered-connect-execution"', "")),
    ("original execution compiler omitted", ORDERED_DISPATCH_MARKERS[1], ""),
    ("original complete family omitted", return_dispatch,
     return_dispatch.replace('"ordered-chain", ', "")),
    ("CONNECT compiler duplicated", connect_dispatch, connect_dispatch + "\n" + connect_dispatch),
)
for name, before, after in dispatch_controls:
    try:
        validate_ordered_dispatch(harness.replace(before, after, 1))
    except AssertionError as error:
        assert before in str(error), f"dispatch control failed for an unrelated reason: {name}: {error}"
    else:
        raise AssertionError(f"ordered profile dispatch contract accepted its deliberate defect: {name}")
workflow = (ROOT.parent / '.github/workflows/android-multihop-contract.yml').read_text()
for dependency in ('android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainCapture.java',
                   'android/test_android_node_chain_capture.py'):
    assert workflow.count("- '" + dependency + "'") == 2, f"ordered source push/PR trigger missing: {dependency}"
assert workflow.count('          python3 android/test_android_node_chain_capture.py') == 1, "actual ordered compiler/capture gate is required"

# Every original call from the complete Java aggregate belongs to one mandatory
# bounded phase. Both the source dispatch and executed receipt remain required.
SOURCE_PHASES = ("paired-roundtrips", "paired-capture", "ordered-editor", "editor-budget",
                 "editor-product", "identity-modes", "imported", "socks")
PHASE_CALLS = (
    ("roundtrip",),
    ("sourceControls", "generationControls", "validationControls", "compilationRace", "captureAtomicity"),
    ("editorChecks", "editorGeneration", "editorFailures", "orderedPermission", "editorNative", "editorAtomicity"),
    ("editorFinalBudget",), ("editorHandlers", "productHandoff"),
    ("pairedIdentity", "nativeIdentityReceipt", "identityCompilerAdmission", "editorMixed", "editorMixedHandlers"),
    ("importedMiddle",), ("socksMiddle",),
)
ROUNDTRIPS = ("2/", "3/", "4/", "8/", "3/aes-256-gcm", "4/aes-256-gcm+xor-whitening",
              "4/fixed-middle", "2/awg-fast", "3/awg-strong", "4/mixed-awg", "8/mixed-awg")


def validate_source_phases(source, java):
    tree = ast.parse(source)
    values = [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == "SOURCE_PHASES" for t in n.targets)]
    assert values == [SOURCE_PHASES], "complete ordered Python phase inventory changed"
    declaration = re.findall(r'completeSourcePhases\(\)\{return List.of\(([^\n]+)\);\}', java)
    assert len(declaration) == 1 and tuple(re.findall(r'"([^"\n]+)"', declaration[0])) == SOURCE_PHASES, "complete ordered Java phase inventory changed"
    body = java.split('static void runSourcePhase(Path root,String phase)throws Exception{', 1)[1].split('\n public static void main(', 1)[0]
    cases = re.findall(r'case "([^"\n]+)" -> \{([^\n]+)\}', body)
    assert tuple(name for name, _ in cases) == SOURCE_PHASES, "complete ordered Java dispatch changed"
    for (name, calls), expected in zip(cases, PHASE_CALLS):
        assert tuple(re.findall(r'([A-Za-z][A-Za-z0-9]*)\(root(?:,key)?\);', calls)) == expected, "complete ordered original calls changed: " + name
    assert tuple(re.findall(r'"([^"\n]+)"', cases[0][1])) == ROUNDTRIPS, "complete ordered roundtrip inventory changed"
    for marker in ('phases = ("imported",) if imported_only else SOURCE_PHASES',
                   'phase_checks = [run_source_phase(command, phase, env) for phase in phases]',
                   'capture_output=True, text=True, timeout=180)',
                   'if receipt is None:', 're.fullmatch(', 'check=True,'):
        assert source.count(marker) >= 1, "complete ordered execution/receipt boundary omitted: " + marker
    for marker in ('for(String phase:completeSourcePhases())runSourcePhase(root,phase);',
                   'if(completeSourcePhases().contains(family)){runSourcePhase(root,family);',
                   'default -> throw new IllegalArgumentException("unknown complete source phase");'):
        assert java.count(marker) == 1, "complete ordered Java execution boundary omitted"


ordered_source = (ROOT / 'test_android_node_chain_capture.py').read_text()
validate_source_phases(ordered_source, ORDERED.HARNESS)
phase_assignment = next(n for n in ast.parse(ordered_source).body if isinstance(n, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == "SOURCE_PHASES" for t in n.targets))
source_lines = ordered_source.splitlines(keepends=True)
for index, name in enumerate(SOURCE_PHASES):
    for changed_phases in (SOURCE_PHASES[:index]+SOURCE_PHASES[index+1:],
                           SOURCE_PHASES[:index]+(name,)+SOURCE_PHASES[index:]):
        changed = (''.join(source_lines[:phase_assignment.lineno-1]) +
                   'SOURCE_PHASES = '+repr(changed_phases)+'\n' +
                   ''.join(source_lines[phase_assignment.end_lineno:]))
        try:
            validate_source_phases(changed, ORDERED.HARNESS)
        except (AssertionError, SyntaxError, ValueError):
            pass
        else:
            raise AssertionError('complete ordered source accepted missing/duplicate phase: '+name)
for group in PHASE_CALLS:
    for name in group:
        before = name+'(root'+(',key' if name == 'roundtrip' else '')+');'
        start = ORDERED.HARNESS.index('static void runSourcePhase(')
        changed = ORDERED.HARNESS[:start] + ORDERED.HARNESS[start:].replace(before, '', 1)
        try:
            validate_source_phases(ordered_source, changed)
        except AssertionError:
            pass
        else:
            raise AssertionError('complete ordered source accepted missing original call: '+name)

for phase in SOURCE_PHASES:
    valid = 'Android ordered source phase '+phase+': 17 checks PASS\n'
    if phase == 'socks':
        valid = 'Android ordered SOCKS source: 17 checks; actual shared compiler and saved profile ownership passed\n' + valid
    with patch.object(ORDERED.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, valid, '')) as called, contextlib.redirect_stdout(io.StringIO()):
        assert ORDERED.run_source_phase(['java', 'original-fixture'], phase, {}) == 17
        assert called.call_args.args[0] == ['java', 'original-fixture', phase]
        assert called.call_args.kwargs['check'] is True and called.call_args.kwargs['timeout'] == 180
    invalid = ['', valid+valid, valid.replace(phase, 'foreign'), valid.replace('17', '0')]
    if phase == 'socks':
        invalid += [valid.split('\n', 1)[1], valid.replace('17 checks;', '18 checks;')]
    for output in invalid:
        with patch.object(ORDERED.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output, '')):
            try:
                ORDERED.run_source_phase(['java'], phase, {})
            except AssertionError:
                pass
            else:
                raise AssertionError('complete ordered source accepted missing/duplicate/foreign/zero receipt')
    for error in (subprocess.CalledProcessError(1, ['java'], output=valid), subprocess.TimeoutExpired(['java'], 180)):
        with patch.object(ORDERED.subprocess, 'run', side_effect=error):
            try:
                ORDERED.run_source_phase(['java'], phase, {})
            except (AssertionError, subprocess.TimeoutExpired):
                pass
            else:
                raise AssertionError('complete ordered source accepted failed or timed-out phase')

# The original final aggregate now runs as complete bounded JVM groups. The
# selected Java inventory and the post-execution receipt must both be checked.
for family in ('store-tor', 'store-external', 'store-openvpn', 'store-router'):
    assert 'case "' + family + '" -> java.util.List.of(' in harness
for marker in ('validate_general_inventory(inventory)', 'for fault in ("omitted", "duplicated"):',
               'for family, selected in GENERAL_FAMILIES.items():', 'general_command + [family]',
               'json.loads(receipts[0]) != list(selected)',
               'independent store instances both adopted the same obsolete editor source'):
    assert marker in harness, f"original bounded profile inventory/control missing: {marker}"


# Exercise the shipping ABI guard with an explicit javap-text boundary. Actual
# gomobile/AAR production is independently required by the native Android build.
OPENVPN_EXECUTION_ABI = ('io.nekohasekai.libbox.RouterNodeChainExecution routerNodeChainOpenVPNExecutionFromLaunch(java.lang.String, java.lang.String) throws java.lang.Exception;', 'io.nekohasekai.libbox.RouterNodeChainExecution newRouterNodeChainOpenVPNExecutionLaunch(java.lang.String) throws java.lang.Exception;', 'io.nekohasekai.libbox.RouterNodeChainExecution routerNodeChainOpenVPNExecutionFromLast(java.lang.String, java.lang.String, java.lang.String) throws java.lang.Exception;', 'io.nekohasekai.libbox.CommandServer routerNodeChainOpenVPNExecutionNewCommandServer(io.nekohasekai.libbox.RouterNodeChainExecution, io.nekohasekai.libbox.CommandServerHandler, io.nekohasekai.libbox.PlatformInterface) throws java.lang.Exception;')
build=(ROOT/'build-sing-box-libbox.sh').read_text()
expected_loop="  for signature in "+' '.join("'"+value+"'" for value in OPENVPN_EXECUTION_ABI)+"; do\n    grep -Fq \"$signature\" \"$api_list\" || { echo \"combined libbox AAR is missing typed OpenVPN execution API: $signature\" >&2; return 1; }\n  done\n"
assert build.count(expected_loop)==1,"Android publication lost exact typed OpenVPN execution ABI guard"
with tempfile.TemporaryDirectory(prefix='android-openvpn-abi-') as folder:
    api=Path(folder)/'libbox.javap'
    guard='verify() {\n'+expected_loop+'}\nverify\n'
    for omitted in (None,*OPENVPN_EXECUTION_ABI):
        api.write_text('\n'.join(value for value in OPENVPN_EXECUTION_ABI if value!=omitted)+'\n')
        result=subprocess.run(['bash','-c',guard],env={**os.environ,'api_list':str(api)},text=True,capture_output=True,timeout=10)
        if omitted is None:
            assert result.returncode==0,result.stderr
        else:
            assert result.returncode==1 and omitted in result.stderr,"Android ABI guard admitted missing typed OpenVPN API"

print("Android connection profile safety contract: PASS")
