#!/usr/bin/env python3
"""Require the shipping ordered Server worker against independent encrypted peers.

The fixture opens only original private namespace handles. It uses real WG/AWG
and SS2022 engines, original selected DNS, authenticated SOCKS/UoT2, and joined
native stop. Missing native privileges are a failure, never a mocked success.
"""
from pathlib import Path
import argparse
import ast
import hashlib
import importlib.util
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

BUILD = load('server_encrypted_build', 'build-native-runtime.py')
NODE = load('server_encrypted_original_peer', 'test_desktop_node_physical.py')
UID = load('server_encrypted_owned_process', 'test_desktop_socket_uid.py')
WORKER = load('server_encrypted_worker', 'test_server_node_chain_native.py')
DNS_DIAGNOSTIC = load('server_dns_failure_diagnostic', 'server_dns_failure_diagnostic.py')
CASES = ('wg', 'awg-fast', 'awg-strong', 'mixed-three', 'wrong-first-key', 'wrong-middle-key',
         'wrong-ss-key', 'wrong-awg-parameters', 'wrong-node', 'failed-selected-dns',
         'wrong-public-trust', 'cancel-prefix', 'admission-restrictions', 'joined-active-udp', 'candidate-wg', 'candidate-awg')
NEGATIVE = frozenset(case for case in CASES if case.startswith('wrong-') or case in ('failed-selected-dns', 'cancel-prefix'))
MODES = {case: ('wg', 'wg') for case in CASES}
MODES.update({'candidate-awg': ('wg', 'awg2-fast'), 'awg-fast': ('wg', 'awg2-fast'), 'wrong-awg-parameters': ('wg', 'awg2-fast'),
              'awg-strong': ('awg2-strong', 'wg'), 'mixed-three': ('wg', 'awg2-fast', 'awg2-strong')})
# Preserve the exact ordinary peer package's registered transport closure.
# Native PQ execution is neither tagged nor selected by this WG/AWG gate.
TAGS = NODE.TAGS
if 'routervpn_native_pq' in TAGS or 'routervpn_pq_traffic_test' in TAGS:
    raise ValueError('Encrypted Server ordinary gate acquired a foreign native diagnostic')
TEMPLATE = 'mobile/server_chain_acceptance/encrypted_linux_test.go.tmpl'
TARGET = 'cmd/sing-box/routervpn_server_chain_encrypted_linux_test.go'
OWNER = 'routervpn-server-encrypted-test-source.json'
NATIVE = 'TestServerChainEncryptedNative'
SOURCE = 'TestServerChainEncryptedSourceInventory'
IMPORTED_CASES = ('original', 'wrong-middle-key', 'wrong-final-key', 'wrong-final-identity',
                  'failed-selected-dns', 'wrong-public-identity', 'joined-active-udp', 'admission-restrictions',
                  'prefix-original', 'prefix-wrong-middle-key', 'prefix-wrong-final-key', 'prefix-wrong-final-identity',
                  'prefix-failed-selected-dns', 'prefix-wrong-public-identity', 'prefix-joined-active-udp', 'prefix-admission-restrictions',
                  'prefix-wg-one', 'prefix-awg-fast', 'prefix-awg-strong', 'prefix-max-five',
                  'prefix-wrong-first-packet-key', 'prefix-wrong-later-packet-key',
                  'prefix-hostname-wg-one', 'prefix-hostname-awg-fast', 'prefix-hostname-awg-strong',
                  'prefix-hostname-max-five', 'prefix-hostname-wrong-transport-dns', 'prefix-hostname-wrong-middle-key',
                  'prefix-hostname-failed-selected-dns', 'prefix-hostname-joined-active-udp',
                  'prefix-hostname-wrong-first-packet-key', 'prefix-hostname-wrong-later-packet-key')
IMPORTED_NATIVE = 'TestServerChainImportedEncryptedNative'
IMPORTED_SOURCE = 'TestServerChainImportedEncryptedSource'
IMPORTED_TEMPLATE = 'mobile/server_chain_acceptance/imported_linux_test.go.tmpl'
IMPORTED_TARGET = 'cmd/sing-box/routervpn_server_chain_imported_linux_test.go'
IMPORTED_OWNER = 'routervpn-server-imported-encrypted-test-source.json'
MULTIPLE_CASES = ('adjacent', 'sparse', 'packet-first', 'wrong-key-first', 'wrong-key-second', 'wrong-public-first',
                  'wrong-public-second', 'failed-selected-dns', 'joined-active-udp')
MULTIPLE_NATIVE = 'TestServerChainMultipleEncryptedNative'
MULTIPLE_SOURCE = 'TestServerChainMultipleEncryptedSource'
HOSTNAME_TCP_ROOT = 'TestRouterVPNServerHostnameActualTCPTransport'
PACKET_RULE_ROOT = 'TestRouterVPNDesktopMultipleServerPacketRulePublication'

def check_peer_component_verdict(output, root):
    expected = (r'=== RUN[ \t]+'+re.escape(root)+r'\n--- PASS: '+re.escape(root)+r' \([0-9.]+s\)\nPASS\n?')
    if re.fullmatch(expected, output) is None:
        raise ValueError('Original peer component omitted, replaced or failed its verdict: '+root)


RECEIPT_FIELDS = {'modes', 'case', 'capture_sha256', 'source_sha256', 'prefixes', 'ready', 'retired', 'selected_dns',
                  'final_tcp', 'final_udp', 'peer_joined', 'worker_joined', 'carrier_change_refused'}


def run(*arguments, **options):
    try:
        return UID.run(*arguments, **options)
    except subprocess.CalledProcessError as error:
        raw = error.output or b''
        if isinstance(raw, bytes):
            raw = raw[-16384:].decode('utf-8', errors='replace')
        else:
            raw = raw[-16384:]
        if raw:
            sys.stderr.write('Original encrypted Server compiler/native failure (bounded tail):\n'+raw+'\n')
            sys.stderr.flush()
        raise


def image_identity(path):
    path = Path(path)
    info = path.lstat()
    if not path.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o6022 or not info.st_mode & 0o111 or not 0 < info.st_size <= 512 << 20:
        raise ValueError('Encrypted Server lost an original compiled image')
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, hashlib.sha256(path.read_bytes()).hexdigest())


def install_fixture(core):
    core = Path(core)
    if core.is_symlink() or subprocess.check_output(['git', '-C', str(core), 'rev-parse', 'HEAD'], text=True).strip() != BUILD.PIN:
        raise ValueError('Encrypted Server requires the original pinned core')
    target, record, template = core/TARGET, core/OWNER, ROOT/TEMPLATE
    if any(path.is_symlink() for path in (template, target, record, target.parent)):
        raise ValueError('Encrypted Server source contains a linked owner')
    raw = template.read_bytes()
    if not raw.startswith(b'//go:build linux && !android && routervpn_server_chain_acceptance\n\npackage main\n'):
        raise ValueError('Encrypted Server fixture changed its native test selector')
    if record.exists():
        old = json.loads(record.read_text())
        if old.get('schema') != 1 or old.get('target') != TARGET or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != old.get('sha256'):
            raise ValueError('Encrypted Server generated fixture was changed')
    elif target.exists() and target.read_bytes() != raw:
        raise ValueError('Encrypted Server target is unowned')
    target.write_bytes(raw)
    record.write_text(json.dumps({'schema': 1, 'target': TARGET, 'sha256': hashlib.sha256(raw).hexdigest()}, sort_keys=True)+'\n')


def install_imported_fixture(core):
    core = Path(core)
    if core.is_symlink() or subprocess.check_output(['git', '-C', str(core), 'rev-parse', 'HEAD'], text=True).strip() != BUILD.PIN:
        raise ValueError('Encrypted Server requires the original pinned core')
    target, record, template = core/IMPORTED_TARGET, core/IMPORTED_OWNER, ROOT/IMPORTED_TEMPLATE
    if any(path.is_symlink() for path in (template, target, record, target.parent)):
        raise ValueError('Encrypted Server source contains a linked owner')
    raw = template.read_bytes()
    if not raw.startswith(b'//go:build linux && !android && routervpn_server_chain_acceptance\n\npackage main\n'):
        raise ValueError('Encrypted Server fixture changed its native test selector')
    if record.exists():
        old = json.loads(record.read_text())
        if old.get('schema') != 1 or old.get('target') != IMPORTED_TARGET or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != old.get('sha256'):
            raise ValueError('Encrypted Server generated fixture was changed')
    elif target.exists() and target.read_bytes() != raw:
        raise ValueError('Encrypted Server target is unowned')
    target.write_bytes(raw)
    record.write_text(json.dumps({'schema': 1, 'target': IMPORTED_TARGET, 'sha256': hashlib.sha256(raw).hexdigest()}, sort_keys=True)+'\n')


def checked_sources(core):
    core, records = NODE.checked_sources(Path(core))
    WORKER.verify_sources(core)
    for path in WORKER.PREP.inputs():
        records['server/'+path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    for target, raw in WORKER.PREP.copies().items():
        if (core/target).is_symlink() or (core/target).read_bytes() != raw:
            raise ValueError('Encrypted Server lost actual shipping worker bytes')
        records['generated/'+target] = hashlib.sha256(raw).hexdigest()
    required = ('node_wg_peer_test.go.tmpl', 'node_awg_peer_test.go.tmpl', 'node_imported_peer_linux_test.go.tmpl', 'node_chain_peer_linux_test.go.tmpl', 'node_chain_imported_test.go.tmpl', 'node_chain_imported_server_peer_test.go.tmpl')
    for name in required:
        destination = NODE.PREP.PEER_TEMPLATES[name]
        if (core/destination).read_bytes() != (ROOT/'mobile/desktop'/name).read_bytes():
            raise ValueError('Encrypted Server peer was projected or substituted')
    if (core/TARGET).is_symlink() or (core/TARGET).read_bytes() != (ROOT/TEMPLATE).read_bytes():
        raise ValueError('Encrypted Server native fixture is not the original source')
    if (core/IMPORTED_TARGET).is_symlink() or (core/IMPORTED_TARGET).read_bytes() != (ROOT/IMPORTED_TEMPLATE).read_bytes():
        raise ValueError('Imported Server native fixture is not the original source')
    for name in (TEMPLATE, IMPORTED_TEMPLATE, 'deploy/server_dns_failure_diagnostic.py', DNS_DIAGNOSTIC.HELPER, 'deploy/test_server_node_chain_encrypted.py', 'deploy/test_server_node_chain_encrypted_runner.py', '.github/workflows/server-node-chain-encrypted.yml'):
        path = ROOT/name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Encrypted Server lost required gate input')
        records['acceptance/'+name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return core, records


def check_verdict(output, case, *, source_only=False):
    if case not in CASES and not source_only:
        raise ValueError('Unknown encrypted Server case')
    root = SOURCE if source_only else NATIVE
    expected = {root, *(root+'/'+name for name in (CASES if source_only else (case,)))}
    runs, passes, receipts = set(), set(), []
    carrier_mtu = None
    root_passed = False
    for line in output.splitlines():
        stripped = line.strip()
        if '--- FAIL:' in line or '--- SKIP:' in line or 'WARNING: DATA RACE' in line or 'panic:' in line:
            raise ValueError('Encrypted Server native test failed, skipped or raced')
        match = re.fullmatch(r'=== RUN\s+(\S+)', stripped)
        if match:
            name = match[1]
            if root_passed or name not in expected or name in runs or name != root and root not in runs:
                raise ValueError('Encrypted Server started unexpected or late work')
            runs.add(name)
        match = re.fullmatch(r'--- PASS: (\S+) \([0-9.]+s\)', stripped)
        if match:
            name = match[1]
            if name not in expected or name not in runs or name in passes:
                raise ValueError('Encrypted Server has unmatched/duplicate PASS')
            if name == root:
                # Go buffers child PASS reports after the parent PASS. Native
                # work and original-retirement receipt must already exist.
                if runs != expected or not source_only and len(receipts) != 1:
                    raise ValueError('Encrypted Server parent passed before original retirement')
                root_passed = True
            passes.add(name)
        if 'ENCRYPTED_SERVER_CARRIER_CAPACITY ' in line:
            raw = line.split('ENCRYPTED_SERVER_CARRIER_CAPACITY ', 1)[1]
            if not source_only or root not in runs or root_passed or carrier_mtu is not None or re.fullmatch(r'[1-9][0-9]{3}', raw) is None or not 1280 <= int(raw) <= 9000:
                raise ValueError('Encrypted Server lost its exact compiled carrier declaration')
            carrier_mtu = int(raw)
        if 'ENCRYPTED_SERVER_RECEIPT ' in line:
            if source_only or root_passed or root+'/'+case not in runs or root+'/'+case in passes:
                raise ValueError('Encrypted Server emitted a late or foreign receipt')
            raw = line.split('ENCRYPTED_SERVER_RECEIPT ', 1)[1]
            pairs = []
            value = json.loads(raw, object_pairs_hook=lambda entries: pairs.extend(key for key, _ in entries) or dict(entries))
            if value.get('modes') != list(MODES[case]):
                raise ValueError('Encrypted Server receipt downgraded an original native cipher')
            if set(value) != RECEIPT_FIELDS | ({'candidate_connects','candidate_closed'} if case.startswith('candidate-') else set()) or len(pairs) != len(set(pairs)) or value['case'] != case or type(value['prefixes']) is not int or value['prefixes'] != (3 if case == 'mixed-three' else 2):
                raise ValueError('Encrypted Server receipt identity/inventory changed')
            if case.startswith('candidate-') and (type(value['candidate_connects']) is not int or value['candidate_connects'] != 50 or value['candidate_closed'] is not True):
                raise ValueError('Encrypted candidate quota or original cleanup omitted')
            if any(value[name] is not True for name in ('retired', 'worker_joined', 'peer_joined')):
                raise ValueError('Encrypted Server omitted original joined cleanup')
            if any(not isinstance(value[name], str) or re.fullmatch('[0-9a-f]{64}', value[name]) is None for name in ('capture_sha256', 'source_sha256')):
                raise ValueError('Encrypted Server lost source/capture identity')
            if value['carrier_change_refused'] is not (case == 'wg'):
                raise ValueError('Encrypted Server lost original carrier generation refusal')
            ready = case not in NEGATIVE
            if value['ready'] is not ready or value['selected_dns'] is not ready or any(type(value[key]) is not int or value[key] < 0 for key in ('final_tcp', 'final_udp')):
                raise ValueError('Encrypted Server changed its required success/refusal verdict')
            if ready and (value['final_tcp'] <= 0 or value['final_udp'] <= 0):
                raise ValueError('Encrypted Server omitted real final encrypted traffic')
            receipts.append(value)
    if runs != expected or passes != expected or not root_passed or (len(receipts) != (0 if source_only else 1)) or not re.search(r'^PASS\r?$', output, re.M):
        raise ValueError('Encrypted Server omitted an exact required verdict')
    if source_only and carrier_mtu is None:
        raise ValueError('Encrypted Server omitted compiled carrier declaration')
    return receipts[0] if receipts else {'source_cases': list(CASES), 'carrier_mtu': carrier_mtu}



def check_multiple_receipt(value, case):
    counters = {'outer_tcp', 'outer_udp', 'outer_proofs', 'outer_auth_failures', 'inner_auth_failures', 'packet_udp', 'packet_proofs',
                'inner_tcp', 'inner_udp', 'inner_proofs', 'final_health', 'final_dns',
                'final_public', 'final_udp', 'echo_replies'}
    fields = counters | {'case', 'positions', 'source_sha256', 'capture_sha256', 'ready',
                         'pending_closed', 'worker_joined', 'peer_joined', 'in_flight'}
    if case == 'sparse':
        fields |= {'candidate_position', 'candidate_connects'}
        if type(value.get('candidate_position')) is not int or value['candidate_position'] != 2 or \
                type(value.get('candidate_connects')) is not int or value['candidate_connects'] != 50:
            raise ValueError('Multiple-import candidate did not complete fifty connections through its original paired packet')
    if set(value) != fields or value['case'] != case or case not in MULTIPLE_CASES:
        raise ValueError('Multiple-import receipt is foreign or incomplete')
    if any(type(value[k]) is not int or value[k] < 0 for k in counters):
        raise ValueError('Multiple-import peer counters must be nonnegative integers')
    if any(not isinstance(value[k], str) or not re.fullmatch('[0-9a-f]{64}', value[k])
           for k in ('source_sha256', 'capture_sha256')):
        raise ValueError('Multiple-import source/worker digest missing')
    sparse = case != 'adjacent'
    positions = [0, 1] if case == 'packet-first' else [0, 2] if sparse else [0]
    if value['positions'] != positions or any(type(p) is not int for p in value['positions']):
        raise ValueError('Multiple-import source packet positions changed')
    ready = case in ('adjacent', 'sparse', 'packet-first', 'joined-active-udp')
    if any(value[k] is not True for k in ('pending_closed', 'worker_joined', 'peer_joined')) or \
            value['ready'] is not ready or value['in_flight'] is not (case == 'joined-active-udp'):
        raise ValueError('Multiple-import pending, terminal or retirement authority changed')
    outer_proven = case != 'wrong-key-first'
    inner_reached = outer_proven and case != 'wrong-public-first'
    inner_proven = inner_reached and case != 'wrong-key-second'
    final_reached = inner_proven and case != 'wrong-public-second'
    observations = {'outer_tcp': True, 'outer_proofs': outer_proven, 'outer_auth_failures': case == 'wrong-key-first',
                    'inner_auth_failures': case == 'wrong-key-second',
                    'packet_proofs': sparse and inner_reached, 'inner_tcp': inner_reached,
                    'inner_proofs': inner_proven, 'final_health': final_reached, 'final_dns': final_reached,
                    'final_public': ready, 'echo_replies': ready}
    # A captured WG keepalive may arrive before a wrong public proof is rejected.
    # Every authenticated downstream proof must still remain at zero.
    if case != 'wrong-public-first':
        observations['packet_udp'] = sparse and inner_reached
    if any((value[k] > 0) != expected for k, expected in observations.items()) or \
            ready and any(value[k] == 0 for k in ('outer_udp', 'inner_udp', 'final_udp')):
        raise ValueError('Multiple-import proof or packet observation crossed the wrong member')


def check_imported_verdict(output, case, *, source_only=False, multiple=False):
    cases = MULTIPLE_CASES if multiple else IMPORTED_CASES
    if not source_only and case not in cases:
        raise ValueError('Unknown imported Server case')
    root = IMPORTED_SOURCE if source_only else IMPORTED_NATIVE
    if multiple:
        root = MULTIPLE_SOURCE if source_only else MULTIPLE_NATIVE
    marker = 'MULTIPLE_SERVER_RECEIPT ' if multiple else 'IMPORTED_SERVER_RECEIPT '
    expected = {root, *(root+'/'+name for name in (cases if source_only else (case,)))}
    runs, passes, receipts = set(), set(), []
    ended = False
    for line in output.splitlines():
        text = line.strip()
        if any(marker in line for marker in ('--- FAIL:', '--- SKIP:', 'WARNING: DATA RACE', 'panic:')):
            raise ValueError('Imported Server failed, skipped or raced')
        match = re.fullmatch(r'=== RUN\s+(\S+)', text)
        if match:
            name = match[1]
            if ended or name not in expected or name in runs or name != root and root not in runs:
                raise ValueError('Imported Server unexpected or repeated work')
            runs.add(name)
        match = re.fullmatch(r'--- PASS: (\S+) \([0-9.]+s\)', text)
        if match:
            name = match[1]
            if name not in runs or name in passes:
                raise ValueError('Imported Server unmatched or repeated PASS')
            if name == root:
                if runs != expected or not source_only and len(receipts) != 1:
                    raise ValueError('Imported Server passed before original retirement')
                ended = True
            passes.add(name)
        if marker in line:
            if source_only or ended or root+'/'+case not in runs or root+'/'+case in passes:
                raise ValueError('Imported Server late or foreign receipt')
            keys = []
            value = json.loads(line.split(marker, 1)[1], object_pairs_hook=lambda entries: keys.extend(k for k,v in entries) or dict(entries))
            if multiple:
                if len(keys) != len(set(keys)):
                    raise ValueError('Duplicate multiple-import evidence')
                check_multiple_receipt(value, case)
                receipts.append(value)
                continue
            fields = {'case', 'prefix_modes', 'prefix_packets', 'prefix_proofs', 'capture_sha256', 'source_sha256', 'ready', 'selected_dns', 'middle_tcp', 'middle_udp', 'final_tcp', 'final_udp', 'transport_dns_queries', 'retired', 'worker_joined', 'peer_joined', 'private_udp_refused', 'private_sink_packets', 'private_sink_replies'}
            if set(value) != fields or len(keys) != len(set(keys)) or value['case'] != case:
                raise ValueError('Imported Server receipt identity changed')
            if any(value[k] is not True for k in ('retired','worker_joined','peer_joined')):
                raise ValueError('Imported Server lost original joined retirement')
            if any(not isinstance(value[k], str) or re.fullmatch('[0-9a-f]{64}', value[k]) is None for k in ('capture_sha256','source_sha256')):
                raise ValueError('Imported Server source identity missing')
            original = case.removeprefix('prefix-').removeprefix('hostname-')
            ready = original in ('original', 'joined-active-udp', 'admission-restrictions', 'wg-one', 'awg-fast', 'awg-strong', 'max-five')
            modes = []
            if case.startswith('prefix-'):
                modes = {'wg-one': ['wg'], 'awg-fast': ['wg', 'awg2-fast'], 'awg-strong': ['awg2-strong', 'wg'],
                         'max-five': ['wg', 'awg2-fast', 'awg2-strong', 'wg', 'awg2-fast']}.get(original, ['wg', 'wg'])
            if value['prefix_modes'] != (modes or None):
                raise ValueError('Imported Server changed actual packet inventory')
            packet_fault = original in ('wrong-first-packet-key', 'wrong-later-packet-key')
            hostname = case.startswith('prefix-hostname-')
            transport_fault = original == 'wrong-transport-dns'
            queries = value['transport_dns_queries']
            if type(queries) is not int or queries < 0 or (queries > 0) is not (hostname and not packet_fault):
                raise ValueError('Imported hostname lost its original packet-routed transport DNS observation')
            for field in ('prefix_packets', 'prefix_proofs'):
                counts = value[field]
                if not modes:
                    if counts is not None:
                        raise ValueError('Imported Server trio manufactured packet observations')
                    continue
                if not isinstance(counts, list) or len(counts) != len(modes) or any(type(n) is not int or n < 0 for n in counts):
                    raise ValueError('Imported Server omitted actual packet observations')
                for position, count in enumerate(counts):
                    if field == 'prefix_packets':
                        observed = not packet_fault or original == 'wrong-first-packet-key' and position == 0 or original == 'wrong-later-packet-key' and position <= 1
                    else:
                        observed = not packet_fault or original == 'wrong-later-packet-key' and position == 0
                    if (count > 0) is not observed:
                        raise ValueError('Imported Server packet proof boundary changed')
            if value['ready'] is not ready or value['selected_dns'] is not ready:
                raise ValueError('Imported Server success/refusal changed')
            counters = ('middle_tcp','middle_udp','final_tcp','final_udp')
            if any(type(value[k]) is not int or value[k] < 0 for k in counters) or not (packet_fault or transport_fault) and value['middle_tcp'] <= 0 or (packet_fault or transport_fault) and any(value[k] != 0 for k in counters) or ready and any(value[k] <= 0 for k in counters):
                raise ValueError('Imported Server missing actual encrypted observations')
            restricted = original == 'admission-restrictions'
            if value['private_udp_refused'] is not restricted or any(type(value[k]) is not int or value[k] < 0 for k in ('private_sink_packets','private_sink_replies')):
                raise ValueError('Imported Server omitted original private policy observation')
            if restricted and (value['private_sink_packets'] != 0 or value['private_sink_replies'] != 0) or ready and not restricted and (value['private_sink_packets'] <= 0 or value['private_sink_replies'] <= 0):
                raise ValueError('Imported Server private policy observation contradicts its original source')
            receipts.append(value)
    if runs != expected or passes != expected or not ended or len(receipts) != (0 if source_only else 1) or not re.search(r'^PASS\r?$', output, re.M):
        raise ValueError('Imported Server omitted exact required verdict')
    return receipts[0] if receipts else {'source_cases': list(cases)}


def namespace_program(source_sha256, *, imported=False, multiple=False):
    """Transfer only sealed stdlib namespace code across the private UID boundary.

    Namespace root maps to outer root, not the runner account. It must not
    reopen the runner's private checkout or import repository modules there.
    The exact source hash was already captured by checked_sources before build.
    """
    path = Path(__file__).resolve()
    if path.is_symlink() or not path.is_file():
        raise ValueError('Encrypted Server lost original namespace source')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != source_sha256:
        raise ValueError('Encrypted Server namespace source changed after capture')
    tree = ast.parse(raw, filename=str(path))
    projected = ast.parse('from pathlib import Path\nimport hashlib\nimport os\nimport platform\nimport re\nimport stat\nimport subprocess\nimport sys\n').body
    selections = (('IMPORTED_CASES', IMPORTED_CASES), ('IMPORTED_NATIVE', IMPORTED_NATIVE)) if imported else (('CASES', CASES), ('NATIVE', NATIVE))
    if multiple:
        if imported:
            raise ValueError('Conflicting encrypted Server case families')
        selections = (('MULTIPLE_CASES', MULTIPLE_CASES), ('MULTIPLE_NATIVE', MULTIPLE_NATIVE))
    for name, captured in selections:
        definitions = [node for node in tree.body if isinstance(node, ast.Assign)
                       and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                       and node.targets[0].id == name]
        if len(definitions) != 1 or ast.literal_eval(definitions[0].value) != captured:
            raise ValueError('Encrypted Server namespace changed original case inventory')
        definition = definitions[0]
        if imported or multiple:
            definition.targets[0].id = name.split('_', 1)[1]
        projected.append(definition)
    for name in ('image_identity', 'inside_namespace'):
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
        if len(functions) != 1 or functions[0].decorator_list:
            raise ValueError('Encrypted Server namespace lost an original required function')
        projected.append(functions[0])
    projected.extend(ast.parse("""
if __name__ == '__main__':
    if len(sys.argv) != 8:
        raise ValueError('Encrypted Server namespace requires exact original arguments')
    sys.exit(inside_namespace(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]),
        {'driver': sys.argv[4], 'peer': sys.argv[5], 'worker': sys.argv[6]}, sys.argv[7]))
""").body)
    return ast.unparse(ast.Module(body=projected, type_ignores=[]))


def inside_namespace(driver, peer, worker, identities, case):
    if platform.system() != 'Linux' or os.geteuid() != 0 or case not in CASES:
        raise ValueError('Encrypted Server needs its isolated native Linux root')
    for role, path in (('driver', driver), ('peer', peer), ('worker', worker)):
        if image_identity(path)[-1] != identities[role]:
            raise ValueError('Encrypted Server namespace lost a compiled image')
    original = os.environ.get('ROUTERVPN_SERVER_CHAIN_OUTER_NETNS')
    current = os.stat('/proc/self/ns/net')
    if not original or original == f'{current.st_dev}:{current.st_ino}':
        raise ValueError('Encrypted Server refused the original host network namespace')
    declared = os.environ.get('ROUTERVPN_SERVER_CHAIN_CARRIER_MTU', '')
    if re.fullmatch(r'[1-9][0-9]{3}', declared) is None or not 1280 <= int(declared) <= 9000:
        raise ValueError('Encrypted Server requires its compiled carrier declaration')
    carrier_mtu = int(declared)
    # Every mutation is below the newly owned mount/network/PID namespaces.
    subprocess.run(['mount', '--make-rprivate', '/'], check=True, timeout=5)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run'], check=True, timeout=5)
    commands = (
        ('link', 'set', 'lo', 'up'), ('netns', 'add', 'rvpn-peer'),
        ('link', 'add', 'rvpn-test', 'type', 'veth', 'peer', 'name', 'rvpn-peer'),
        ('link', 'set', 'rvpn-test', 'mtu', str(carrier_mtu)),
        ('link', 'set', 'rvpn-peer', 'mtu', str(carrier_mtu)),
        ('link', 'set', 'rvpn-peer', 'netns', 'rvpn-peer'),
        ('addr', 'add', '192.168.210.1/30', 'dev', 'rvpn-test'), ('link', 'set', 'rvpn-test', 'up'),
        ('route', 'add', 'default', 'via', '192.168.210.2', 'dev', 'rvpn-test'),
        ('netns', 'exec', 'rvpn-peer', 'ip', 'link', 'set', 'lo', 'up'),
        ('netns', 'exec', 'rvpn-peer', 'ip', 'addr', 'add', '192.168.210.2/30', 'dev', 'rvpn-peer'),
        ('netns', 'exec', 'rvpn-peer', 'ip', 'link', 'set', 'rvpn-peer', 'up'))
    for command in commands:
        subprocess.run(['ip', *command], check=True, timeout=5)
    env = dict(os.environ, ROUTERVPN_SERVER_CHAIN_NATIVE_NS='1', ROUTERVPN_SERVER_CHAIN_PEER=str(peer),
               ROUTERVPN_SERVER_CHAIN_PEER_SHA256=identities['peer'], ROUTERVPN_SERVER_CHAIN_IMAGE=str(worker),
               ROUTERVPN_SERVER_CHAIN_IMAGE_SHA256=identities['worker'], GORACE='atexit_sleep_ms=0')
    try:
        # Read both actual endpoints before running the unchanged proof graph.
        for command in (['ip', '-o', 'link', 'show', 'dev', 'rvpn-test'],
                        ['ip', 'netns', 'exec', 'rvpn-peer', 'ip', '-o', 'link', 'show', 'dev', 'rvpn-peer']):
            actual = subprocess.check_output(command, text=True, timeout=5)
            value = re.search(r'\bmtu ([0-9]+)\b', actual)
            if value is None or int(value.group(1)) != carrier_mtu:
                raise ValueError('Encrypted Server actual carrier differs from its declared packet envelope')
        result = subprocess.run([str(driver), '-test.run=^'+NATIVE+'$/'+ '/'.join('^'+re.escape(part)+'$' for part in case.split('/')), '-test.v', '-test.count=1', '-test.timeout=90s'], env=env, timeout=105)
    finally:
        subprocess.run(['ip', 'netns', 'delete', 'rvpn-peer'], check=True, timeout=5)
    return result.returncode


def repository_identity(required):
    if required is None:
        return None
    if re.fullmatch('[0-9a-f]{40}', required) is None:
        raise ValueError('Encrypted Server requires an exact source commit')
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=ROOT, text=True, timeout=30).strip()
    if git('rev-parse', 'HEAD') != required:
        raise ValueError('Encrypted Server source commit changed')
    git('diff', '--quiet', 'HEAD', '--')
    if git('ls-files', '--others', '--exclude-standard', '--', 'mobile', 'internal', 'deploy', 'cmd', '.github', 'go.mod', 'go.sum'):
        raise ValueError('Encrypted Server source includes unpublished inputs')
    return {'commit': required, 'tree': git('rev-parse', 'HEAD^{tree}')}


def execute(core, go='go', *, env=None, receipt=None, compile_only=False):
    if platform.system() != 'Linux':
        raise ValueError('Encrypted Server requires actual Linux')
    captured = dict(os.environ if env is None else env, GOWORK='off')
    if captured.get('GOOS', 'linux') != 'linux' or captured.get('CGO_ENABLED', '1') != '1':
        raise ValueError('Encrypted Server forbids cross-host or non-race acceptance')
    captured['CGO_ENABLED'] = '1'
    install_fixture(core)
    install_imported_fixture(core)
    core, before = checked_sources(core)
    compiler, captured = UID.compiler_toolchain(core, go, captured)
    architecture = run([compiler, 'env', 'GOARCH'], cwd=core, env=captured).strip()
    if architecture not in ('amd64', 'arm64'):
        raise ValueError('Encrypted Server architecture is not required native inventory')
    receipt = Path(receipt).absolute() if receipt else None
    if receipt and (receipt.exists() or receipt.is_symlink() or not receipt.parent.is_dir()):
        raise ValueError('Encrypted Server receipt requires a new owned path')
    with tempfile.TemporaryDirectory(prefix='routervpn-server-encrypted-') as temporary:
        workspace = Path(temporary).resolve()
        workspace.chmod(0o755)  # Test images contain no private lease input.
        driver, peer, worker = workspace/'acceptance.test', workspace/'peer.test', workspace/'sing-box'
        common = ['-race', '-mod=readonly', '-p=1', '-tags='+','.join(TAGS), '-ldflags=-checklinkname=0']
        print('Compiling original shipping Server CLI', flush=True)
        run([compiler, 'build', *common, '-o', worker, './cmd/sing-box'], cwd=core, env=captured, timeout=600)
        print('Compiling unchanged independent encrypted peer', flush=True)
        run([compiler, 'test', '-c', *common, '-o', peer, './protocol/routervpnamnezia'], cwd=core, env=captured, timeout=600)
        driver_flags = [arg if not arg.startswith('-tags=') else arg+',routervpn_server_chain_acceptance' for arg in common]
        print('Compiling actual encrypted acceptance driver', flush=True)
        run([compiler, 'test', '-c', *driver_flags, '-o', driver, './cmd/sing-box'], cwd=core, env=captured, timeout=600)
        images = {role: image_identity(path) for role, path in (('driver', driver), ('peer', peer), ('worker', worker))}
        if checked_sources(core)[1] != before:
            raise ValueError('Encrypted Server source changed during compilation')
        for component in (HOSTNAME_TCP_ROOT, PACKET_RULE_ROOT):
            output = run([peer, '-test.run=^'+component+'$', '-test.v', '-test.count=1', '-test.timeout=30s'], cwd=core, env=captured, timeout=45)
            check_peer_component_verdict(output, component)
            print(output, end='')
        source_output = run([driver, '-test.run=^'+SOURCE+'$', '-test.v', '-test.count=1', '-test.timeout=60s'], cwd=core, env=captured, timeout=75)
        source_verdict = check_verdict(source_output, None, source_only=True)
        print(source_output, end='')
        imported_output = run([driver, '-test.run=^'+IMPORTED_SOURCE+'$', '-test.v', '-test.count=1', '-test.timeout=60s'], cwd=core, env=captured, timeout=75)
        check_imported_verdict(imported_output, None, source_only=True)
        print(imported_output, end='')
        multiple_output = run([driver, '-test.run=^'+MULTIPLE_SOURCE+'$', '-test.v', '-test.count=1', '-test.timeout=60s'], cwd=core, env=captured, timeout=75)
        check_imported_verdict(multiple_output, None, source_only=True, multiple=True)
        print(multiple_output, end='')
        verdicts, imported_verdicts, multiple_verdicts = [], [], []
        if not compile_only:
            sudo = UID.privilege_tool()
            original = os.stat('/proc/self/ns/net')
            native_env = dict(captured, TMPDIR='/tmp', ROUTERVPN_SERVER_CHAIN_CARRIER_MTU=str(source_verdict['carrier_mtu']), ROUTERVPN_SERVER_CHAIN_OUTER_NETNS=f'{original.st_dev}:{original.st_ino}')
            program = namespace_program(before['acceptance/deploy/test_server_node_chain_encrypted.py'])
            for case in CASES:
                command = ['unshare', '--user', '--map-root-user', '--mount', '--net', '--pid', '--fork', '--mount-proc',
                           sys.executable, '-I', '-c', program, str(driver), str(peer), str(worker),
                           images['driver'][-1], images['peer'][-1], images['worker'][-1], case]
                if sudo:
                    command = [sudo, '-n', '--preserve-env=ROUTERVPN_SERVER_CHAIN_OUTER_NETNS,ROUTERVPN_SERVER_CHAIN_CARRIER_MTU', '--', *command]
                output = run(command, cwd=workspace, env=native_env, timeout=125, sudo=sudo)
                verdicts.append(check_verdict(output, case)); print(output, end='')
            imported_program = namespace_program(before['acceptance/deploy/test_server_node_chain_encrypted.py'], imported=True)
            for case in IMPORTED_CASES:
                command = ['unshare', '--user', '--map-root-user', '--mount', '--net', '--pid', '--fork', '--mount-proc',
                           sys.executable, '-I', '-c', imported_program, str(driver), str(peer), str(worker),
                           images['driver'][-1], images['peer'][-1], images['worker'][-1], case]
                if sudo:
                    command = [sudo, '-n', '--preserve-env=ROUTERVPN_SERVER_CHAIN_OUTER_NETNS,ROUTERVPN_SERVER_CHAIN_CARRIER_MTU', '--', *command]
                try:
                    output = run(command, cwd=workspace, env=native_env, timeout=125, sudo=sudo)
                except subprocess.CalledProcessError as original_failure:
                    # Original source/image/case remains release authority. The
                    # separate shadow replay cannot issue an acceptance receipt.
                    DNS_DIAGNOSTIC.observe_failure(case, original_failure, core=core, workspace=workspace,
                        compiler=compiler, captured=captured, common=common, driver_flags=driver_flags,
                        peer=peer, program=imported_program, native_env=native_env, sudo=sudo,
                        run=run, image_identity=image_identity, source_identity=lambda: checked_sources(core)[1], expected_source=before)
                    raise
                imported_verdicts.append(check_imported_verdict(output, case)); print(output, end='')
            multiple_program = namespace_program(before['acceptance/deploy/test_server_node_chain_encrypted.py'], multiple=True)
            for case in MULTIPLE_CASES:
                command = ['unshare', '--user', '--map-root-user', '--mount', '--net', '--pid', '--fork', '--mount-proc',
                           sys.executable, '-I', '-c', multiple_program, str(driver), str(peer), str(worker),
                           images['driver'][-1], images['peer'][-1], images['worker'][-1], case]
                if sudo:
                    command = [sudo, '-n', '--preserve-env=ROUTERVPN_SERVER_CHAIN_OUTER_NETNS,ROUTERVPN_SERVER_CHAIN_CARRIER_MTU', '--', *command]
                output = run(command, cwd=workspace, env=native_env, timeout=125, sudo=sudo)
                multiple_verdicts.append(check_imported_verdict(output, case, multiple=True))
                print(output, end='')
        if checked_sources(core)[1] != before or any(image_identity(path) != images[role] for role, path in (('driver', driver), ('peer', peer), ('worker', worker))):
            raise ValueError('Encrypted Server original source/image changed during acceptance')
        result = {'schema': 1, 'gate': 'ordered-server-encrypted', 'scope': 'compile-and-source-only' if compile_only else 'actual-encrypted-server-worker',
                  'target': 'linux/'+architecture, 'pin': BUILD.PIN, 'source_files': before,
                  'source_sha256': hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                  'images': {role: {'sha256': identity[-1], 'bytes': identity[2]} for role, identity in images.items()},
                  'required_cases': list(CASES), 'cases': verdicts, 'required_imported_cases': list(IMPORTED_CASES), 'imported_cases': imported_verdicts,
                  'required_multiple_cases': list(MULTIPLE_CASES), 'multiple_cases': multiple_verdicts}
    if workspace.exists():
        raise ValueError('Encrypted Server compilation workspace did not retire')
    if receipt:
        if compile_only:
            raise ValueError('Compile-only verification cannot publish native acceptance receipt')
        with receipt.open('x', encoding='utf-8') as output:
            json.dump(result, output, indent=2, sort_keys=True); output.write('\n')
    return result


def standalone(go='go', *, receipt=None, required_commit=None):
    repository = repository_identity(required_commit)
    compiler, captured = UID.compiler_toolchain(ROOT, go, dict(os.environ))
    old = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix='routervpn-server-encrypted-core-') as temporary:
        workspace = Path(temporary); core, xray = workspace/'core', workspace/'xray'
        try:
            os.environ.clear(); os.environ.update(captured)
            BUILD.checkout(core, 'https://github.com/SagerNet/sing-box.git', BUILD.PIN)
            BUILD.checkout(xray, 'https://github.com/XTLS/Xray-core.git', BUILD.POLICY.XRAY.XRAY_PIN)
            BUILD.pristine(core, BUILD.PIN); BUILD.pristine(xray, BUILD.POLICY.XRAY.XRAY_PIN)
            BUILD.POLICY.prepare_native(core, xray)
            BUILD.PERFORMANCE.prepare(core); BUILD.OPENVPN.prepare(core)
            BUILD.EXTERNAL.prepare(core, go=str(compiler), env=captured); BUILD.BUFFERS.prepare(core)
            BUILD.run([compiler, 'mod', 'tidy'], cwd=core, env=captured); BUILD.run([compiler, 'mod', 'verify'], cwd=core, env=captured)
            BUILD.POLICY.AMNEZIA.verify(core)
            result = execute(core, str(compiler), env=captured)
        finally:
            os.environ.clear(); os.environ.update(old)
    if repository_identity(required_commit) != repository or workspace.exists():
        raise ValueError('Encrypted Server original repository/workspace did not remain owned')
    result['repository'] = repository
    if receipt:
        path = Path(receipt).absolute()
        if path.exists() or path.is_symlink() or not path.parent.is_dir():
            raise ValueError('Encrypted Server receipt requires an unused owned path')
        with path.open('x', encoding='utf-8') as output:
            json.dump(result, output, indent=2, sort_keys=True); output.write('\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path); parser.add_argument('--go', default='go'); parser.add_argument('--standalone', action='store_true')
    parser.add_argument('--compile-only', action='store_true'); parser.add_argument('--receipt', type=Path); parser.add_argument('--require-commit')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    for role in ('driver', 'peer', 'worker'):
        parser.add_argument('--'+role, type=Path, help=argparse.SUPPRESS); parser.add_argument('--'+role+'-sha256', help=argparse.SUPPRESS)
    parser.add_argument('--case', choices=CASES, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside:
        sys.exit(inside_namespace(args.driver, args.peer, args.worker, {role: getattr(args, role+'_sha256') for role in ('driver', 'peer', 'worker')}, args.case))
    if args.standalone and not args.core and not args.compile_only:
        result = standalone(args.go, receipt=args.receipt, required_commit=args.require_commit)
    elif args.core and not args.standalone and not args.require_commit:
        result = execute(args.core, args.go, receipt=args.receipt, compile_only=args.compile_only)
    else:
        parser.error('use --standalone with required commit, or --core [--compile-only]')
    print(json.dumps({key: value for key, value in result.items() if key != 'source_files'}, sort_keys=True))
