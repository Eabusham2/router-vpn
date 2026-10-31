#!/usr/bin/env python3
"""Exercise complete MAX with actual scoped Windows WFP and the real Rust ABI.

The retained separate peer executes the original MAX reference graph. Client
permits and socket ownership use the actual shipping Windows factories; TUN is
an explicit harmless boundary. --prospective adds only the four complete MAX
families to the test compilation and first proves unmodified admission closed.
It does not modify or enable the shipping/public predicate.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MAX = load('windows_complete_max_graph', 'test_desktop_node_max.py')
WPQ = load('windows_complete_max_native', 'test_windows_node_pq.py')
NODE, REFERENCE, WFP = MAX.NODE, MAX.REFERENCE, WPQ.WFP
PREDICATE = WPQ.PREDICATE
PEER = 'protocol/routervpnpq/node_max_peer_windows_test.go'
PEER_TEMPLATE = 'mobile/desktop/node_max_peer_windows_test.go.tmpl'
PREFIX = WPQ.PREFIX
TAGS = REFERENCE.TAGS + ',routervpn_windows_node_composition'
MODES = tuple(mode for modes in MAX.FAMILIES.values() for mode in modes)
LAYERS = MAX.LAYERS
CLOSED = 'TestRouterVPNDesktopNodeWindowsMAXCapabilityClosed'
OPEN = 'TestRouterVPNDesktopNodeWindowsMAXCapabilityOpen'
MARKERS = 'TestRouterVPNDesktopNodeWindowsMAXMarkers'
STARTUP_RECORDS = MAX.STARTUP_RECORDS
SUCCESSION = 'TestRouterVPNDesktopNodeWindowsMAXSuccession'
FOREIGN = 'TestRouterVPNDesktopNodeWindowsMAXForeignPredecessor'
PROSPECTIVE_BEFORE = '\tswitch mode {\n'
PROSPECTIVE_AFTER = PROSPECTIVE_BEFORE + '\tcase "max-quic-wg", "max-quic-awg", "max-tls-wg", "max-tls-awg":\n\t\treturn true\n'
JOIN_FAILURES = (*MAX.JOIN_FAILURES, *WPQ.CLEANUP_DIAGNOSTICS, 'captured Node Box did not join',
    'actual Windows PQ owner did not join', 'owned MAX reference did not join',
    'MAX reference ignored its owned input EOF', 'MAX reference retained its unjoined process',
    'MAX failed credential startup did not join', 'MAX cancelled native credential trial did not join',
    'exact PQ test-owned deny did not retire', 'rejected MAX successor did not join')


def checked_sources(source):
    source, records = MAX.checked_sources(Path(source))
    actual, native = WPQ.checked_sources(source)
    if source != actual:
        raise ValueError('MAX and native WFP changed the captured core identity')
    for name, digest in native.items():
        if name in records and records[name] != digest:
            raise ValueError('MAX and Windows PQ disagree on an owned source record')
        records[name] = digest
    path = ROOT / PEER_TEMPLATE
    if NODE.PREP.PEER_TEMPLATES.get(path.name) != PEER or path.is_symlink() or not path.read_bytes().startswith(PREFIX):
        raise ValueError('Complete MAX WFP lost its exact native/CGO/test-only mapping')
    # Key generation executes this exact private-root helper before exposing
    # any KEM material. Bind it and its executable acceptance/preparation
    # tests to the native evidence, not only the Python invocation wrapper.
    for relative in (PEER_TEMPLATE, 'deploy/test_windows_node_max.py', 'deploy/test_windows_node_max_runner.py',
                     'client/Protect-RouterVPN-Windows-PrivateRoot.ps1', 'client/test-windows-private-acl.ps1',
                     'deploy/build_pq_reference_fixture.py', 'deploy/test_pq_reference_preparation.py'):
        records['windows-max/' + relative] = MAX.regular_digest(ROOT / relative)
    return source, records


def prospective_predicate(raw):
    if ('func DesktopNodePhysicalGraphSupported(mode, startLayer string) bool {' not in raw or
            any('"' + mode + '"' in raw for mode in MODES)):
        raise ValueError('Prospective complete MAX lost its exact closed four-family source')
    return WFP.BOOT.IDENTITY.replace_once(raw, PROSPECTIVE_BEFORE, PROSPECTIVE_AFTER)


def native_parent(parent):
    before = 'TestRouterVPNDesktopNodeCompleteMAX'
    if not parent.startswith(before):
        raise ValueError('MAX native control has an unrelated graph parent')
    return 'TestRouterVPNDesktopNodeWindowsMAX' + parent[len(before):]


def ordinary_witness(protocol):
    return 'MAX native ordinary ' + protocol + ' socket denied by captured WFP'


def handshake_witness(protocol):
    return 'MAX native captured ' + protocol + ' handshake rejected before ready'


# Only deliberate socket-bypass compilations receive this observer. It never
# creates a socket grant or returns a different I/O result. A native WSAEACCES
# must occur between two fresh, identical BFE/isolated-owner readbacks for the
# exact captured outer tuple; a timeout or unrelated startup failure is silent.
ORDINARY_OBSERVER = r'''//go:build windows && routervpn_windows_node_composition

package mobiletor

import (
    "context"
    "errors"
    "net"
    "net/netip"
    "syscall"
    "time"
)

func desktopMAXControlSnapshot(ctx context.Context, network string, remote netip.AddrPort) (DesktopWindowsNodeCompositionReadback, bool) {
    if ctx == nil || ctx.Err() != nil || network != "tcp" && network != "udp" || !remote.IsValid() || remote.Port() == 0 {
        return DesktopWindowsNodeCompositionReadback{}, false
    }
    proof, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()
    snapshot, err := DesktopWindowsNodeCompositionSnapshot(proof)
    if err != nil || snapshot.Closed || snapshot.Target.Validate() != nil || snapshot.Owner.Kind != "windows-isolated-token" || !snapshot.Options.RetainBaselineForHandoff || len(snapshot.Grants) != 0 || len(snapshot.Options.PrivateDestinations) != 1 || snapshot.Options.PrivateDestinations[0] != (DesktopWindowsSocketDestination{Network: network, Address: remote}) {
        return snapshot, false
    }
    desktopWindowsNodeComposition.Lock()
    policy := desktopWindowsNodeComposition.owner
    desktopWindowsNodeComposition.Unlock()
    return snapshot, policy != nil && policy.Current(snapshot.Capture, snapshot.Owner)
}

func desktopMAXControlDenied(ctx context.Context, before DesktopWindowsNodeCompositionReadback, network string, remote netip.AddrPort, err error) {
    if !errors.Is(err, syscall.Errno(10013)) {
        return
    }
    after, current := desktopMAXControlSnapshot(ctx, network, remote)
    if !current || before.Target != after.Target || before.Capture != after.Capture || before.Owner != after.Owner {
        return
    }
    if network == "tcp" {
        println("MAX native ordinary tcp socket denied by captured WFP")
    } else {
        println("MAX native ordinary udp socket denied by captured WFP")
    }
}

type desktopMAXControlConn struct {
    net.Conn
    ctx context.Context
    before DesktopWindowsNodeCompositionReadback
    network string
    remote netip.AddrPort
}

func (c *desktopMAXControlConn) Write(body []byte) (int, error) {
    count, err := c.Conn.Write(body)
    desktopMAXControlDenied(c.ctx, c.before, c.network, c.remote, err)
    return count, err
}

func DesktopWindowsMAXControlDial(ctx context.Context, network, address string, dial func() (net.Conn, error)) (net.Conn, error) {
    remote, parseErr := netip.ParseAddrPort(address)
    before, current := desktopMAXControlSnapshot(ctx, network, remote)
    connection, err := dial()
    if parseErr == nil && current {
        desktopMAXControlDenied(ctx, before, network, remote, err)
        if connection != nil {
            connection = &desktopMAXControlConn{Conn: connection, ctx: ctx, before: before, network: network, remote: remote}
        }
    }
    return connection, err
}
'''


def late_handshake_control(selected, protocol):
    raw = selected[4]
    boundary = '\tif closed || !allowed || owner == nil || !owner.Current() {\n'
    if raw.count(boundary) != 1:
        raise ValueError('MAX native control lost its precise late-handshake mutation')
    observer = ('\tif !closed && allowed && owner != nil && owner.SocketCurrent() && !owner.Current() && base == ' + json.dumps(protocol) + ' {\n'
                '\t\tsnapshot, err := mobiletor.DesktopWindowsNodeCompositionSnapshot(ctx)\n'
                '\t\tif err == nil && !snapshot.Closed && snapshot.Target.Validate() == nil && snapshot.Capture == owner.brokerCapture() && snapshot.Owner.Kind == "windows-isolated-token" {\n'
                '\t\t\tprintln(' + json.dumps(handshake_witness(protocol)) + ')\n\t\t}\n\t}\n')
    return (*selected[:4], raw.replace(boundary, observer + boundary))


def observed_control_sources(source, mutation):
    label, _, _, _, _, replacement = mutation
    if replacement is None:
        return {}
    sources = MAX.control_sources(source, label, *replacement)
    protocol = {'uncaptured-outer-tcp': 'tcp', 'uncaptured-outer-udp': 'udp'}.get(label)
    if protocol is None:
        return sources
    relative, raw = replacement
    if protocol == 'tcp':
        before = 'conn, err := (&net.Dialer{}).DialContext(cctx, N.NetworkTCP, b.server.String())'
        after = 'conn, err := nodeMAXOrdinaryDial(cctx, N.NetworkTCP, b.server.String())'
        helper = '''//go:build windows && routervpn_windows_node_composition

package routervpnxray

import (
    "context"
    "net"
    "github.com/sagernet/sing-box/routervpn/mobiletor"
)

func nodeMAXOrdinaryDial(ctx context.Context, network, address string) (net.Conn, error) {
    return mobiletor.DesktopWindowsMAXControlDial(ctx, network, address, func() (net.Conn, error) {
        return (&net.Dialer{}).DialContext(ctx, network, address)
    })
}
'''
    else:
        before = 'Dialer:             func() N.Dialer { _ = outboundDialer; return N.SystemDialer }(),'
        after = 'Dialer:             func() N.Dialer { _ = outboundDialer; return nodeMAXOrdinaryDialer{N.SystemDialer} }(),'
        helper = '''//go:build windows && routervpn_windows_node_composition

package hysteria2

import (
    "context"
    "net"
    "github.com/sagernet/sing-box/routervpn/mobiletor"
    M "github.com/sagernet/sing/common/metadata"
    N "github.com/sagernet/sing/common/network"
)

type nodeMAXOrdinaryDialer struct { N.Dialer }

func (d nodeMAXOrdinaryDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
    return mobiletor.DesktopWindowsMAXControlDial(ctx, network, destination.String(), func() (net.Conn, error) {
        return d.Dialer.DialContext(ctx, network, destination)
    })
}
'''
    sources[relative] = WFP.BOOT.IDENTITY.replace_once(raw, before, after)
    for path, contents in (
            ('routervpn/mobiletor/desktop_socket_windows_max_control_overlay.go', ORDINARY_OBSERVER),
            (str(Path(relative).parent / 'routervpn_max_wfp_control_overlay.go'), helper)):
        if (source / path).exists() or (source / path).is_symlink():
            raise ValueError('MAX native observer would replace an unowned source')
        sources[path] = contents
    return sources


def mutations(source):
    result = []
    for label, relative, parent, case, witness, replacement in MAX.mutations(source):
        if label.startswith('uncaptured-outer-'):
            witness = ordinary_witness(label.removeprefix('uncaptured-outer-'))
        elif label == 'cached-selected-dns':
            witness = 'actual WFP complete MAX cached or bypassed selected DNS'
        elif label.startswith('valid-'):
            witness = 'actual WFP MAX accepted the substituted authenticated layer credential'
        result.append((label, native_parent(parent), case, witness, None, (relative, replacement)))
    kernel = WFP.mutants(source)
    for family, mode in (('TLS', 'max-tls-wg'), ('QUIC', 'max-quic-wg')):
        parent = 'TestRouterVPNDesktopNodeWindowsMAX' + family
        protocol = 'tcp' if family == 'TLS' else 'udp'
        for label, selected, group, case, witness in (
            ('legacy-max-adoption-' + family.lower(), kernel[0], FOREIGN, mode,
             'foreign MAX predecessor reached actual native encrypted startup'),
            ('late-max-handshake-' + family.lower(), late_handshake_control(kernel[1], protocol), parent, mode + '/off',
             handshake_witness(protocol)),
            ('ordinary-max-' + ('tcp' if family == 'TLS' else 'udp') + '-deny', kernel[2], parent, mode + '/off',
             'independent peer marker receipt'),
        ):
            result.append((label, group, case, witness, selected, None))
    return tuple(result)


def overlay(source, directory, *, prospective, mutation=None):
    if mutation is not None and mutation not in mutations(source):
        raise ValueError('MAX mutation is not one of its exact compiled controls')
    selected = mutation[4] if mutation is not None else None
    result = WFP.overlay(source, directory, selected)
    value = json.loads(result.read_text(encoding='utf-8'))
    mapping = value['Replace']

    def add(relative, raw, name):
        actual = source / relative
        if Path(relative).is_absolute() or '..' in Path(relative).parts or str(actual) in mapping:
            raise ValueError('MAX overlay overlaps native ownership or escapes its captured source')
        path = directory / (name + '.go')
        path.write_text(raw, encoding='utf-8')
        mapping[str(actual)] = str(path)

    if prospective:
        add(PREDICATE, prospective_predicate((source / PREDICATE).read_text(encoding='utf-8')), 'prospective-max-predicate')
    if mutation is not None and mutation[5] is not None:
        sources = observed_control_sources(source, mutation)
        for index, (relative, raw) in enumerate(sorted(sources.items())):
            add(relative, raw, 'max-native-negative-' + str(index))
    result.write_text(json.dumps(value, sort_keys=True), encoding='utf-8')
    return result


def overlay_source_hashes(source, overlay_path):
    value = json.loads(overlay_path.read_text(encoding='utf-8'))
    if set(value) != {'Replace'} or not isinstance(value['Replace'], dict) or not value['Replace']:
        raise ValueError('Windows MAX lost its exact compiled overlay')
    records = {}
    for original, replacement in value['Replace'].items():
        relative = Path(original).relative_to(source)
        path = Path(replacement)
        if '..' in relative.parts or path.parent != overlay_path.parent:
            raise ValueError('Windows MAX compiled overlay escaped its captured workspace')
        records[relative.as_posix()] = MAX.regular_digest(path)
    return records


def rejected_output(status, output, parent, case, witness):
    output = output.replace('\r\n', '\n')
    invalid = ('fatal:', 'testing: warning:', *JOIN_FAILURES)
    if any(value.casefold() in output.casefold() for value in invalid):
        raise ValueError('Windows MAX control failed its owned cleanup')
    if len(re.findall(r'^\s*--- FAIL:.*$', output, re.MULTILINE)) != 2 or re.search(r'^FAIL$', output, re.MULTILINE) is None:
        raise ValueError('Windows MAX control omitted its exact final executable failure')
    MAX.rejected_output(status, output, parent, case, witness)


def repository_identity(expected_sha=None):
    def git(*arguments):
        return subprocess.check_output(['git', *arguments], cwd=ROOT, text=True).strip()
    commit = git('rev-parse', '--verify', 'HEAD^{commit}')
    tree = git('rev-parse', '--verify', 'HEAD^{tree}')
    changes = git('status', '--porcelain', '--untracked-files=all')
    if expected_sha is not None and (re.fullmatch('[0-9a-f]{40}', expected_sha) is None or commit != expected_sha or changes):
        raise ValueError('Authoritative Windows MAX requires the exact clean repository commit')
    return {'commit': commit, 'tree': tree, 'clean': not bool(changes),
            'status_sha256': hashlib.sha256(changes.encode('utf-8')).hexdigest()}


def execute(source, pq, cache, go='go', *, prospective=False, env=None, receipt_path=None, expected_sha=None):
    if platform.system() != 'Windows' or not WFP.BOOT.IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError('Complete MAX WFP requires actual elevated Windows')
    receipt_path = WPQ.new_receipt_path(receipt_path)
    repository = repository_identity(expected_sha)
    source, before = checked_sources(Path(source))
    compiler, captured, architecture = NODE.selected_compiler(go, source, dict(os.environ if env is None else env))
    target = captured['GOOS'] + '/' + architecture
    if target not in ('windows/amd64', 'windows/arm64') or captured.get('CGO_ENABLED', '1') != '1':
        raise ValueError('Complete MAX WFP requires matching-host Windows and the real CGO ABI')
    pq, cache = Path(pq).absolute(), Path(cache).absolute()
    native = REFERENCE.BUILD.PQ.verify(pq, target)
    captured['CGO_ENABLED'] = '1'
    captured['CGO_LDFLAGS'] = shlex.join(['-static', '-L' + str(pq), *native['native_static_libs']])
    for name in ('ROUTERVPN_NODE_MAX_WFP_REFERENCE_CHILD', 'ROUTERVPN_NODE_PQ_WFP_REFERENCE_CHILD', 'ROUTERVPN_NODE_WFP_REFERENCE_CHILD'):
        captured.pop(name, None)
    race = ['-race'] if architecture == 'amd64' else []
    tools = MAX.tool_receipts(source, compiler, captured, target, cache)
    dependencies = MAX.dependency_receipt(source, compiler, captured)
    status, output = NODE.run([compiler, 'mod', 'verify'], cwd=source, env=captured, timeout=300)
    if status:
        raise ValueError('Windows MAX checksum verification failed:\n' + output[-8192:])
    packet = REFERENCE.BUILD.POLICY.AMNEZIA
    status, output = NODE.run([compiler, 'list', '-m', '-mod=readonly', '-json', packet.MODULE], cwd=source, env=captured, timeout=60)
    dependency = json.loads(output) if status == 0 else {}
    if dependency.get('Version') != packet.VERSION or dependency.get('Sum') != packet.SUM or dependency.get('Replace'):
        raise ValueError('Windows MAX requires the unmodified pinned packet implementation')
    status, output = NODE.run([compiler, 'test', *race, '-count=1', '-timeout=30s', '-v',
        WFP.RESOURCES / 'socket_peer.go', WFP.RESOURCES / 'socket_peer_test.go'], cwd=source, env=captured, timeout=90)
    print(output, end='' if output.endswith('\n') else '\n', flush=True)
    MAX.required_output(status, output, 'TestWindowsNodeObserverTransportPeer', ())
    with tempfile.TemporaryDirectory(prefix='routervpn-windows-complete-max-') as directory:
        workspace = Path(directory)
        keys = workspace / 'private' / 'keys'
        REFERENCE.generate_keys(target, cache, keys)
        key_records = REFERENCE.key_files(keys)
        key_generator = cache / REFERENCE.BUILD.PQ.TARGETS[target] / 'release/examples/native_keys.exe'
        generator_digest = MAX.regular_digest(key_generator)
        captured['ROUTERVPN_PQ_TEST_KEYS'] = str(keys)
        relay, relay_digest = NODE.build_layer_reference(compiler, workspace, captured, race)
        xray, xray_digest, xray_source, xray_records = NODE.build_xray_reference(compiler, source, workspace, captured, race)
        build = [compiler, 'test', '-c', '-p=1', '-mod=readonly', '-tags=' + TAGS, *race, '-ldflags=-checklinkname=0']
        controls, suites = [], []
        with REFERENCE.test_sources(source):
            compiled_overlays = {}

            def compile_in(name, prospective, mutation=None):
                owned = workspace / name
                owned.mkdir()
                selected = overlay(source, owned, prospective=prospective, mutation=mutation)
                before_overlay = overlay_source_hashes(source, selected)
                binary = owned / 'complete-max-native.test.exe'
                status, output = NODE.run([*build, '-overlay=' + str(selected), '-o', binary, './protocol/routervpnpq'], cwd=source, env=captured, timeout=600)
                if status:
                    raise ValueError('Windows MAX compilation failed: ' + name + '\n' + output[-32768:])
                if overlay_source_hashes(source, selected) != before_overlay:
                    raise ValueError('Windows MAX overlay changed during native compilation: ' + name)
                compiled_overlays[name] = before_overlay
                return binary

            def run_suite(binary, parent, cases, timeout):
                digest = MAX.regular_digest(binary)
                status, output = NODE.run([binary, '-test.run=^' + parent + '$', '-test.count=1', '-test.timeout=' + str(timeout) + 's', '-test.v'],
                                          cwd=source, env=captured, timeout=timeout + 15)
                print(output, end='' if output.endswith('\n') else '\n', flush=True)
                MAX.required_output(status, output, parent, cases)
                if MAX.regular_digest(binary) != digest:
                    raise ValueError('Windows MAX executable changed during native execution')
                suites.append({'parent': parent, 'cases': cases, 'binary_sha256': digest,
                               'output_sha256': hashlib.sha256(output.encode('utf-8')).hexdigest()})

            if prospective:
                closed = compile_in('unmodified-closed-capability', False)
                run_suite(closed, CLOSED, MODES, 600)
                closed.unlink()
            binary = compile_in('native-composition', prospective)
            digest = MAX.regular_digest(binary)
            run_suite(binary, OPEN, (), 15)
            run_suite(binary, MARKERS, ('bounded-input', 'unarmed-and-wrong-owner', 'encrypted-fragments', 'exact-armed-stream'), 30)
            status, output = NODE.run([binary, '-test.run=^Test(RealPinnedFactory|RealFactory|RealPQTraffic)|^' + STARTUP_RECORDS + '$', '-test.v', '-test.count=1', '-test.timeout=120s'],
                                      cwd=source, env=captured, timeout=135)
            print(output, end='' if output.endswith('\n') else '\n', flush=True)
            for parent in MAX.PQ.NATIVE_CASES:
                MAX.required_output(status, output, parent, ('v2', 'v3') if parent == 'TestRealPinnedFactoryExchangeAndRekey' else ())
            MAX.required_output(status, output, STARTUP_RECORDS, ())
            startup_record_output = hashlib.sha256(output.encode('utf-8')).hexdigest()
            for family in MAX.FAMILIES:
                for suffix, cases, timeout in (('', MAX.TRAFFIC[family], 600), ('Credentials', MAX.CREDENTIALS[family], 1800)):
                    run_suite(binary, 'TestRouterVPNDesktopNodeWindowsMAX' + family + suffix, cases, timeout)
            run_suite(binary, SUCCESSION, tuple(mode + '/' + layer for mode in MODES for layer in LAYERS), 1800)
            run_suite(binary, FOREIGN, MODES, 600)
            for mutation in mutations(source):
                name, parent, case, witness, _, replacement = mutation
                negative = compile_in(name, prospective, mutation)
                negative_digest = MAX.regular_digest(negative)
                status, output = NODE.run([negative, '-test.run=' + MAX.selector(parent, case), '-test.count=1', '-test.timeout=90s', '-test.v'],
                                          cwd=source, env=captured, timeout=105)
                try:
                    rejected_output(status, output, parent, case, witness)
                except ValueError as error:
                    raise ValueError(str(error) + ': ' + name + '\n' + output[-16384:]) from error
                if MAX.regular_digest(negative) != negative_digest:
                    raise ValueError('Windows MAX control executable changed')
                if overlay_source_hashes(source, negative.parent / 'overlay.json') != compiled_overlays[name]:
                    raise ValueError('Windows MAX control overlay changed during execution')
                controls.append({'name': name, 'parent': parent, 'case': case, 'witness': witness,
                                 'binary_sha256': negative_digest, 'exit_status': status,
                                 'source': replacement[0] if replacement else mutation[4][1],
                                 'replacement_sha256': hashlib.sha256((replacement[1] if replacement else mutation[4][4]).encode()).hexdigest(),
                                 'source_overlay_sha256': compiled_overlays[name],
                                 'output_sha256': hashlib.sha256(output.encode()).hexdigest()})
                negative.unlink()
                print('Rejected actual Windows complete MAX control: ' + name + ' output_sha256=' + controls[-1]['output_sha256'], flush=True)
            if MAX.regular_digest(binary) != digest or REFERENCE.key_files(keys) != key_records or MAX.regular_digest(key_generator) != generator_digest or MAX.regular_digest(relay) != relay_digest or MAX.regular_digest(xray) != xray_digest or NODE.xray_reference_sources(xray_source) != xray_records:
                raise ValueError('Windows MAX keys, reference executables or source changed')
        if checked_sources(source)[1] != before or REFERENCE.BUILD.PQ.verify(pq, target) != native or MAX.tool_receipts(source, compiler, captured, target, cache) != tools or MAX.dependency_receipt(source, compiler, captured) != dependencies:
            raise ValueError('Windows MAX captured source, archive or tool identity changed')
        result = {'schema': 1, 'target': target, 'source': before, 'repository': repository,
                  'native_pq': native, 'tools': tools,
                  'prepared_quic_dependencies': dependencies, 'test_binary_sha256': digest,
                  'relay_sha256': relay_digest, 'xray_sha256': xray_digest,
                  'xray_pin': NODE.PREP.RELAY.XRAY.XRAY_PIN, 'xray_source': xray_records,
                  'key_generator_sha256': generator_digest, 'fresh_independent_keypairs': 3,
                  'prospective': prospective, 'current_closed_admission_proved': prospective,
                  'prospective_predicate': {'before': PROSPECTIVE_BEFORE, 'after': PROSPECTIVE_AFTER} if prospective else None,
                  'traffic_cases': MAX.TRAFFIC, 'credential_cases': MAX.CREDENTIALS,
                  'succession_cases': tuple(mode + '/' + layer for mode in MODES for layer in LAYERS),
                  'foreign_predecessor_cases': MODES, 'native_abi_cases': MAX.PQ.NATIVE_CASES,
                  'startup_record_case': STARTUP_RECORDS, 'startup_record_output_sha256': startup_record_output,
                  'suites': suites, 'compiled_negative_controls': controls,
                  'native_firewall': 'actual-appid-scoped-wfp', 'native_socket_source': 'actual-isolated-token',
                  'tun': 'modeled', 'public_admission': 'separate' if prospective else 'shipping-predicate', 'device_acceptance': 'separate'}
    if workspace.exists() or workspace.is_symlink():
        raise ValueError('Windows MAX retained its disposable private workspace')
    if repository_identity(expected_sha) != repository:
        raise ValueError('Windows MAX repository identity changed before final acknowledgment')
    result['private_key_workspace_removed'] = True
    WPQ.publish_receipt(receipt_path, result, workspace)
    print('Actual Windows WFP, complete four-family MAX, 12 Start Layer paths, 48 credential cases, native rekey, selected Home DNS, joined reversal and compiled controls passed; TUN, public host and device acceptance remain separate.', flush=True)
    return result


def standalone(go='go', *, prospective=False, receipt_path=None, expected_sha=None):
    if platform.system() != 'Windows' or not WFP.BOOT.IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError('Standalone complete MAX requires actual elevated Windows')
    compiler, captured, architecture = NODE.selected_compiler(go, ROOT, dict(os.environ))
    target = 'windows/' + architecture
    if captured.get('CGO_ENABLED', '1') != '1':
        raise ValueError('Standalone MAX cannot disable its native cryptographic ABI')
    receipt_path = WPQ.new_receipt_path(receipt_path)
    captured['CGO_ENABLED'] = '1'
    native = REFERENCE.BUILD
    previous = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix='routervpn-windows-max-core-') as directory:
        workspace = Path(directory)
        source, xray, pq, cache = (workspace / name for name in ('core', 'xray', 'pq', 'cargo-cache'))
        try:
            os.environ.clear()
            os.environ.update(captured)
            native.checkout(source, 'https://github.com/SagerNet/sing-box.git', native.PIN)
            native.checkout(xray, 'https://github.com/XTLS/Xray-core.git', native.POLICY.XRAY.XRAY_PIN)
            native.pristine(source, native.PIN)
            native.pristine(xray, native.POLICY.XRAY.XRAY_PIN)
            native.PQ.build(target, pq, cache)
            native.POLICY.prepare_native(source, xray)
            native.PERFORMANCE.prepare(source)
            native.OPENVPN.prepare(source)
            native.EXTERNAL.prepare(source, go=str(compiler), env=captured)
            native.BUFFERS.prepare(source)
            native.run([compiler, 'mod', 'tidy'], cwd=source, env=captured)
            native.run([compiler, 'mod', 'verify'], cwd=source, env=captured)
            native.POLICY.AMNEZIA.verify(source)
            result = execute(source, pq, cache, str(compiler), prospective=prospective, env=captured, expected_sha=expected_sha)
        finally:
            os.environ.clear()
            os.environ.update(previous)
    if repository_identity(expected_sha) != result['repository']:
        raise ValueError('Standalone Windows MAX source changed before cleanup acknowledgment')
    result['standalone_source_workspace_removed'] = True
    WPQ.publish_receipt(receipt_path, result, workspace)
    return result


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, nargs='?')
    parser.add_argument('pq', type=Path, nargs='?')
    parser.add_argument('--cache', type=Path, default=ROOT / 'dist/.native-pq-cache')
    parser.add_argument('--go', default='go')
    parser.add_argument('--prospective', action='store_true')
    parser.add_argument('--standalone', action='store_true')
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--sha', help='require this exact clean repository commit for authoritative evidence')
    arguments = parser.parse_args()
    if arguments.standalone:
        if arguments.source is not None or arguments.pq is not None:
            parser.error('--standalone owns its exact source and native archive')
        standalone(arguments.go, prospective=arguments.prospective, receipt_path=arguments.receipt, expected_sha=arguments.sha)
    else:
        if arguments.source is None or arguments.pq is None:
            parser.error('an exact prepared source and native PQ archive are required')
        execute(arguments.source, arguments.pq, arguments.cache, arguments.go,
                prospective=arguments.prospective, receipt_path=arguments.receipt, expected_sha=arguments.sha)
