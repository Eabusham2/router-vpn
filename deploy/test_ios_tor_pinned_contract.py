#!/usr/bin/env python3
"""Exercise the Apple native gate's source, matrix and real-engine boundaries.

Only command execution is doubled here. The separate shipping gate executes
the real Swift compilers, native Libbox constructor and C Tor ABI.
"""
from pathlib import Path
import contextlib
import hashlib
import importlib.util
import io
import json
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('apple_tor_native_gate', ROOT/'deploy/test_ios_tor_pinned.py')
GATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(GATE)
REGISTRY = (b'package include\nimport (\n\t"github.com/sagernet/sing-box/protocol/socks"\n'
            b'\t"github.com/sagernet/sing-box/protocol/routervpntor"\n)\n'
            b'func OutboundRegistry() {\n\tsocks.RegisterOutbound(registry)\n'
            b'\troutervpntor.RegisterOutbound(registry)\n}\n')


def populate(folder, execution='local'):
    for name, (mode, layer, kind) in GATE.cases(execution).items():
        entry = folder/name; entry.mkdir()
        (entry/'fixture.json').write_text(json.dumps(dict(mode=mode, layer=layer, transport=kind, session='captured-session')))
        owner = {'type': 'routervpn-tor', 'session_id': 'captured-session'}
        if execution == 'server':
            owner = dict(type='routervpn-server-tor', tag='routervpn-tor-exit', session_id='captured-session',
                         profile='{}', entry_config='{}', entry_profile='{}')
        elif mode.startswith('external-'):
            protocol = mode.removeprefix('external-')
            owner.update(tag='routervpn-tor-exit', detour='custom-exit',
                external_tor_profile=json.dumps(dict(id='tor-exit', multihop_enabled=True,
                    multihop_entry_id='ordinary-entry', multihop_entry_mode=protocol, multihop_exit_id='tor-exit',
                    multihop_exit_mode='tor' if kind == 'tor' else 'tor-bridge', multihop_execution='local')),
                external_predecessor_profile=json.dumps(dict(id='ordinary-entry', node_kind='external',
                    external=dict(protocol=protocol, expected_public_ip='203.0.113.88'))),
                external_predecessor_config=json.dumps(dict(route=dict(final='custom-exit'))))
        (entry/'sing-box.json').write_text(json.dumps({'outbounds': [owner]}))
        if mode in ('naive-h2', 'naive-h3', 'hysteria2'):
            (entry/'trust.pem').write_text('exact test-only trust asset')
        if mode in ('reality-vision', 'reality-pq-vision', 'reality-xhttp'):
            (entry/'xray.json').write_text('{}')
    report = dict(schema=1, graphs=396 if execution == 'local' else 342,
                  home_dns_combinations=285 if execution == 'local' else 5,
                  profile_policy_combinations=320, public_tor_traffic=False,
                  native_handles='boundary doubles',
                  sources={str(path.relative_to(ROOT)): GATE.sha(path) for path in GATE.host_sources(execution)})
    if execution == 'server':
        report['execution'] = execution
    else:
        report.update(router_tor_graphs=348, ordinary_tor_graphs=48)
    (folder/'source-evidence.json').write_text(json.dumps(report))


def populate_padding(folder):
    # Command-boundary fixtures only. The shipping Swift emitter and native
    # source getter are exercised by the actual pinned gate, not reconstructed
    # by this runner ownership contract.
    for index, (name, (mode, layer, kind, rate)) in enumerate(GATE.padding_cases().items()):
        entry = folder/name; entry.mkdir()
        session = 'padding-session-'+str(index)
        selected = dict(id='tor-exit', daita_enabled=True, daita_rate_kbps=rate)
        source = {}
        if mode != 'direct':
            selected.update(multihop_execution='local', multihop_entry_id='entry', multihop_entry_mode=mode.removeprefix('external-'))
            previous = dict(id='entry', node_kind='router-vpn', start_layer=layer)
            if mode.startswith('external-'):
                previous.update(node_kind='external', external=dict(protocol=mode.removeprefix('external-')))
            source.update(predecessor_profile=json.dumps(previous), predecessor_config='{}')
        source['profile'] = json.dumps(selected)
        owner = dict(type='routervpn-tor', tag='routervpn-tor-exit', session_id=session, padding_source=source)
        (entry/'sing-box.json').write_text(json.dumps(dict(outbounds=[owner])))
        (entry/'fixture.json').write_text(json.dumps(dict(mode=mode, layer=layer, transport=kind, rate_kbps=rate,
            session=session, source_sha256='1'*64)))
        if mode in ('naive-h2', 'naive-h3', 'hysteria2'):
            (entry/'trust.pem').write_text('exact test-only trust asset')
        if mode.startswith('reality-'):
            (entry/'xray.json').write_text('{}')
    (folder/'source-evidence.json').write_text(json.dumps(dict(schema=1, execution='local', padding_enabled=True,
        graphs=528, private_graphs=456, direct_graphs=8, ordinary_graphs=64, rates_kbps=[0,32,64,192],
        entry_layers=list(GATE.LAYERS), public_tor_traffic=False, native_handles='boundary doubles',
        sources={str(path.relative_to(ROOT)): GATE.sha(path) for path in GATE.host_sources()})))


class AppleTorNativeGate(unittest.TestCase):
    def test_enabled_matrix_preserves_all_layers_sources_and_rates(self):
        self.assertEqual(len(GATE.native_cases()), 738)
        self.assertEqual(len(GATE.padding_cases()), 528)
        for fault in ('missing', 'extra', 'stale', 'rate', 'bool-rate', 'server', 'session', 'duplicate-session',
                      'source-sha', 'lost-source', 'missing-entry', 'foreign-entry', 'private-authority', 'layer', 'borrowed-direct'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary); populate_padding(folder)
                self.assertGreater(len(GATE.require_padding_matrix(folder)), 1056)
                entry = folder/'external-socks5-off-tor-32'
                graph = entry/'sing-box.json'; metadata = entry/'fixture.json'
                body = json.loads(graph.read_text()); owner = body['outbounds'][0]
                source = owner['padding_source']; selected = json.loads(source['profile'])
                if fault == 'missing':
                    graph.unlink()
                elif fault == 'extra':
                    (folder/'unowned').mkdir()
                elif fault == 'stale':
                    evidence = json.loads((folder/'source-evidence.json').read_text()); evidence['sources']['deploy/test_ios_tor_profile.py'] = '0'*64
                    (folder/'source-evidence.json').write_text(json.dumps(evidence))
                elif fault in ('rate', 'bool-rate', 'server'):
                    if fault == 'server': selected['multihop_execution'] = 'server'
                    else: selected['daita_rate_kbps'] = 64 if fault == 'rate' else True
                    source['profile'] = json.dumps(selected)
                elif fault == 'session': owner['session_id'] = 'foreign-owner'
                elif fault == 'duplicate-session':
                    reference = folder/'external-socks5-off-tor-64'
                    fixture = json.loads((reference/'fixture.json').read_text()); duplicate = json.loads(metadata.read_text())
                    duplicate['session'] = fixture['session']; metadata.write_text(json.dumps(duplicate)); owner['session_id'] = fixture['session']
                elif fault == 'source-sha':
                    fixture = json.loads(metadata.read_text()); fixture['source_sha256'] = 'claimed-hash'; metadata.write_text(json.dumps(fixture))
                elif fault == 'lost-source': del owner['padding_source']
                elif fault == 'missing-entry': del source['predecessor_config']
                elif fault in ('foreign-entry', 'private-authority'):
                    previous = json.loads(source['predecessor_profile'])
                    if fault == 'foreign-entry': previous['id'] = 'replacement-entry'
                    else: previous['api_token'] = 'foreign-private-token'
                    source['predecessor_profile'] = json.dumps(previous)
                elif fault == 'layer':
                    graph = folder/'wg-aes-256-gcm-tor-32/sing-box.json'; body = json.loads(graph.read_text())
                    source = body['outbounds'][0]['padding_source']; previous = json.loads(source['predecessor_profile'])
                    previous['start_layer'] = 'off'; source['predecessor_profile'] = json.dumps(previous)
                else:
                    graph = folder/'direct-off-tor-32/sing-box.json'; body = json.loads(graph.read_text())
                    body['outbounds'][0]['padding_source']['predecessor_profile'] = '{}'
                if fault != 'missing': graph.write_text(json.dumps(body))
                with self.assertRaises((ValueError, FileNotFoundError)):
                    GATE.require_padding_matrix(folder)

    def test_exact_matrix_asset_and_session_ownership(self):
        mutations = ('missing', 'extra', 'renamed', 'empty', 'oversized', 'linked-root',
                     'linked-graph', 'linked-asset', 'missing-trust', 'wrong-session', 'wrong-mode', 'missing-home-dns', 'stale-source',
                     'missing-openvpn-binding', 'changed-openvpn-binding', 'extra-source')
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); folder = root/'graphs'; folder.mkdir(); populate(folder)
                self.assertEqual(len(GATE.require_matrix(folder)), 901)
                entry = folder/'naive-h3-aes-256-gcm-snowflake'
                graph = entry/'sing-box.json'
                if mutation == 'missing': graph.unlink()
                elif mutation == 'extra': (folder/'extra').mkdir()
                elif mutation == 'renamed': entry.rename(folder/'unknown-profile')
                elif mutation == 'empty': graph.write_bytes(b'')
                elif mutation == 'oversized':
                    with graph.open('wb') as stream: stream.truncate(4*1024*1024+1)
                elif mutation == 'linked-root':
                    alias = root/'alias'; alias.symlink_to(folder, target_is_directory=True); folder = alias
                elif mutation == 'linked-graph':
                    preserved = root/'preserved'; entry.rename(preserved); entry.symlink_to(preserved, target_is_directory=True)
                elif mutation == 'linked-asset':
                    graph.unlink(); graph.symlink_to(folder/'tor-does-not-exist')
                elif mutation == 'missing-trust': (entry/'trust.pem').unlink()
                elif mutation == 'wrong-session':
                    graph.write_text(json.dumps({'outbounds': [{'type': 'routervpn-tor', 'session_id': 'another-session'}]}))
                elif mutation == 'wrong-mode':
                    data = json.loads((entry/'fixture.json').read_text()); data['mode'] = 'wg'
                    (entry/'fixture.json').write_text(json.dumps(data))
                elif mutation == 'missing-home-dns':
                    data = json.loads((folder/'source-evidence.json').read_text()); del data['home_dns_combinations']
                    (folder/'source-evidence.json').write_text(json.dumps(data))
                elif mutation in ('missing-openvpn-binding', 'changed-openvpn-binding', 'extra-source'):
                    data = json.loads((folder/'source-evidence.json').read_text())
                    key = 'mobile/routervpn_openvpn.go'
                    self.assertIn(key, data['sources'])
                    if mutation == 'missing-openvpn-binding':
                        del data['sources'][key]
                    elif mutation == 'changed-openvpn-binding':
                        data['sources'][key] = '0'*64
                    else:
                        data['sources']['unowned-bridge.go'] = '0'*64
                    (folder/'source-evidence.json').write_text(json.dumps(data))
                else:
                    data = json.loads((folder/'source-evidence.json').read_text())
                    data['sources']['deploy/test_ios_tor_profile.py'] = '0'*64
                    (folder/'source-evidence.json').write_text(json.dumps(data))
                with self.assertRaises((ValueError, FileNotFoundError)):
                    GATE.require_matrix(folder)

    def test_missing_engine_overlay_removes_only_exact_registration(self):
        changed = GATE.missing_tor_registry(REGISTRY)
        self.assertEqual(changed, REGISTRY.replace(b'\t"github.com/sagernet/sing-box/protocol/routervpntor"\n', b'')
                         .replace(b'\troutervpntor.RegisterOutbound(registry)\n', b''))
        self.assertIn(b'socks.RegisterOutbound', changed)
        for source in (changed, REGISTRY+REGISTRY, REGISTRY.replace(b'routervpntor.RegisterOutbound', b'other.RegisterOutbound')):
            with self.assertRaises(ValueError): GATE.missing_tor_registry(source)

    def test_ordinary_tor_matrix_retains_all_original_graphs_and_exact_source_roles(self):
        self.assertIn('with_openvpn', GATE.TAGS.split(','))
        self.assertEqual(len(GATE.cases()), 396)
        self.assertEqual(len(GATE.cases('server')), 342)
        self.assertEqual(sum(name.startswith('external-') for name in GATE.cases()), 48)
        faults = ('missing-count', 'wrong-router-count', 'missing-ordinary', 'missing-profile', 'wrong-kind',
                  'wrong-protocol', 'wrong-entry', 'wrong-mode', 'private-api', 'private-token', 'server',
                  'unknown-source', 'foreign-route', 'borrowed-private')
        for fault in faults:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary); populate(folder)
                graph = folder/'external-socks5-off-tor/sing-box.json'
                body = json.loads(graph.read_text()); owner = body['outbounds'][0]
                entry = json.loads(owner['external_predecessor_profile'])
                selected = json.loads(owner['external_tor_profile'])
                if fault in ('missing-count', 'wrong-router-count'):
                    report = json.loads((folder/'source-evidence.json').read_text())
                    if fault == 'missing-count': del report['ordinary_tor_graphs']
                    else: report['router_tor_graphs'] = 342
                    (folder/'source-evidence.json').write_text(json.dumps(report))
                elif fault == 'missing-ordinary': graph.unlink()
                elif fault == 'missing-profile': del owner['external_predecessor_profile']
                elif fault == 'wrong-kind': entry['node_kind'] = 'router-vpn'
                elif fault == 'wrong-protocol': entry['external']['protocol'] = 'wireguard'
                elif fault == 'wrong-entry': selected['multihop_entry_id'] = 'foreign-entry'
                elif fault == 'wrong-mode': selected['multihop_entry_mode'] = 'wireguard'
                elif fault == 'private-api': entry['router_api'] = 'http://10.77.0.1:8787'
                elif fault == 'private-token': entry['api_token'] = 'unowned-private-credential'
                elif fault == 'server': selected['multihop_execution'] = 'server'
                elif fault == 'unknown-source': owner['external_predecessor_config'] = 'null'
                elif fault == 'foreign-route': owner['external_predecessor_config'] = json.dumps(dict(route=dict(final='direct')))
                else:
                    private = folder/'wg-off-tor/sing-box.json'
                    private.write_text(json.dumps(body))
                if fault != 'missing-profile': owner['external_predecessor_profile'] = json.dumps(entry)
                owner['external_tor_profile'] = json.dumps(selected)
                if fault != 'missing-ordinary': graph.write_text(json.dumps(body))
                with self.assertRaises((ValueError, FileNotFoundError)):
                    GATE.require_matrix(folder)

    def test_server_matrix_rejects_local_owner_and_changed_private_inputs(self):
        for fault in ('local', 'extra-owner', 'entry', 'option', 'source', 'execution', 'direct', 'session'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary); populate(folder, 'server')
                self.assertEqual(len(GATE.require_matrix(folder, 'server')), 793)
                graph = folder/'wg-off-tor/sing-box.json'
                body = json.loads(graph.read_text()); owner = body['outbounds'][0]
                if fault == 'local': owner['type'] = 'routervpn-tor'
                elif fault == 'extra-owner': body['outbounds'].append(dict(type='routervpn-tor', session_id='captured-session'))
                elif fault == 'entry': owner['entry_profile'] = 'null'
                elif fault == 'option': owner['detour'] = 'direct'
                elif fault == 'session': owner['session_id'] = 'replacement'
                elif fault == 'direct': (folder/'direct-off-tor').mkdir()
                else:
                    report = json.loads((folder/'source-evidence.json').read_text())
                    if fault == 'source': del report['sources']['deploy/test_ios_tor_server_profile.py']
                    else: report['execution'] = 'local'
                    (folder/'source-evidence.json').write_text(json.dumps(report))
                graph.write_text(json.dumps(body))
                with self.assertRaises(ValueError): GATE.require_matrix(folder, 'server')

    def exercise(self, fault=''):
        with tempfile.TemporaryDirectory(prefix='apple-tor-gate-contract-') as temporary:
            root = Path(temporary); vendor = root/'vendor'; package = root/'package'
            (vendor/'experimental/libbox').mkdir(parents=True); (vendor/'include').mkdir()
            (package/'lib').mkdir(parents=True)
            (package/'lib/libroutervpn_tor.so').write_bytes(b'package boundary double')
            for name in ('go.mod', 'go.sum'): (vendor/name).write_text('exact module fixture')
            registry = vendor/'include/registry.go'; registry.write_bytes(REGISTRY)
            target = vendor/'experimental/libbox/routervpn_tor_ios_graph_test.go'
            padding_target = vendor/'experimental/libbox/routervpn_tor_ios_padding_graph_test.go'
            if fault == 'occupied': target.write_text('existing owner')
            calls, folders = [], []

            def command(arguments, *, cwd, env, timeout, **kwargs):
                self.assertGreater(timeout, 0)
                calls.append(arguments)
                if arguments[1] in (str(GATE.FIXTURE), str(GATE.SERVER_FIXTURE)):
                    execution = 'server' if arguments[1] == str(GATE.SERVER_FIXTURE) else 'local'
                    self.assertTrue(kwargs['check'])
                    self.assertFalse(target.exists())
                    self.assertNotIn('CGO_LDFLAGS', env, 'C Tor flags leaked into ordinary host fixture generators')
                    if fault == ('server-swift' if execution == 'server' else 'swift'): raise subprocess.CalledProcessError(1, arguments)
                    folder = Path(arguments[arguments.index('--output')+1]); folders.append(folder)
                    populate(folder, execution)
                    if execution == 'local':
                        padding = Path(arguments[arguments.index('--padding-output')+1]); folders.append(padding)
                        populate_padding(padding)
                        if fault == 'padding-short': (padding/'direct-off-tor-32/sing-box.json').unlink()
                    if fault == 'short' and execution == 'local': (folder/'direct-off-tor/sing-box.json').unlink()
                    if fault == 'server-short' and execution == 'server': (folder/'wg-off-tor/sing-box.json').unlink()
                    return SimpleNamespace(returncode=0)
                self.assertEqual(Path(cwd), vendor)
                self.assertEqual(env['CGO_LDFLAGS'], 'verified-native-library-and-rpath')
                self.assertTrue(Path(env['ROUTERVPN_IOS_TOR_SERVER_GRAPHS']).is_dir())
                self.assertEqual(target.read_bytes(), GATE.TEMPLATE.read_bytes())
                self.assertEqual(padding_target.read_bytes(), GATE.PADDING_TEMPLATE.read_bytes())
                self.assertTrue(Path(env['ROUTERVPN_IOS_LOCAL_PADDING_GRAPHS']).is_dir())
                self.assertEqual(Path(env['ROUTERVPN_IOS_TOR_STATE']).parent, folders[0].parent)
                for template in (GATE.TEMPLATE, GATE.PADDING_TEMPLATE):
                    self.assertIn('os.Getenv("ROUTERVPN_IOS_TOR_STATE")', template.read_text())
                self.assertEqual(arguments[arguments.index('-tags')+1], GATE.TAGS)
                self.assertIn('-mod=readonly', arguments)
                self.assertIn('-count=1', arguments)
                self.assertEqual(arguments[arguments.index('-run')+1], '^('+GATE.TEST+'|'+GATE.PADDING_TEST+')$')
                self.assertEqual(registry.read_bytes(), REGISTRY)
                missing = env.get('ROUTERVPN_IOS_TOR_MISSING_ENGINE') == '1'
                if missing:
                    overlay = json.loads(Path(arguments[arguments.index('-overlay')+1]).read_text())
                    replacement = Path(overlay['Replace'][str(registry)])
                    self.assertEqual(replacement.read_bytes(), GATE.missing_tor_registry(REGISTRY))
                else:
                    self.assertNotIn('-overlay', arguments)
                failed = fault == ('negative' if missing else 'native')
                names = sorted(GATE.native_cases())
                if fault == 'skipped' and missing: names.pop()
                for name in names:
                    kwargs['stdout'].write(json.dumps({'Action': 'pass', 'Test': GATE.TEST+'/'+name})+'\n')
                padding_names = sorted(GATE.padding_cases())
                if fault == 'padding-skipped' and missing: padding_names.pop()
                for name in padding_names:
                    kwargs['stdout'].write(json.dumps({'Action': 'pass', 'Test': GATE.PADDING_TEST+'/'+name})+'\n')
                return SimpleNamespace(returncode=1 if failed else 0)

            with mock.patch.object(GATE.subprocess, 'check_output', return_value='wrong' if fault == 'pin' else GATE.PIN), \
                 mock.patch.object(GATE.TOR.TORPACK.PACKAGE, 'verify', return_value={'platform': 'host-test'}), \
                 mock.patch.object(GATE, 'verify_prepared'), \
                 mock.patch.object(GATE, 'host_environment', return_value={'CGO_ENABLED': '1', 'CGO_LDFLAGS': 'verified-native-library-and-rpath'}), \
                 mock.patch.object(GATE, 'source_hashes', return_value={'source': 'fixed'}), \
                 mock.patch.object(GATE.subprocess, 'run', side_effect=command), contextlib.redirect_stdout(io.StringIO()):
                if fault:
                    with self.assertRaises((ValueError, FileNotFoundError, RuntimeError, subprocess.CalledProcessError)):
                        GATE.run(vendor, package, 'go')
                else:
                    GATE.run(vendor, package, 'go')
            self.assertEqual(registry.read_bytes(), REGISTRY, 'negative gate changed shipping registration')
            if fault == 'occupied': self.assertEqual(target.read_text(), 'existing owner')
            else: self.assertFalse(target.exists(), 'test-only source survived completion or failure')
            self.assertFalse(padding_target.exists(), 'padding test-only source survived completion or failure')
            for folder in folders: self.assertFalse(folder.exists(), 'temporary graph export survived')
            return len(calls)

    def test_actual_runner_requires_swift_then_both_native_passes(self):
        self.assertEqual(self.exercise(), 4)

    def test_source_and_host_failures_stop_before_native(self):
        for fault, count in (('pin', 0), ('occupied', 0), ('swift', 1), ('short', 1), ('padding-short', 1), ('server-swift', 2), ('server-short', 2)):
            with self.subTest(fault=fault): self.assertEqual(self.exercise(fault), count)

    def test_native_failure_and_skipped_negative_are_fatal(self):
        for fault, count in (('native', 3), ('negative', 4), ('skipped', 4), ('padding-skipped', 4)):
            with self.subTest(fault=fault): self.assertEqual(self.exercise(fault), count)

    def test_prepared_gate_rejects_stale_source_and_fake_c_loader(self):
        copied = {'protocol/routervpntor/owned.go': b'package owned\n'}
        dns = (ROOT/'mobile/toroutbound/dns_adapter.go.tmpl').read_bytes()
        pack = GATE.TOR.TORPACK
        loader = {'routervpn/nativetor/'+name: (pack.SOURCE/(name+'.tmpl')).read_bytes()
                  for name in ('native.go', 'backend.go', 'unavailable.go')}
        loader['routervpn/nativetor/routervpn_tor_host.h'] = (ROOT/'mobile/tor/routervpn_tor_host.h').read_bytes()
        loader['experimental/libbox/routervpn_tor_native.go'] = (pack.SOURCE/'bridge.go.tmpl').read_bytes()
        for mutation in ('source', 'stale', 'dns', 'loader', 'loader-record'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                vendor = Path(temporary)
                for relative, data in {**copied, **loader, 'dns/transport_adapter.go': dns}.items():
                    path = vendor/relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
                tor_record = dict(schema=1, core=GATE.PIN, source_sha256='current',
                    dns_adapter_sha256=hashlib.sha256(dns).hexdigest(),
                    files={name: hashlib.sha256(data).hexdigest() for name, data in copied.items()})
                loader_record = dict(schema=1, core=GATE.PIN, source_sha256=pack.digest(),
                    files={name: hashlib.sha256(data).hexdigest() for name, data in loader.items()})
                (vendor/GATE.TOR.OWNER).write_text(json.dumps(tor_record))
                (vendor/pack.OWNER).write_text(json.dumps(loader_record))
                with mock.patch.object(GATE.TOR, 'copies', return_value=copied), mock.patch.object(GATE.TOR, 'digest', return_value='current'):
                    GATE.verify_prepared(vendor)
                    if mutation == 'source': (vendor/'protocol/routervpntor/owned.go').write_text('different native owner')
                    elif mutation == 'stale':
                        tor_record['source_sha256'] = 'stale'; (vendor/GATE.TOR.OWNER).write_text(json.dumps(tor_record))
                    elif mutation == 'dns': (vendor/'dns/transport_adapter.go').write_text('different resolver owner')
                    elif mutation == 'loader': (vendor/'routervpn/nativetor/backend.go').write_text('fake Tor ABI')
                    else:
                        loader_record['files']['routervpn/nativetor/backend.go'] = '0'*64
                        (vendor/pack.OWNER).write_text(json.dumps(loader_record))
                    with self.assertRaises(ValueError): GATE.verify_prepared(vendor)

    def test_digest_captures_actual_host_and_native_inputs(self):
        paths = GATE.inputs(); self.assertEqual(len(paths), len(set(paths)))
        before = GATE.digest(); original = Path.read_bytes
        for name in ('internal/mobiletor/profile.go', 'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift',
                     'deploy/test_ios_tor_profile.py', 'mobile/routervpn_tor_ios_graph_test.go.tmpl',
                     'mobile/routervpn_tor_ios_padding_graph_test.go.tmpl',
                     'ios/RouterVPN/PacketTunnel/RouterVPNTorPaddingReceipt.swift',
                     'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift',
                     'deploy/test_ios_libbox_delivery.py',
                     'deploy/native_tor_graph_host.py', 'mobile/torpack/backend.go.tmpl', 'mobile/torpt/SOURCE_LOCK.json'):
            changed = ROOT/name; self.assertIn(changed, paths)
            with mock.patch.object(Path, 'read_bytes', lambda path: original(path)+(b'changed' if path == changed else b'')):
                self.assertNotEqual(before, GATE.digest())
        for name in ('ios/RouterVPN/PacketTunnel/RouterVPNTorPaddingReceipt.swift',
                     'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift', 'deploy/test_ios_libbox_delivery.py'):
            self.assertNotIn(ROOT/name, GATE.host_sources(), 'separate delivery gate was falsely presented as graph-emitter source')
        with mock.patch.object(GATE.HOST, 'environment', return_value={}) as selected:
            GATE.host_environment('go', Path('/host/libroutervpn_tor.so'), '/llvm/clang')
        selected.assert_called_once_with('go', Path('/host/libroutervpn_tor.so'), '/llvm/clang', require_swift=True)

    def test_linux_build_runs_gate_before_mobile_link_and_tracks_apple_changes(self):
        shell = (ROOT/'android/build-sing-box-libbox.sh').read_text()
        call = 'test_ios_tor_pinned.py" --vendor "$VENDOR" --native-package "$TOR_HOST_PACKAGE"'
        self.assertIn(call, shell)
        self.assertIn('--output "$TOR_GATE_PARENT/apple-graphs"', shell)
        self.assertLess(shell.index(call), shell.index('go_retry run ./cmd/internal/build_libbox -target android'))
        self.assertLess(shell.index('APPLE_TOR_GRAPH_SHA='), shell.index('if [[ -s "$AAR"'))
        self.assertIn('"$OPENVPN_SHA" "$APPLE_TOR_GRAPH_SHA"', shell)
        gradle = (ROOT/'android/app/build.gradle').read_text()
        for name in ('test_ios_tor_pinned.py', 'test_ios_tor_pinned_contract.py',
                     'test_ios_tor_profile.py', 'native_tor_graph_host.py'):
            self.assertIn("rootProject.file('../deploy/"+name+"')", gradle)
        self.assertIn("rootProject.fileTree('../mobile')", gradle)
        for name in ('App', 'PacketTunnel'):
            self.assertIn("rootProject.fileTree('../ios/RouterVPN/"+name+"')", gradle)
        workflow = (ROOT/'.github/workflows/android-combined-runtime.yml').read_text()
        self.assertIn('runs-on: ubuntu-24.04', workflow)


if __name__ == '__main__':
    unittest.main()
