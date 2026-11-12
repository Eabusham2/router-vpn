#!/usr/bin/env python3
"""Contract controls for the separate H2 native gate; mocks are not native proof."""
from pathlib import Path
import hashlib
import importlib.util
import json
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('naive_h2_native_gate', ROOT/'deploy/test_mobile_imported_naive_h2.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


class NaiveH2NativeRunner(unittest.TestCase):
    def test_home_inventory_and_native_parser_keep_every_actual_producer(self):
        self.assertEqual(G.HOME_NAMES, {'http-connect.json', 'https-connect.json'})
        self.assertEqual(len(G.HOME_VERDICTS), 7)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            homes = {}
            for role in G.HOME_ROLES:
                directory = root/role; directory.mkdir(); homes[role] = directory
                for name in G.HOME_NAMES: (directory/name).write_text('{}')
            def execute(*args, **options):
                self.assertEqual(args[5:8], ('libbox', G.HOME_ROOT, G.HOME_VERDICTS))
                self.assertEqual(options, {'timeout':120})
                for role in G.HOME_ROLES:
                    self.assertEqual(args[2]['ROUTERVPN_'+role.upper()+'_NAIVE_H2_HOME_GRAPHS'], str(homes[role]))
                return {'modeled':True}
            with patch.object(G.SOCKS, 'execute_image', side_effect=execute):
                result = G.execute_home_parsers('go', root, {}, root/'image', 'a'*64, homes)
                self.assertEqual(set(result['sources']), set(G.HOME_ROLES))
            for missing in G.HOME_ROLES:
                with self.assertRaises(ValueError):
                    G.execute_home_parsers('go', root, {}, root/'image', 'a'*64, {k:v for k,v in homes.items() if k != missing})
            with patch.object(G.SOCKS, 'execute_image', side_effect=ValueError('actual parser failure')):
                with self.assertRaisesRegex(ValueError, 'actual parser failure'):
                    G.execute_home_parsers('go', root, {}, root/'image', 'a'*64, homes)
            target = homes['apple']/'http-connect.json'
            def changed(*args, **options): target.write_text('{"changed":true}')
            with patch.object(G.SOCKS, 'execute_image', side_effect=changed):
                with self.assertRaisesRegex(ValueError, 'changed during'):
                    G.execute_home_parsers('go', root, {}, root/'image', 'a'*64, homes)
            for fault in ('missing', 'extra', 'empty', 'linked', 'array'):
                with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                    path=Path(directory)
                    for name in G.HOME_NAMES: (path/name).write_text('{}')
                    first=path/'http-connect.json'
                    if fault=='missing': first.unlink()
                    elif fault=='extra': (path/'foreign.json').write_text('{}')
                    elif fault=='empty': first.write_text('')
                    elif fault=='linked': first.unlink(); first.symlink_to(path/'https-connect.json')
                    else: first.write_text('[]')
                    with self.assertRaises(ValueError): G.home_inventory(path)

    def sources(self, directory, role='shared'):
        for name in G.NAMES:
            kind, mode, first, last = name.removesuffix('.json').split('--')
            protocol = 'openvpn' if kind.startswith('openvpn-') else kind
            graph = {'endpoints': [{'tag': 'entry-wg', 'network': kind.removeprefix('openvpn-')}], 'original': name}
            source = ['{}', json.dumps({'protocol': protocol, 'profile': {'start_layer': first}}),
                      mode, '{}', json.dumps({'start_layer': last}), '', '', 'a'*64, json.dumps(graph)]
            raw = source if role in ('shared', 'android') else graph
            (directory/(('android-' if role == 'android' else '')+name)).write_text(json.dumps(raw))

    def test_all_four_producer_schemas_and_exact_separate_names(self):
        self.assertEqual(len(G.NAMES), 81)
        self.assertEqual(set(G.PARSER_ROOTS), {'shared', 'android', 'apple', 'desktop'})
        for role in G.PARSER_ROOTS:
            with self.subTest(role=role), tempfile.TemporaryDirectory() as root:
                directory = Path(root); self.sources(directory, role)
                self.assertEqual(len(G.inventory(directory, role)), 81)
                if role == 'android':
                    with self.assertRaises(ValueError): G.inventory(directory, 'shared')
                if role in ('apple', 'desktop'):
                    with self.assertRaises(ValueError): G.inventory(directory, 'shared')

    def test_missing_extra_ordinary_empty_and_linked_files_are_refused(self):
        for fault in ('missing', 'extra', 'ordinary', 'empty', 'linked', 'directory'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as root:
                directory = Path(root); self.sources(directory)
                first, second = sorted(G.NAMES)[:2]; path = directory/first
                if fault == 'missing': path.unlink()
                elif fault == 'extra': (directory/'extra.json').write_bytes(path.read_bytes())
                elif fault == 'ordinary': path.rename(directory/first.replace('naive-h2', 'reality-vision'))
                elif fault == 'empty': path.write_bytes(b'')
                elif fault == 'linked': path.unlink(); path.symlink_to(directory/second)
                else: path.unlink(); path.mkdir()
                with self.assertRaises(ValueError): G.inventory(directory, 'shared')

    def test_renamed_receipts_cannot_substitute_kind_layer_wire_or_mode(self):
        for fault in ('kind', 'entry-layer', 'final-layer', 'wire', 'mode'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as root:
                directory = Path(root); self.sources(directory)
                path = directory/'openvpn-tcp--naive-h2--off--off.json'
                value = json.loads(path.read_text()); capture = json.loads(value[1]); final = json.loads(value[4]); graph = json.loads(value[8])
                if fault == 'kind': capture['protocol'] = 'socks5'
                elif fault == 'entry-layer': capture['profile']['start_layer'] = 'aes-256-gcm'
                elif fault == 'final-layer': final['start_layer'] = 'aes-256-gcm+xor-whitening'
                elif fault == 'wire': graph['endpoints'][0]['network'] = 'udp'
                else: value[2] = 'naive-h3'
                value[1], value[4], value[8] = json.dumps(capture), json.dumps(final), json.dumps(graph)
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError): G.inventory(directory, 'shared')

    def test_every_peer_cell_retains_lifetime_dns_and_independent_authority(self):
        counts = {}
        for kind in G.KINDS:
            counts[kind] = 0
            for first in G.LAYERS:
                for last in G.LAYERS:
                    faults = G.faults(kind, first, last); counts[kind] += len(faults)
                    self.assertEqual(len(faults), len(set(faults)))
                    self.assertTrue({'success', 'cancel', 'close-owner', 'replacement-owner'} <= set(faults))
                    self.assertEqual('entry-layer-key' in faults, first != 'off')
                    self.assertEqual('entry-layer-whitening' in faults, first == G.LAYERS[2])
                    self.assertEqual('final-layer-key' in faults, last != 'off')
                    self.assertEqual('final-layer-whitening' in faults, last == G.LAYERS[2])
                    self.assertEqual('bootstrap-route' in faults, last != 'off' or first == last == 'off')
                    if first == last == 'off':
                        self.assertTrue({'entry-route', 'wrong-entry-ip', 'final-user', 'final-password',
                            'final-server-name', 'final-certificate', 'dns-route', 'final-route',
                            'final-identity', 'final-token'} <= set(faults))
        self.assertEqual(counts, dict(zip(G.KINDS, (72,72,74,72,74,74,75,72,72))))
        self.assertEqual(sum(counts.values()), 657)
        self.assertEqual(sum(len(G.peer_verdicts(parent, kinds)) for parent,kinds in G.PEERS.items()), 659)
        for parent,kinds in G.PEERS.items():
            names = G.peer_verdicts(parent, kinds)
            self.assertEqual(len(names), len(set(names)))
            self.assertEqual(names[0], parent)
            self.assertTrue(all(name.startswith(parent+'/') for name in names[1:]))

    def test_literal_gate_preserves_all_ipv4_ipv6_dotted_and_refusal_verdicts(self):
        self.assertEqual(list(G.LOOPBACK), ['TestRouterVPNDesktopNodeNaiveLiteral', 'TestRouterVPNDesktopNodeNaiveCONNECTLiteral', 'TestRouterVPNDesktopNodeNaiveCONNECTDNSPolicies'])
        connect = G.LOOPBACK['TestRouterVPNDesktopNodeNaiveCONNECTLiteral']
        ordinary = {carrier+'/'+endpoint+'/'+fault
                    for carrier in ('http-connect', 'https-connect')
                    for endpoint in ('192.0.2.77', '2001:db8::77')
                    for fault in ('home-udp', 'naive-password', 'naive-server-name',
                                  'naive-certificate', 'forced-query', 'connect-auth', 'connect-route')}
        layered = {carrier+'/'+endpoint+'/final-layer/'+layer+'/'+fault
                   for carrier in ('http-connect', 'https-connect')
                   for endpoint in ('192.0.2.77', '2001:db8::77')
                   for layer in ('aes-256-gcm', 'aes-256-gcm+xor-whitening')
                   for fault in (('home-udp', 'layer-password', 'layer-whitening', 'layer-route', 'layer-bypass')
                                 if endpoint == '192.0.2.77' else ('home-udp',))}
        self.assertEqual(len(ordinary), 28)
        self.assertEqual(len(layered), 24)
        self.assertEqual(set(connect), ordinary | layered)
        self.assertEqual(len(connect), 52)
        cases = next(iter(G.LOOPBACK.values()))
        self.assertEqual(len(cases), 23)
        self.assertTrue({'ipv4-trailing-dot-name', 'ipv6-trailing-dot-name',
            'ipv6-dotted-wrong-server-name', 'ipv6-dotted-wrong-certificate',
            'literal-ipv6-with-udp-bootstrap', 'literal-with-udp-bootstrap',
            'forced-nonliteral-query-control', 'fresh-ipv6-after-refusals'} <= set(cases))

    def test_exact_mobile_and_desktop_preparation_bind_readers_loader_and_peer(self):
        mobile = G.module('naive_h2_mobile_preparation', 'prepare-mobile-multihop.py')
        inputs = set(mobile.inputs())
        for source,target in G.PARSER_COPIES:
            self.assertIn(ROOT/source, inputs)
            self.assertIn("(root/'"+Path(target).name+"').write_bytes((ROOT/'"+source+"').read_bytes())", (ROOT/'deploy/prepare-mobile-multihop.py').read_text())
        self.assertEqual(G.PACKET.NODE.PREP.PEER_TEMPLATES['node_imported_naive_h2_test.go.tmpl'],
            'protocol/routervpnamnezia/routervpn_desktop_node_imported_naive_h2_test.go')
        self.assertIn(ROOT/'mobile/desktop/node_imported_naive_h2_test.go.tmpl', G.PACKET.NODE.PREP.inputs())
        self.assertEqual(G.PACKET.NODE.PREP.PEER_TEMPLATES['node_naive_dns_test.go.tmpl'],
            'protocol/routervpnamnezia/routervpn_desktop_node_naive_dns_test.go')
        self.assertIn(ROOT/'mobile/desktop/node_naive_dns_test.go.tmpl', G.PACKET.NODE.PREP.inputs())
        self.assertIn('with_purego', G.SOCKS.TAGS.split(','))
        self.assertIn('with_naive_outbound', G.SOCKS.TAGS.split(','))
        self.assertIn('routervpn_openvpn_remote_test', G.PACKET.TAGS.split(','))
        self.assertIn('routerImportedNaiveH2LoadLibrary = cronet.LoadLibrary', (ROOT/G.LOADER).read_text())

    def test_parser_overlay_contains_both_owned_shipping_readers_and_real_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); vendor = root/'vendor'; vendor.mkdir(); work = root/'work'; work.mkdir()
            calls = []
            def command(argv, cwd, env, timeout):
                calls.append(argv)
                self.assertEqual((cwd,env,timeout), (vendor,{'owned':'1'},600))
                self.assertEqual(argv[-1], './experimental/libbox')
                self.assertTrue({'-mod=readonly','-race','-c','-ldflags=-checklinkname=0'} <= set(map(str,argv)))
                overlay = json.loads(Path(argv[argv.index('-overlay')+1]).read_text())['Replace']
                self.assertEqual(set(overlay), {str(vendor/target) for _,target in G.PARSER_COPIES})
                for source,target in G.PARSER_COPIES: self.assertEqual(Path(overlay[str(vendor/target)]).read_bytes(), (ROOT/source).read_bytes())
                Path(argv[argv.index('-o')+1]).write_bytes(b'compiled actual-package boundary')
                return 0,''
            with patch.object(G.SOCKS,'run_command',side_effect=command):
                image,digest = G.parser_image(Path('/compiler/go'),vendor,work,{'owned':'1'})
            self.assertEqual(digest,hashlib.sha256(image.read_bytes()).hexdigest()); self.assertEqual(len(calls),1)
            target = vendor/G.LOADER_TARGET; target.parent.mkdir(parents=True); target.write_bytes(b'foreign loader')
            with patch.object(G.SOCKS,'run_command') as compile:
                with self.assertRaisesRegex(ValueError,'differs'): G.parser_image(Path('/compiler/go'),vendor,work,{})
                compile.assert_not_called()

    @staticmethod
    def events(names):
        return '\n'.join(json.dumps({'Action':action,'Test':name}) for name in names for action in ('run','pass'))

    def test_missing_duplicate_skip_fail_and_foreign_native_verdicts_block_success(self):
        names = ['Native','Native/original']
        complete = self.events(names); G.SOCKS.require_verdicts(complete,0,names)
        for changed in (self.events(names[:1]), complete+'\n'+self.events(names[1:]),
                        complete.replace('"pass"','"skip"',1), complete.replace('"pass"','"fail"',1),
                        complete+'\n'+self.events(['foreign'])):
            with self.assertRaises(ValueError): G.SOCKS.require_verdicts(changed,0,names)
        with self.assertRaises(ValueError): G.SOCKS.require_verdicts(complete,1,names)

    def test_all_stages_seal_library_before_native_image_and_verify_after_execution(self):
        for stage in ('parser','loopback','reference'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); vendor = root/'vendor'; vendor.mkdir(); compiler = root/'go'; compiler.write_bytes(b'compiler')
                image = root/'image'; image.write_bytes(b'image'); order=[]; observed=[]
                def command(argv,cwd,env,timeout):
                    self.assertEqual(cwd,ROOT)
                    self.assertEqual(argv[1:5], ['test','-mod=readonly','-race','-json'])
                    self.assertEqual(argv[-1],'-timeout=60s'); self.assertEqual(timeout,180)
                    self.sources(Path(env['ROUTERVPN_IMPORTED_NAIVE_H2_FIXTURES']))
                    expected = [G.SHARED_ROOT]+[G.SHARED_ROOT+'/'+k+'/'+a+'/'+b for k in G.KINDS for a in G.LAYERS for b in G.LAYERS]
                    return 0,self.events(expected)
                def library(*args): order.append('library'); return (root/'library','module','a'*64,42)
                def compile(*args): order.append('compile'); return image,hashlib.sha256(image.read_bytes()).hexdigest()
                def execute(compiler,vendor,env,image,digest,package,parent,names,timeout):
                    order.append('execute'); observed.extend(names); return {'verdicts':len(names)}
                def version(argv,**kwargs): return {'GOVERSION':G.SOCKS.TOOLCHAIN,'GOHOSTOS':'linux','GOHOSTARCH':'amd64'}[argv[-1]]
                with patch.object(G.shutil,'which',return_value=str(compiler)), patch.object(G.subprocess,'check_output',side_effect=version), \
                     patch.object(G,'source_receipt',return_value={'original':'sha'}), patch.object(G.PACKET,'checked_sources',return_value={'prepared':'sha'}), \
                     patch.object(G.SOCKS,'run_command',side_effect=command), patch.object(G.PACKET.NODE,'stage_naive_library',side_effect=library), \
                     patch.object(G,'parser_image',side_effect=compile), patch.object(G.PACKET,'compile_image',side_effect=compile), \
                     patch.object(G.SOCKS,'execute_image',side_effect=execute), patch.object(G,'parser_inventory_controls',return_value={'modeled':True}), \
                     patch.object(G,'parser_library_controls',return_value={'modeled':True}), \
                     patch.object(G.PACKET.NODE,'verify_naive_library',side_effect=lambda _:order.append('verify')), patch('builtins.print'):
                    result=G.run(vendor,stage=stage)
                self.assertEqual(order[:2],['library','compile']); self.assertEqual(order[-1],'verify')
                self.assertEqual(len(observed), {'parser':82,'loopback':126,'reference':659}[stage])
                self.assertEqual(result['native_library'], {'sha256':'a'*64,'bytes':42})
                self.assertFalse(result['device_acceptance']); self.assertFalse(result['production_router_acceptance'])


if __name__ == '__main__':
    unittest.main()
