#!/usr/bin/env python3
"""Contract controls for the separate H3 native gate; mocks are not native proof."""
from pathlib import Path
import hashlib
import importlib.util
import json
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('naive_h3_native_gate', ROOT/'deploy/test_mobile_imported_naive_h3.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


class NaiveH3NativeRunner(unittest.TestCase):
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
        self.assertEqual(len(G.NAMES), 63)
        self.assertEqual(set(G.PARSER_ROOTS), {'shared', 'android', 'apple', 'desktop'})
        for role in G.PARSER_ROOTS:
            with self.subTest(role=role), tempfile.TemporaryDirectory() as root:
                directory = Path(root); self.sources(directory, role)
                self.assertEqual(len(G.inventory(directory, role)), 63)
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
                elif fault == 'ordinary': path.rename(directory/first.replace('naive-h3', 'reality-vision'))
                elif fault == 'empty': path.write_bytes(b'')
                elif fault == 'linked': path.unlink(); path.symlink_to(directory/second)
                else: path.unlink(); path.mkdir()
                with self.assertRaises(ValueError): G.inventory(directory, 'shared')

    def test_renamed_receipts_cannot_substitute_kind_layer_wire_or_mode(self):
        for fault in ('kind', 'entry-layer', 'final-layer', 'wire', 'mode'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as root:
                directory = Path(root); self.sources(directory)
                path = directory/'openvpn-tcp--naive-h3--off--off.json'
                value = json.loads(path.read_text()); capture = json.loads(value[1]); final = json.loads(value[4]); graph = json.loads(value[8])
                if fault == 'kind': capture['protocol'] = 'socks5'
                elif fault == 'entry-layer': capture['profile']['start_layer'] = 'aes-256-gcm'
                elif fault == 'final-layer': final['start_layer'] = 'aes-256-gcm+xor-whitening'
                elif fault == 'wire': graph['endpoints'][0]['network'] = 'udp'
                else: value[2] = 'naive-h2'
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
        self.assertEqual(counts, dict(zip(G.KINDS, (90,72,74,74,75,72,72))))
        self.assertEqual(sum(counts.values()), 529)
        self.assertEqual(sum(len(G.peer_verdicts(parent, kinds)) for parent,kinds in G.PEERS.items()), 531)
        for parent,kinds in G.PEERS.items():
            names = G.peer_verdicts(parent, kinds)
            self.assertEqual(len(names), len(set(names)))
            self.assertEqual(names[0], parent)
            self.assertTrue(all(name.startswith(parent+'/') for name in names[1:]))

    def test_literal_gate_preserves_all_ipv4_ipv6_dotted_and_refusal_verdicts(self):
        self.assertEqual(list(G.LOOPBACK), ['TestRouterVPNDesktopNodeNaiveH3Literal', 'TestRouterVPNImportedNaiveH3SOCKSAssociation',
                                          'TestRouterVPNDesktopNodeNaiveH3StreamOwner'])
        self.assertEqual(len(G.LOOPBACK['TestRouterVPNImportedNaiveH3SOCKSAssociation']),12)
        self.assertEqual(G.LOOPBACK['TestRouterVPNDesktopNodeNaiveH3StreamOwner'], ('owner-cancellation', 'caller-deadline'))
        cases = next(iter(G.LOOPBACK.values()))
        self.assertEqual(len(cases), 23)
        self.assertTrue({'ipv4-trailing-dot-name', 'ipv6-trailing-dot-name',
            'ipv6-dotted-wrong-server-name', 'ipv6-dotted-wrong-certificate',
            'literal-ipv6-with-udp-bootstrap', 'literal-with-udp-bootstrap',
            'forced-nonliteral-query-control', 'fresh-ipv6-after-refusals'} <= set(cases))

    def test_exact_mobile_and_desktop_preparation_bind_readers_loader_and_peer(self):
        mobile = G.module('naive_h3_mobile_preparation', 'prepare-mobile-multihop.py')
        inputs = set(mobile.inputs())
        for source,target in G.PARSER_COPIES:
            self.assertIn(ROOT/source, inputs)
            self.assertIn("(root/'"+Path(target).name+"').write_bytes((ROOT/'"+source+"').read_bytes())", (ROOT/'deploy/prepare-mobile-multihop.py').read_text())
        self.assertEqual(G.PACKET.NODE.PREP.PEER_TEMPLATES['node_imported_naive_h3_test.go.tmpl'],
            'protocol/routervpnamnezia/routervpn_desktop_node_imported_naive_h3_test.go')
        self.assertIn(ROOT/'mobile/desktop/node_imported_naive_h3_test.go.tmpl', G.PACKET.NODE.PREP.inputs())
        self.assertIn('with_purego', G.SOCKS.TAGS.split(','))
        self.assertIn('with_naive_outbound', G.SOCKS.TAGS.split(','))
        self.assertIn('routervpn_openvpn_remote_test', G.PACKET.TAGS.split(','))
        self.assertIn('routerImportedNaiveH3LoadLibrary = cronet.LoadLibrary', (ROOT/G.LOADER).read_text())

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

    def test_native_transport_controls_preserve_exact_graph_bytes_and_refuse_false_failures(self):
        for fault in ('complete', 'zero-status', 'missing-root', 'skip', 'panic', 'wrong-reason'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); shared = root/'shared'; shared.mkdir(); work = root/'work'; work.mkdir()
                self.sources(shared)
                for path in shared.iterdir():
                    source = json.loads(path.read_text())
                    graph = {'outbounds': [{'type':'naive','quic':True}], 'dns': {'servers': [
                        {'type':'udp','detour':'proxy'}, {'type':'udp','detour':'entry-wg'}]}}
                    source[8] = json.dumps(graph); path.write_text(json.dumps(source))
                original = {path.name:path.read_bytes() for path in shared.iterdir()}
                image = root/'image'; image.write_bytes(b'exact native reader'); digest = hashlib.sha256(image.read_bytes()).hexdigest()
                seen = []
                def command(argv,cwd,env,timeout):
                    self.assertEqual((cwd,timeout), (root,45))
                    self.assertEqual(argv[1:5], ['tool','test2json','-t','-p'])
                    self.assertEqual(argv[-1], '-test.timeout=30s')
                    graph = json.loads((Path(env['ROUTERVPN_APPLE_IMPORTED_NAIVE_H3_FIXTURES'])/'socks5--naive-h3--off--off.json').read_text())
                    index = len(seen); seen.append(graph)
                    if index == 0: self.assertIs(graph['outbounds'][0]['quic'],False)
                    elif index == 1: self.assertEqual(graph['dns']['servers'][0]['type'],'tcp')
                    elif index == 2: self.assertEqual(graph['dns']['servers'][0]['detour'],'entry-wg')
                    else: self.assertEqual(graph['dns']['servers'][1]['detour'],'proxy')
                    parent = G.PARSER_ROOTS['apple'][0]; names = [parent,parent+'/socks5--naive-h3--off--off.json']
                    events = [{'Action':'run','Test':name} for name in names] + [{'Action':'fail','Test':name} for name in reversed(names)]
                    reason = 'Naive H3 parser lost its exact QUIC' if index == 0 else 'changed captured Home UDP transport or resolver owner'
                    status = 1
                    if fault == 'zero-status': status = 0
                    elif fault == 'missing-root': events.pop()
                    elif fault == 'skip': events[2]['Action']='skip'
                    elif fault == 'panic': reason += ' panic: unrelated'
                    elif fault == 'wrong-reason': reason = 'unrelated timeout'
                    return status, '\n'.join(json.dumps(event) for event in events)+'\n'+reason
                with patch.object(G.SOCKS,'run_command',side_effect=command):
                    if fault == 'complete':
                        receipt=G.parser_transport_controls(Path('/go'),root,work,{},image,digest,shared)
                        self.assertEqual(len(seen),4); self.assertEqual(len(receipt['rejected']),4)
                        self.assertEqual((receipt['producer'],receipt['raw_reader']),('exact shared source graph','apple'))
                    else:
                        with self.assertRaisesRegex(ValueError,'wrong boundary'):
                            G.parser_transport_controls(Path('/go'),root,work,{},image,digest,shared)
                self.assertEqual({path.name:path.read_bytes() for path in shared.iterdir()},original)
                self.assertEqual((work/'transport-native-inventory'/'socks5--naive-h3--off--off.json').read_text(),json.loads(original['socks5--naive-h3--off--off.json'])[8])

    def test_actual_desktop_tuple_control_retains_all_previous_refusals_and_original_bytes(self):
        for fault in ('complete','zero-status','missing-root','skip','panic','wrong-reason'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary); desktop=root/'desktop'; desktop.mkdir(); work=root/'work'; work.mkdir()
                self.sources(desktop,'desktop')
                for path in desktop.iterdir():
                    graph=json.loads(path.read_text())
                    graph.update(outbounds=[{'type':'naive','quic':True}],dns={'servers':[
                        {'type':'udp','tag':'selected-dns','detour':'proxy','server':'10.88.0.53','server_port':53},
                        {'type':'udp','tag':'routervpn-predecessor-bootstrap-0','detour':'entry-wg','server':'10.88.0.53','server_port':53}]})
                    path.write_text(json.dumps(graph))
                original={path.name:path.read_bytes() for path in desktop.iterdir()}
                name='socks5--naive-h3--off--off.json'
                image=root/'image'; image.write_bytes(b'exact native reader'); digest=hashlib.sha256(image.read_bytes()).hexdigest()
                seen=[]
                def command(argv,cwd,env,timeout):
                    self.assertEqual((cwd,timeout),(root,45)); self.assertEqual(argv[-1],'-test.timeout=30s')
                    self.assertNotIn('ROUTERVPN_APPLE_IMPORTED_NAIVE_H3_FIXTURES',env)
                    graph=json.loads((Path(env['ROUTERVPN_DESKTOP_IMPORTED_NAIVE_H3_FIXTURES'])/name).read_text())
                    expected=json.loads(original[name]); index=len(seen); seen.append(graph)
                    if index==0: expected['outbounds'][0]['quic']=False
                    elif index==1: expected['dns']['servers'][0]['type']='tcp'
                    elif index==2: expected['dns']['servers'][0]['detour']='entry-wg'
                    elif index==3: expected['dns']['servers'][1]['detour']='proxy'
                    elif index==4:
                        for row in expected['dns']['servers']:row['server']='192.0.2.53'
                    else:self.fail('unexpected desktop transport control')
                    self.assertEqual(graph,expected)
                    parent=G.PARSER_ROOTS['desktop'][0];names=[parent,parent+'/'+name]
                    events=[{'Action':'run','Test':n} for n in names]+[{'Action':'fail','Test':n} for n in reversed(names)]
                    reason='Naive H3 parser lost its exact QUIC' if index==0 else 'changed captured Home UDP transport or resolver owner'
                    status=1
                    if index==4:
                        if fault=='zero-status':status=0
                        elif fault=='missing-root':events.pop()
                        elif fault=='skip':events[2]['Action']='skip'
                        elif fault=='panic':reason+=' panic: unrelated'
                        elif fault=='wrong-reason':reason='unrelated timeout'
                    return status,'\n'.join(json.dumps(event) for event in events)+'\n'+reason
                with patch.object(G.SOCKS,'run_command',side_effect=command):
                    if fault=='complete':
                        receipt=G.parser_transport_controls(Path('/go'),root,work,{},image,digest,root/'absent-shared',desktop)
                        self.assertEqual(receipt['rejected'],['h2-downgrade','selected-tcp','selected-entry','bootstrap-final','home-server-substitution'])
                        self.assertEqual((receipt['producer'],receipt['raw_reader']),('original desktop source graph','desktop'))
                    else:
                        with self.assertRaisesRegex(ValueError,'wrong boundary'):
                            G.parser_transport_controls(Path('/go'),root,work,{},image,digest,root/'absent-shared',desktop)
                self.assertEqual(len(seen),5)
                self.assertEqual({path.name:path.read_bytes() for path in desktop.iterdir()},original)
                self.assertEqual((work/'transport-native-inventory'/name).read_bytes(),original[name])

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

    def test_stream_owner_gate_requires_both_original_native_lifetimes(self):
        root = 'TestRouterVPNDesktopNodeNaiveH3StreamOwner'
        names = [root]+[root+'/'+leaf for leaf in G.LOOPBACK[root]]
        complete = self.events(names)
        G.SOCKS.require_verdicts(complete, 0, names)
        for missing in names:
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                G.SOCKS.require_verdicts(self.events([name for name in names if name != missing]), 0, names)
        for duplicated in names:
            with self.subTest(duplicated=duplicated), self.assertRaises(ValueError):
                G.SOCKS.require_verdicts(complete+'\n'+self.events([duplicated]), 0, names)
        for verdict in ('skip', 'fail'):
            with self.subTest(verdict=verdict), self.assertRaises(ValueError):
                G.SOCKS.require_verdicts(complete.replace('"pass"', '"'+verdict+'"', 1), 0, names)

    def test_all_stages_seal_library_before_native_image_and_verify_after_execution(self):
        for stage in ('parser','loopback','reference'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); vendor = root/'vendor'; vendor.mkdir(); compiler = root/'go'; compiler.write_bytes(b'compiler')
                image = root/'image'; image.write_bytes(b'image'); order=[]; observed=[]
                def command(argv,cwd,env,timeout):
                    self.assertEqual(cwd,ROOT)
                    self.assertEqual(argv[1:5], ['test','-mod=readonly','-race','-json'])
                    self.assertEqual(argv[-1],'-timeout=60s'); self.assertEqual(timeout,180)
                    self.sources(Path(env['ROUTERVPN_IMPORTED_NAIVE_H3_FIXTURES']))
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
                     patch.object(G,'parser_transport_controls',return_value={'modeled':True}), \
                     patch.object(G.PACKET.NODE,'verify_naive_library',side_effect=lambda _:order.append('verify')), patch('builtins.print'):
                    result=G.run(vendor,stage=stage)
                self.assertEqual(order[:2],['library','compile']); self.assertEqual(order[-1],'verify')
                self.assertEqual(len(observed), {'parser':64,'loopback':40,'reference':531}[stage])
                self.assertEqual(result['native_library'], {'sha256':'a'*64,'bytes':42})
                self.assertFalse(result['device_acceptance']); self.assertFalse(result['production_router_acceptance'])


if __name__ == '__main__':
    unittest.main()
