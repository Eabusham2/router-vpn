#!/usr/bin/env python3
"""Fail-closed inventory and verdict controls for the Apple native matrix gate."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('apple_imported_gate', Path(__file__).with_name('test_ios_imported_router_pinned.py'))
G = importlib.util.module_from_spec(spec); spec.loader.exec_module(G)


class ImportedGate(unittest.TestCase):
    def events(self):
        return [{'Package': G.PACKAGE, 'Action': 'pass', 'Test': t}
                for t in sorted({G.PARENT} | {G.PARENT+'/'+n for n in G.NAMES})] + [
                    {'Package': G.PACKAGE, 'Action': 'pass'}]

    def encode(self, events):
        return '\n'.join(json.dumps(e) for e in events)

    def test_preserved_proxy_and_complete_packet_matrix(self):
        ss = {a+'--'+b+'--2022-blake3-aes-256-gcm.json' for a in G.LAYERS for b in G.LAYERS} | {'off--off--2022-blake3-aes-128-gcm.json', 'off--off--2022-blake3-chacha20-poly1305.json'}
        hy = {'hysteria2--'+a+'--'+b+'.json' for a in G.LAYERS for b in G.LAYERS}
        original = ss | hy | {"final-hysteria2--"+name for name in ss | hy}
        packet = {'packet-'+kind+'--final-'+final+'--'+a+'--'+b+'.json'
                  for kind in ('wireguard', 'amneziawg') for final in ('shadowsocks', 'hysteria2')
                  for a in G.LAYERS for b in G.LAYERS}
        self.assertEqual(len(original), 40)
        self.assertEqual(len(packet), 36)
        self.assertFalse(original & packet)
        packet_final = {'final-'+mode+'--'+name for mode in ('wg','awg2-fast','awg2-strong') for name in ss | hy}
        self.assertEqual(len(packet_final),60)
        self.assertFalse(packet_final & (original | packet))
        nested = {'packet-'+kind+'--final-'+final+'--'+a+'--'+b+'.json'
                  for kind in ('wireguard', 'amneziawg') for final in ('wg', 'awg2-fast', 'awg2-strong')
                  for a in G.LAYERS for b in G.LAYERS}
        self.assertEqual(len(nested),54)
        self.assertFalse(nested & (original | packet | packet_final))
        socks={"socks5--final-"+mode+".json" for mode in ("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong")}
        published_layers={"socks5--final-"+mode+"--"+b+".json" for mode in ("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong") for b in G.LAYERS[1:]}
        published_entry_layers={"socks5--final-"+mode+"--entry-"+a+".json" for mode in ("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong") for a in G.LAYERS[1:]}
        independent_layers={"socks5--final-"+mode+"--"+a+"--"+b+".json" for mode in ("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong") for a in G.LAYERS for b in G.LAYERS if (a,b)!=("off","off") and a!="off" and b!="off"}
        self.assertEqual(len(published_layers),10)
        self.assertEqual(len(published_entry_layers),10)
        self.assertEqual(len(independent_layers),20)
        self.assertFalse(published_entry_layers & (published_layers | independent_layers))
        self.assertFalse(published_layers & independent_layers)
        socks_layers=published_layers | published_entry_layers | independent_layers
        self.assertEqual(len(socks_layers),40)
        self.assertFalse(socks & socks_layers)
        self.assertFalse(socks_layers & (original | packet | packet_final | nested))
        self.assertFalse(socks & (original | packet | packet_final | nested))
        connect={"connect--"+p+"--"+m+"--"+d+".json" for p in ("http-connect","https-connect") for m in ("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305") for d in ("home","custom")}
        self.assertEqual(len(connect),12)
        self.assertFalse(connect & (original | packet | packet_final | nested | socks | socks_layers))
        openvpn={"openvpn--"+transport+"--final-"+mode+"--"+a+"--"+b+".json" for transport in ("tcp","udp") for mode in ("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong") for a in G.LAYERS for b in G.LAYERS}
        previous= original | packet | packet_final | nested | socks | socks_layers | connect
        self.assertEqual(len(previous),247)
        self.assertEqual(len(openvpn),90)
        self.assertFalse(previous & openvpn)
        reality={"socks5--final-reality-vision.json"}
        reality|={"socks5--final-reality-vision--"+b+".json" for b in G.LAYERS[1:]}
        reality|={"socks5--final-reality-vision--entry-"+a+".json" for a in G.LAYERS[1:]}
        reality|={"socks5--final-reality-vision--"+a+"--"+b+".json" for a in G.LAYERS[1:] for b in G.LAYERS[1:]}
        self.assertEqual(len(reality),9)
        self.assertFalse(reality & (previous | openvpn))
        self.assertEqual(G.NAMES,previous | openvpn | reality)
        self.assertEqual(len(ss), 11)
        self.assertEqual(len(hy), 9)
        self.assertEqual(len(self.events()), 348)

    def test_exact_verdicts(self):
        G.require_verdicts(self.encode(self.events()))

    def build_output(self):
        return {'ImportPath': G.PACKAGE+' ['+G.PACKAGE+'.test]', 'Action': 'build-output',
                'Output': '# '+G.PACKAGE+'\nld: warning: fixture compiler diagnostic\n'}

    def test_compiler_output_preserves_exact_native_verdicts(self):
        G.require_verdicts(self.encode([self.build_output(), *self.events()]))
        for events in ([self.build_output()], [self.build_output(), *self.events()[1:]],
                       [self.build_output(), *self.events()[:-1]]):
            with self.subTest(events=len(events)), self.assertRaises(ValueError):
                G.require_verdicts(self.encode(events))

    def test_build_failure_or_malformed_output_cannot_be_a_native_verdict(self):
        for fault in ('build-fail', 'package', 'test', 'null-package', 'missing-path',
                      'empty-path', 'wrong-path-type', 'missing-output', 'wrong-output-type'):
            event = self.build_output()
            if fault == 'build-fail': event['Action'] = 'build-fail'
            elif fault == 'package': event['Package'] = G.PACKAGE
            elif fault == 'test': event['Test'] = G.PARENT
            elif fault == 'null-package': event['Package'] = None
            elif fault == 'missing-path': event.pop('ImportPath')
            elif fault == 'empty-path': event['ImportPath'] = ''
            elif fault == 'wrong-path-type': event['ImportPath'] = [G.PACKAGE]
            elif fault == 'missing-output': event.pop('Output')
            else: event['Output'] = {'Action': 'pass', 'Test': G.PARENT}
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                G.require_verdicts(self.encode([event, *self.events()]))

    def test_missing_duplicate_skipped_failed_and_foreign(self):
        for change in ('missing', 'duplicate', 'skip', 'fail', 'foreign', 'no-package'):
            events = self.events()
            if change == 'missing': events.pop(0)
            elif change == 'duplicate': events[1] = events[0]
            elif change in ('skip', 'fail'): events[0]['Action'] = change
            elif change == 'foreign': events[0]['Package'] = 'unrelated/package'
            else: events.pop()
            with self.subTest(change=change), self.assertRaises(ValueError):
                G.require_verdicts(self.encode(events))

    def test_portable_crypto_provider_is_in_source_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for name in ('deploy/test_ios_imported_router_pinned.py','ios/RouterVPN/prepare-libbox.sh',
                         'go.mod','deploy/ios_test_crypto_bridge.py','android/test_android_multihop_graph.py'):
                target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text('original')
            with mock.patch.object(G,'ROOT',root),mock.patch.object(G,'__file__',str(root/'deploy/test_ios_imported_router_pinned.py')):
                original=G.digest()
                (root/'deploy/ios_test_crypto_bridge.py').write_text('changed actual SHA provider')
                self.assertNotEqual(original,G.digest())

    def test_connect_layer_matrix_and_verdicts_are_separate(self):
        self.assertEqual(len(G.CONNECT_LAYER_NAMES),32)
        self.assertFalse(G.CONNECT_LAYER_NAMES & G.NAMES)
        expected={G.CONNECT_LAYER_PARENT} | {G.CONNECT_LAYER_PARENT+'/'+n for n in G.CONNECT_LAYER_NAMES}
        self.assertEqual(len(expected),33)
        events=[{'Package':G.PACKAGE,'Action':'pass','Test':n} for n in sorted(expected)] + [{'Package':G.PACKAGE,'Action':'pass'}]
        G.require_verdicts(self.encode([self.build_output(),*events]),G.CONNECT_LAYER_PARENT,G.CONNECT_LAYER_NAMES)
        for changed in (events[1:],events+[events[0]],events[:-1],events[:-2]+[dict(events[-2],Action='skip')]+events[-1:],events[:-2]+[dict(events[-2],Action='fail')]+events[-1:],self.events()):
            with self.assertRaises(ValueError):G.require_verdicts(self.encode(changed),G.CONNECT_LAYER_PARENT,G.CONNECT_LAYER_NAMES)
        with self.assertRaises(ValueError):G.require_verdicts(self.encode(events))
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for name in G.CONNECT_LAYER_NAMES:(root/name).write_text('{}')
            G.require_matrix(root,G.CONNECT_LAYER_NAMES)
            with self.assertRaises(ValueError):G.require_matrix(root)
            file=root/sorted(G.CONNECT_LAYER_NAMES)[0];file.unlink()
            with self.assertRaises(ValueError):G.require_matrix(root,G.CONNECT_LAYER_NAMES)
            file.symlink_to(root/sorted(G.CONNECT_LAYER_NAMES)[1])
            with self.assertRaises(ValueError):G.require_matrix(root,G.CONNECT_LAYER_NAMES)
            file.unlink();file.write_text('{}');(root/'foreign.json').write_text('{}')
            with self.assertRaises(ValueError):G.require_matrix(root,G.CONNECT_LAYER_NAMES)

    def test_actual_file_matrix(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in G.NAMES: (root/name).write_text('{}')
            G.require_matrix(root)
            name = sorted(G.NAMES)[0]; file = root/name; file.unlink()
            with self.assertRaises(ValueError): G.require_matrix(root)
            file.symlink_to(root/sorted(G.NAMES)[1])
            with self.assertRaises(ValueError): G.require_matrix(root)
            file.unlink(); file.write_text('{}'); (root/'foreign.json').write_text('{}')
            with self.assertRaises(ValueError): G.require_matrix(root)


if __name__ == '__main__':
    unittest.main()
