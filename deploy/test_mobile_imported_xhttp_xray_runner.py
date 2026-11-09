#!/usr/bin/env python3
"""Negative controls for the separate XHTTP source and verdict inventory."""
from pathlib import Path
import importlib.util
import json
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('xhttp_native_gate', ROOT/'deploy/test_mobile_imported_xhttp_xray.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


class XHTTPInventoryTests(unittest.TestCase):
    def sources(self, directory, android=False):
        for name in G.NAMES:
            kind, mode, first, last = name.removesuffix('.json').split('--')
            protocol = 'openvpn' if kind.startswith('openvpn-') else kind
            capture = {'protocol': protocol, 'profile': {'start_layer': first}}
            graph = {'endpoints': [{'tag': 'entry-wg', 'network': kind.removeprefix('openvpn-')}]}
            source = ['{}', json.dumps(capture), mode, '{}', json.dumps({'start_layer': last}), '', '', 'a'*64, json.dumps(graph)]
            (directory/(('android-' if android else '')+name)).write_text(json.dumps(source))

    def test_exact_separate_inventory(self):
        self.assertEqual(len(G.NAMES), 81)
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            self.sources(directory)
            self.assertEqual(len(G.inventory(directory, 'shared')), 81)

    def test_android_requires_its_own_producer_prefix(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root); self.sources(directory, True)
            self.assertEqual(len(G.inventory(directory, 'android')), 81)
            with self.assertRaises(ValueError): G.inventory(directory, 'shared')

    def test_missing_extra_and_ordinary_names_refused(self):
        for fault in ('missing', 'extra', 'ordinary'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as root:
                directory = Path(root); self.sources(directory)
                path = directory/sorted(G.NAMES)[0]
                if fault == 'missing': path.unlink()
                elif fault == 'extra': (directory/'extra.json').write_bytes(path.read_bytes())
                else: path.rename(path.with_name(path.name.replace('reality-xhttp', 'reality-vision')))
                with self.assertRaises(ValueError): G.inventory(directory, 'shared')

    def test_renamed_or_duplicate_receipts_do_not_cover_other_axes(self):
        for fault in ('kind', 'entry-layer', 'final-layer', 'openvpn-wire', 'ordinary-mode'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as root:
                directory = Path(root); self.sources(directory)
                name = 'openvpn-tcp--reality-xhttp--off--off.json'
                path = directory/name; value = json.loads(path.read_text())
                capture, final, graph = json.loads(value[1]), json.loads(value[4]), json.loads(value[8])
                if fault == 'kind': capture['protocol'] = 'socks5'
                elif fault == 'entry-layer': capture['profile']['start_layer'] = 'aes-256-gcm'
                elif fault == 'final-layer': final['start_layer'] = 'aes-256-gcm+xor-whitening'
                elif fault == 'openvpn-wire': graph['endpoints'][0]['network'] = 'udp'
                else: value[2] = 'reality-vision'
                value[1], value[4], value[8] = json.dumps(capture), json.dumps(final), json.dumps(graph)
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError): G.inventory(directory, 'shared')

    def test_linked_source_refused(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root); self.sources(directory)
            first, second = sorted(G.NAMES)[:2]
            (directory/first).unlink(); (directory/first).symlink_to(directory/second)
            with self.assertRaises(ValueError): G.inventory(directory, 'shared')

    def test_required_pq_key_and_owner_controls_are_per_graph(self):
        for first in G.LAYERS:
            for last in G.LAYERS:
                faults = G.faults(first, last)
                self.assertEqual(len(faults), len(set(faults)))
                self.assertTrue({'success', 'final-pq-key', 'final-xhttp-path', 'cancel', 'close-owner'} <= set(faults))
                self.assertEqual('entry-layer-key' in faults, first != 'off')
                self.assertEqual('final-layer-key' in faults, last != 'off')

    def test_native_xhttp_roots_and_mobile_preparer_remain_mandatory(self):
        self.assertEqual(G.LOOPBACK['TestNativeXHTTPAuthenticationRefusal'], ['matching-key', 'wrong-xhttp-path', 'restored-path', 'wrong-pq-key', 'restored-key'])
        self.assertEqual(len(G.LOOPBACK['TestNativeXHTTPConfigurationRefusal']), 9)
        self.assertEqual(G.LOOPBACK['TestNativeXHTTPSelectedDNSUDP443'], [name for name in G.UDP443.CASES if name != 'plain-vision-udp443'])
        self.assertIn('doh3-udp443', G.LOOPBACK['TestNativeXHTTPSelectedDNSUDP443'])
        self.assertEqual(sum(1+len(cases) for cases in G.LOOPBACK.values()), 32)
        source=(ROOT/'deploy/prepare-mobile-multihop.py').read_text()
        self.assertIn("paths.append(ROOT/'mobile/routervpn_imported_xhttp_xray_native_test.go.tmpl')", source)
        self.assertIn("(root/'routervpn_imported_xhttp_xray_native_test.go').write_bytes((ROOT/'mobile/routervpn_imported_xhttp_xray_native_test.go.tmpl').read_bytes())", source)

    def test_partial_skipped_or_failed_native_verdicts_refused(self):
        expected = ['XHTTP', 'XHTTP/wrong-pq-key']
        def events(actions):
            return '\n'.join(json.dumps({'Action': action, 'Test': name}) for name, action in actions)
        complete = [('XHTTP', 'run'), ('XHTTP/wrong-pq-key', 'run'), ('XHTTP/wrong-pq-key', 'pass'), ('XHTTP', 'pass')]
        G.SOCKS.require_verdicts(events(complete), 0, expected)
        for changed in (complete[:-1], complete[:2]+[('XHTTP/wrong-pq-key', 'skip'), ('XHTTP', 'pass')], complete[:2]+[('XHTTP/wrong-pq-key', 'fail'), ('XHTTP', 'pass')]):
            with self.assertRaises(ValueError): G.SOCKS.require_verdicts(events(changed), 0, expected)


if __name__ == '__main__':
    unittest.main()
