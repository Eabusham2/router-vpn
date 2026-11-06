#!/usr/bin/env python3
"""Fail-closed inventory and verdict controls for the Apple native matrix gate."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

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
        self.assertEqual(G.NAMES,previous | openvpn)
        self.assertEqual(len(ss), 11)
        self.assertEqual(len(hy), 9)
        self.assertEqual(len(self.events()), 339)

    def test_exact_verdicts(self):
        G.require_verdicts(self.encode(self.events()))

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
