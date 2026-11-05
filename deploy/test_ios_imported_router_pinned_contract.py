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

    def test_preserved_ss_and_complete_hysteria_matrix(self):
        ss = {a+'--'+b+'--2022-blake3-aes-256-gcm.json' for a in G.LAYERS for b in G.LAYERS} | {'off--off--2022-blake3-aes-128-gcm.json', 'off--off--2022-blake3-chacha20-poly1305.json'}
        hy = {'hysteria2--'+a+'--'+b+'.json' for a in G.LAYERS for b in G.LAYERS}
        self.assertEqual(G.NAMES, ss | hy)
        self.assertEqual(len(ss), 11)
        self.assertEqual(len(hy), 9)
        self.assertEqual(len(self.events()), 22)

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
