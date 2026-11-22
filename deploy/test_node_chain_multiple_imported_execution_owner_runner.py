#!/usr/bin/env python3
"""Require every independent-provider native verdict and its original source."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'multiple_imported_owner_runner_checks', ROOT/'deploy/test_node_chain_multiple_imported_execution_owner.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def events(parser):
    rows = []
    for package, roots in parser.ROOTS.items():
        rows.append(dict(Package=package, Action='start'))
        for root in roots:
            name = parser.PREFIX+root
            rows.append(dict(Package=package, Action='run', Test=name))
            for child in parser.CHILDREN.get(root, ()):
                rows.append(dict(Package=package, Action='run', Test=name+'/'+child))
                rows.append(dict(Package=package, Action='pass', Test=name+'/'+child))
            rows.append(dict(Package=package, Action='pass', Test=name))
        rows.append(dict(Package=package, Action='pass'))
    return rows


def encoded(rows):
    return '\n'.join(json.dumps(row) for row in rows)


PHASES = (RUNNER.GENERATOR, RUNNER.BOX, RUNNER.DESKTOP_BOX, RUNNER.DESKTOP_COMMAND)


class MultipleImportedNativeVerdicts(unittest.TestCase):
    def test_complete_independent_source_native_and_desktop_inventories(self):
        expected = ((1, 9), (6, 38), (3, 29), (9, 90))
        for parser, (roots, records) in zip(PHASES, expected):
            with self.subTest(prefix=parser.PREFIX, package=parser.ROOTS):
                self.assertEqual(parser.verdict(encoded(events(parser)), 0),
                                 {'roots': roots, 'test_records': records})

    def test_each_run_pass_or_terminal_cannot_be_omitted(self):
        for parser in PHASES:
            rows = events(parser)
            for index, row in enumerate(rows):
                if row['Action'] in ('run', 'pass'):
                    with self.subTest(prefix=parser.PREFIX, row=row), self.assertRaises(ValueError):
                        parser.verdict(encoded(rows[:index]+rows[index+1:]), 0)

    def test_skip_race_failure_foreign_duplicate_or_nonzero_cannot_pass(self):
        for parser in PHASES:
            rows = events(parser)
            package = next(iter(parser.ROOTS))
            bad_rows = [dict(Package=package, Action='skip'),
                        dict(Package=package, Action='fail'),
                        dict(Package=package, Action='output', Output='WARNING: DATA RACE'),
                        dict(Package='foreign', Action='pass'), rows[1], rows[2]]
            for row in bad_rows:
                with self.subTest(prefix=parser.PREFIX, row=row), self.assertRaises(ValueError):
                    parser.verdict(encoded(rows[:2]+[row]+rows[2:]), 0)
            for code in (1, -9, 124):
                with self.subTest(prefix=parser.PREFIX, code=code), self.assertRaises(ValueError):
                    parser.verdict(encoded(rows), code)
        with self.assertRaises(ValueError):
            RUNNER.DESKTOP_COMMAND.verdict(encoded(events(RUNNER.BOX)), 0)

    def test_desktop_gate_compares_the_actual_complete_prepared_sources(self):
        preparation = RUNNER.NATIVE.load('multiple_imported_verifier_fixture', 'prepare-desktop-external.py')
        copies = preparation.pt_copies()
        for template in sorted((ROOT/'mobile/desktop').glob('node*.go.tmpl')):
            if template.name not in (*preparation.PT_TEMPLATES, *preparation.BOX_TEMPLATES, *preparation.PEER_TEMPLATES):
                copies['cmd/sing-box/routervpn_'+template.name.removesuffix('.tmpl')] = template.read_bytes()
        required = {relative for relative in copies if 'multiple_imported_execution' in relative}
        self.assertGreaterEqual(len(required), 11)
        # Only the preceding, separately tested general verifier is doubled.
        # This runner's actual desktop projection checks run on every byte.
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(RUNNER.NATIVE, 'verify', return_value='original-general-source'):
            core = Path(directory)
            for relative, raw in copies.items():
                target = core/relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            original = RUNNER.verify(core, True)
            for relative in sorted(required):
                target = core/relative
                raw = target.read_bytes()
                target.unlink()
                with self.subTest(missing=relative), self.assertRaises(FileNotFoundError):
                    RUNNER.verify(core, True)
                target.write_bytes(raw+b'\n')
                with self.subTest(changed=relative), self.assertRaises(ValueError):
                    RUNNER.verify(core, True)
                target.write_bytes(raw)
            self.assertEqual(RUNNER.verify(core, True), original)

    def test_all_artifact_cache_inputs_include_the_gate_and_verdict_checks(self):
        required = {ROOT/'deploy/test_node_chain_multiple_imported_execution_owner.py',
                    ROOT/'deploy/test_node_chain_multiple_imported_execution_owner_runner.py'}
        for relative in ('prepare-mobile-node-chain.py', 'prepare-mobile-multihop.py', 'build-native-runtime.py'):
            module = RUNNER.NATIVE.load('multiple_imported_cache_'+relative.replace('-', '_'), relative)
            with self.subTest(preparer=relative):
                self.assertTrue(required <= set(module.inputs()))

    def test_each_shipping_builder_requires_the_new_gate_and_previous_owners(self):
        for relative in ('android/build-sing-box-libbox.sh', 'ios/RouterVPN/prepare-libbox.sh'):
            source = (ROOT/relative).read_text()
            check = 'deploy/test_node_chain_multiple_imported_execution_owner_runner.py"'
            gate = 'deploy/test_node_chain_multiple_imported_execution_owner.py" --core "$VENDOR"'
            with self.subTest(builder=relative):
                self.assertEqual(source.count(check), 1)
                self.assertEqual(source.count(gate), 1)
                self.assertLess(source.index(check), source.index(gate))
                line = next(line for line in source.splitlines() if gate in line)
                self.assertIn('--race --tags ', line)
                self.assertNotIn('||', line)
                self.assertIn('set -e', source)
                for original in ('test_node_chain_execution_owner.py', 'test_node_chain_openvpn_execution_owner.py'):
                    self.assertIn('deploy/'+original+'" --core "$VENDOR"', source)
        source = (ROOT/'deploy/build-native-runtime.py').read_text().split('def build(', 1)[1]
        check = "ROOT/'deploy/test_node_chain_multiple_imported_execution_owner_runner.py'"
        gate = "ROOT/'deploy/test_node_chain_multiple_imported_execution_owner.py'"
        self.assertEqual(source.count(check), 1)
        self.assertEqual(source.count(gate), 1)
        self.assertLess(source.index(check), source.index(gate))
        self.assertIn("'--desktop', *(['--race'] if race else [])", source)
        self.assertIn("ROOT/'deploy/test_node_chain_openvpn_execution_owner.py'", source)


if __name__ == '__main__':
    unittest.main()
