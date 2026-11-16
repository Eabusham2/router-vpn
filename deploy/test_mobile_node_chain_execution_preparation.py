#!/usr/bin/env python3
"""Original-source and native close-boundary preparation controls; no native I/O."""
import importlib.util
import json
import re
import shlex
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('mobile_execution_preparer', ROOT/'deploy/prepare-mobile-node-chain-execution.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


class Preparation(unittest.TestCase):
    def instance(self):
        return P.FIELD_BEFORE+'}\n'+P.CLOSE_BEFORE+'\n'+P.CONSTRUCT_BEFORE+P.BOX_BEFORE+P.ACQUIRE_BEFORE+'}\n'

    def fixture(self, parent):
        vendor = Path(parent)/'core'
        vendor.mkdir()
        for relative, source in P.PREREQUISITES.items():
            target = vendor/relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT/source).read_bytes())
        target = vendor/'daemon/instance.go'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('package daemon\n\n'+self.instance())
        (vendor/'daemon/started_service.go').write_text('package daemon\n\n'+P.SERVICE_FIELD_BEFORE+'}\n')
        return vendor

    def prepare(self, vendor, pin=None):
        with patch.object(P.subprocess, 'check_output', return_value=(pin or P.PIN)+'\n'):
            P.prepare(vendor)

    def test_execution_validation_changes_invalidate_artifact_reuse(self):
        required = {ROOT/'deploy'/name for name in (
            'test_mobile_node_chain_execution.py',
            'test_mobile_node_chain_execution_runner.py',
            'test_mobile_node_chain_execution_preparation.py')}
        modules = [('bridge', P)]
        for name in ('prepare-mobile-multihop', 'build-native-runtime'):
            spec = importlib.util.spec_from_file_location('execution_cache_'+name, ROOT/'deploy'/(name+'.py'))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            modules.append((name, module))
        for name, module in modules:
            with self.subTest(cache=name):
                self.assertTrue(required <= set(module.inputs()), name)

    def test_openvpn_bridge_roots_are_required_by_both_real_build_commands(self):
        roots = re.findall(r'^func (Test\w+)\(', (ROOT/'mobile/chain_execution/openvpn_test.go.tmpl').read_text(), re.M)
        self.assertEqual(roots, ['TestRouterNodeChainExecutionBridgeOpenVPNOriginalSource',
                                 'TestRouterNodeChainExecutionBridgeOpenVPNOriginalFactory'])
        def selected(shell):
            commands = [shlex.split(line) for line in shell.splitlines()
                        if re.match(r'\s*(?:go|go_retry) test ', line)]
            commands = [x for x in commands if './experimental/libbox' in x]
            for command in commands:
                self.assertIn('-tags', command)
                self.assertTrue({'with_openvpn', 'with_gvisor'}.issubset(
                    command[command.index('-tags')+1].split(',')), 'real OpenVPN registry omitted')
            for root in roots:
                self.assertTrue(any('-run' not in x or re.search(x[x.index('-run')+1], root)
                                    for x in commands), root)
            self.assertTrue(any('-run' in x and all(re.search(x[x.index('-run')+1], root)
                                                   for root in roots) for x in commands),
                            'required explicit OpenVPN bridge selector omitted')
        for name in ('android/build-sing-box-libbox.sh', 'ios/RouterVPN/prepare-libbox.sh'):
            source = (ROOT/name).read_text()
            selected(source)
            anchor = '|NodeChainExecutionBridgeOpenVPN'
            self.assertEqual(source.count(anchor), 1)
            with self.subTest(build=name), self.assertRaises(AssertionError):
                selected(source.replace(anchor, '', 1)+'\n# decoy '+anchor+'\n')
            commands = [line for line in source.splitlines() if re.match(r'\s*(?:go|go_retry) test ', line)
                        and './experimental/libbox' in shlex.split(line)]
            for command in commands:
                self.assertIn(',with_openvpn ', command)
                with self.subTest(build=name, command=command), self.assertRaises(AssertionError):
                    selected(source.replace(command, command.replace(',with_openvpn ', ' ', 1), 1)
                             +'\n# decoy with_openvpn\n')

    def test_complete_original_and_idempotent(self):
        with tempfile.TemporaryDirectory() as parent:
            vendor = self.fixture(parent)
            self.prepare(vendor)
            first = {str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()}
            self.prepare(vendor)
            self.assertEqual(first, {str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()})
            record = json.loads((vendor/P.OWNER).read_bytes())
            self.assertEqual(set(record['files']), set(P.TEMPLATES.values()))
            self.assertIn(P.CLOSE_AFTER, (vendor/'daemon/instance.go').read_text())

    def test_exact_previous_inventory_migrates_but_partial_inventory_refused(self):
        additions = {'experimental/libbox/routervpn_node_chain_execution_last.go', 'experimental/libbox/routervpn_node_chain_execution_last_test.go'}
        for removed in (additions, {next(iter(additions))}):
            with self.subTest(removed=removed), tempfile.TemporaryDirectory() as parent:
                vendor = self.fixture(parent)
                self.prepare(vendor)
                record = json.loads((vendor/P.OWNER).read_bytes())
                for relative in removed:
                    del record['files'][relative]
                    (vendor/relative).unlink()
                (vendor/P.OWNER).write_text(json.dumps(record))
                if removed == additions:
                    self.prepare(vendor)
                    self.assertEqual(set(json.loads((vendor/P.OWNER).read_bytes())['files']), set(P.TEMPLATES.values()))
                else:
                    with self.assertRaisesRegex(ValueError, 'ownership inventory'):
                        self.prepare(vendor)

    def test_wrong_pin_precedes_writes(self):
        with tempfile.TemporaryDirectory() as parent:
            vendor = self.fixture(parent)
            with self.assertRaisesRegex(ValueError, 'exact pinned'):
                self.prepare(vendor, '0'*40)
            self.assertFalse((vendor/P.OWNER).exists())

    def test_socks_upgrade_requires_the_complete_owned_pair(self):
        socks = {P.TEMPLATES[name] for name in ('socks.go.tmpl', 'socks_test.go.tmpl')}
        connect = {P.TEMPLATES[name] for name in ('connect.go.tmpl', 'connect_test.go.tmpl')}
        cases = ((socks, True), (socks | connect, True),
                 ({sorted(socks)[0]}, False), ({sorted(socks)[1]}, False),
                 (socks | {sorted(connect)[0]}, False))
        for removed, accepted in cases:
            with self.subTest(removed=removed), tempfile.TemporaryDirectory() as parent:
                vendor = self.fixture(parent)
                self.prepare(vendor)
                record = json.loads((vendor/P.OWNER).read_bytes())
                for relative in removed:
                    del record['files'][relative]
                    (vendor/relative).unlink()
                (vendor/P.OWNER).write_text(json.dumps(record))
                before = {str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()}
                if accepted:
                    self.prepare(vendor)
                    self.assertEqual(set(json.loads((vendor/P.OWNER).read_bytes())['files']), set(P.TEMPLATES.values()))
                else:
                    with self.assertRaisesRegex(ValueError, 'ownership inventory'):
                        self.prepare(vendor)
                    self.assertEqual(before, {str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()})

    def test_openvpn_upgrade_requires_the_complete_owned_pair(self):
        openvpn = {P.TEMPLATES[name] for name in ('openvpn.go.tmpl', 'openvpn_test.go.tmpl')}
        connect = {P.TEMPLATES[name] for name in ('connect.go.tmpl', 'connect_test.go.tmpl')}
        cases = ((openvpn, True), (openvpn | connect, True),
                 ({sorted(openvpn)[0]}, False), ({sorted(openvpn)[1]}, False),
                 (openvpn | {sorted(connect)[0]}, False))
        for removed, accepted in cases:
            with self.subTest(removed=removed), tempfile.TemporaryDirectory() as parent:
                vendor = self.fixture(parent)
                self.prepare(vendor)
                record = json.loads((vendor/P.OWNER).read_bytes())
                for relative in removed:
                    del record['files'][relative]
                    (vendor/relative).unlink()
                (vendor/P.OWNER).write_text(json.dumps(record))
                before = {str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()}
                if accepted:
                    self.prepare(vendor)
                    self.assertEqual(set(json.loads((vendor/P.OWNER).read_bytes())['files']), set(P.TEMPLATES.values()))
                else:
                    with self.assertRaisesRegex(ValueError, 'ownership inventory'):
                        self.prepare(vendor)
                    self.assertEqual(before, {str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()})

    def test_latency_upgrade_requires_both_owned_templates_and_original_bridge(self):
        latency = {'experimental/libbox/routervpn_node_chain_execution_latency.go',
                   'experimental/libbox/routervpn_node_chain_execution_latency_test.go'}
        self.assertTrue(latency.issubset(P.TEMPLATES.values()))
        self.assertEqual(P.PREREQUISITES['experimental/libbox/routervpn_ordered_latency.go'],
                         'mobile/chain/ordered_latency_bridge.go.tmpl')
        last = {'experimental/libbox/routervpn_node_chain_execution_last.go',
                'experimental/libbox/routervpn_node_chain_execution_last_test.go'}
        restore = {'experimental/libbox/routervpn_node_chain_execution_restore_test.go'}
        for removed in (latency, latency|last, latency|restore, latency|last|restore,
                        {sorted(latency)[0]}, {sorted(latency)[1]}):
            with self.subTest(removed=removed), tempfile.TemporaryDirectory() as parent:
                vendor = self.fixture(parent)
                self.prepare(vendor)
                record = json.loads((vendor/P.OWNER).read_bytes())
                for relative in removed:
                    del record['files'][relative]
                    (vendor/relative).unlink()
                (vendor/P.OWNER).write_text(json.dumps(record))
                if latency.issubset(removed):
                    self.prepare(vendor)
                    self.assertEqual(set(json.loads((vendor/P.OWNER).read_bytes())['files']), set(P.TEMPLATES.values()))
                else:
                    before = {str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()}
                    with self.assertRaisesRegex(ValueError, 'ownership inventory'):
                        self.prepare(vendor)
                    self.assertEqual(before, {str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()})

    def test_published_restore_test_upgrade_keeps_exact_previous_files(self):
        restore = {'experimental/libbox/routervpn_node_chain_execution_restore_test.go'}
        last = {'experimental/libbox/routervpn_node_chain_execution_last.go', 'experimental/libbox/routervpn_node_chain_execution_last_test.go'}
        for removed in (restore, restore|last, restore|{next(iter(last))}):
            with self.subTest(removed=removed), tempfile.TemporaryDirectory() as parent:
                vendor = self.fixture(parent)
                self.prepare(vendor)
                record = json.loads((vendor/P.OWNER).read_bytes())
                for relative in removed:
                    del record['files'][relative]
                    (vendor/relative).unlink()
                (vendor/P.OWNER).write_text(json.dumps(record))
                if removed == restore|{next(iter(last))}:
                    with self.assertRaisesRegex(ValueError, 'ownership inventory'):
                        self.prepare(vendor)
                else:
                    self.prepare(vendor)
                    self.assertEqual(set(json.loads((vendor/P.OWNER).read_bytes())['files']), set(P.TEMPLATES.values()))

    def test_original_native_dependencies_are_exact(self):
        for relative in P.PREREQUISITES:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as parent:
                vendor = self.fixture(parent)
                (vendor/relative).write_text('foreign native owner')
                with self.assertRaisesRegex(ValueError, 'original native owner'):
                    self.prepare(vendor)
                self.assertFalse((vendor/P.OWNER).exists())

    def test_close_preimage_cannot_move_or_discard_actual_return(self):
        source = self.instance()
        for changed in (source.replace('return i.instance.Close()', '_ = i.instance.Close(); return nil'), source+P.CLOSE_BEFORE, source.replace('i.cancel()', '// removed cancellation')):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(ValueError, 'boundary changed'):
                    P.instance_source(changed)

    def test_receipt_field_cannot_be_duplicated(self):
        source = P.instance_source(self.instance()).decode()
        with self.assertRaisesRegex(ValueError, 'moved or duplicated'):
            P.instance_source(source+'\n// routerVPNCloseReceipt')

    def test_construction_hooks_are_exact_and_reserved_once(self):
        source=self.instance()
        for changed in (source.replace(P.CONSTRUCT_BEFORE,'func changed() {\n'),source.replace(P.ACQUIRE_BEFORE,'\tother = boxInstance\n'),source.replace(P.BOX_BEFORE,'\totherBox := box.New(box.Options{\n'),source+P.CONSTRUCT_BEFORE,source+P.ACQUIRE_BEFORE):
            with self.assertRaisesRegex(ValueError,'boundary changed'):
                P.instance_source(changed)
        for changed in ('type Different struct {\n}\n',P.SERVICE_FIELD_BEFORE+'}\n'+P.SERVICE_FIELD_BEFORE+'}\n',P.SERVICE_FIELD_BEFORE+'\trouterVPNCloseCapture int\n}\n'):
            with self.assertRaisesRegex(ValueError,'construction boundary'):
                P.service_source(changed)

    def test_modified_owned_source_refused(self):
        with tempfile.TemporaryDirectory() as parent:
            vendor = self.fixture(parent)
            self.prepare(vendor)
            target = vendor/next(iter(P.TEMPLATES.values()))
            target.write_bytes(target.read_bytes()+b'\n// changed\n')
            with self.assertRaisesRegex(ValueError, 'changed owned'):
                self.prepare(vendor)

    def test_foreign_generated_path_refused(self):
        with tempfile.TemporaryDirectory() as parent:
            vendor = self.fixture(parent)
            target = vendor/next(iter(P.TEMPLATES.values()))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('foreign')
            with self.assertRaisesRegex(ValueError, 'foreign mobile'):
                self.prepare(vendor)

    def test_linked_target_refused(self):
        with tempfile.TemporaryDirectory() as parent:
            vendor = self.fixture(parent)
            target = vendor/next(iter(P.TEMPLATES.values()))
            target.parent.mkdir(parents=True, exist_ok=True)
            original = Path(parent)/'original'
            original.write_text('unrelated')
            target.symlink_to(original)
            with self.assertRaisesRegex(ValueError, 'linked mobile'):
                self.prepare(vendor)
            self.assertEqual(original.read_text(), 'unrelated')

    def test_extra_manifest_owner_refused(self):
        with tempfile.TemporaryDirectory() as parent:
            vendor = self.fixture(parent)
            self.prepare(vendor)
            record = json.loads((vendor/P.OWNER).read_bytes())
            record['files']['unrelated.go']='0'*64
            (vendor/P.OWNER).write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, 'ownership inventory'):
                self.prepare(vendor)


if __name__ == '__main__':
    unittest.main()
