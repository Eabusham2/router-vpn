#!/usr/bin/env python3
"""Verify exact native chain preparation and preservation of other owners."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shlex
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('node_chain_preparation', ROOT/'deploy/prepare-mobile-node-chain.py')
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)

# Narrow exact anchors leave all unrelated construction and lifecycle code
# untouched. Actual pinned production preparation and Go tests run separately.
BOX = '''package box
type Box struct {
    unrelated string
}
func New(options Options) (*Box, error) {
    preserveExistingPreparation()
\treturn &Box{
        unrelated: "original",
    }, nil
}
'''
NETWORK = '''package route
import (
\t"sync/atomic"
)
type NetworkManager struct {
\tstarted                  atomic.Bool
}
func construct() {
    interfaceMonitor.RegisterCallback(nm.notifyInterfaceUpdate)
    platformMonitor.RegisterCallback(nm.notifyInterfaceUpdate)
}
func (r *NetworkManager) notifyInterfaceUpdate(defaultInterface *control.Interface, flags int) {
    preservePinnedStartupCancellationAndJoin()
}
'''


COMMAND = '''package libbox
func NewCommandServer(handler CommandServerHandler, platformInterface PlatformInterface) (*CommandServer, error) {
\tctx := baseContext(platformInterface)
\tpreserveOriginalRecorderAndService(ctx)
\treturn server, nil
}
'''


class NodeChainPreparation(unittest.TestCase):
    def vendor(self, base):
        vendor = Path(base)/'core'
        (vendor/'route').mkdir(parents=True)
        (vendor/'box.go').write_text(BOX)
        (vendor/'route/network.go').write_text(NETWORK)
        return vendor

    def prepare(self, vendor, **kwargs):
        if kwargs.get('mobile', True):
            command = PREP.destination(vendor, 'experimental/libbox/command_server.go')
            if not command.exists():
                command.parent.mkdir(parents=True, exist_ok=True)
                command.write_text(COMMAND)
        def original(command, **options):
            if command[-2:] == ['rev-parse', 'HEAD']:
                return PREP.PIN+'\n'
            if command[-2:] == ['show', PREP.PIN+':experimental/libbox/command_server.go']:
                return COMMAND.encode()
            raise AssertionError('unexpected preparation metadata read')
        with patch.object(PREP.subprocess, 'check_output', side_effect=original), contextlib.redirect_stdout(io.StringIO()):
            PREP.prepare(vendor, **kwargs)

    def test_complete_projection_is_idempotent_and_preserves_other_preparation(self):
        with tempfile.TemporaryDirectory() as directory:
            vendor = self.vendor(directory)
            self.prepare(vendor)
            before = {p.relative_to(vendor): p.read_bytes() for p in vendor.rglob('*') if p.is_file()}
            self.prepare(vendor)
            self.assertEqual(before, {p.relative_to(vendor): p.read_bytes() for p in vendor.rglob('*') if p.is_file()})
            self.assertIn('preserveExistingPreparation()', (vendor/'box.go').read_text())
            self.assertIn('preservePinnedStartupCancellationAndJoin()', (vendor/'route/network.go').read_text())
            for template, relative in PREP.TEMPLATES.items():
                self.assertEqual((vendor/relative).read_bytes(), (ROOT/'mobile/chain'/template).read_bytes())
            owner = json.loads((vendor/PREP.OWNER).read_bytes())
            self.assertEqual(set(owner['files']), set(PREP.TEMPLATES.values()))
            for relative, value in owner['files'].items():
                self.assertEqual(hashlib.sha256((vendor/relative).read_bytes()).hexdigest(), value)

    def test_desktop_omits_mobile_bridge_without_erasing_owned_mobile_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            vendor = self.vendor(directory)
            self.prepare(vendor, mobile=False)
            self.assertFalse((vendor/'experimental/libbox').exists())
            self.prepare(vendor)
            bridge = (vendor/'experimental/libbox/routervpn_node_chain.go').read_bytes()
            self.prepare(vendor, mobile=False)
            self.assertEqual((vendor/'experimental/libbox/routervpn_node_chain.go').read_bytes(), bridge)

    def test_later_native_snapshot_neighbors_preserve_exact_repreparation(self):
        source = PREP.box_source(BOX).decode()
        for anchor, owned in (
            ('type Box struct {\n', '\trouterVPNExternalOptions string\n\trouterVPNTorOptions string\n\trouterVPNNodeOptions string\n'),
            ('func New(options Options) (*Box, error) {\n', '\texternalOptionsDigest := routerVPNExternalOptionsDigest(options.Context, options.Options)\n\ttorOptionsSnapshot := routerVPNTorOptionsSnapshot(options.Context, options.Options)\n\tnodeOptionsDigest := routerVPNNodeOptionsDigest(options.Context, options.Options)\n'),
            ('\treturn &Box{\n', '\t\trouterVPNExternalOptions: externalOptionsDigest,\n\t\trouterVPNTorOptions: torOptionsSnapshot,\n\t\trouterVPNNodeOptions: nodeOptionsDigest,\n')):
            source = source.replace(anchor, anchor+owned)
        self.assertEqual(PREP.box_source(source).decode(), source)
        for fault in (source.replace('type Box struct {\n', 'type Box struct {\n\tforeign string\n'),
                      source.replace('func New(options Options) (*Box, error) {\n', 'func New(options Options) (*Box, error) {\n\tstartForeignOwner()\n')):
            with self.assertRaises(ValueError):
                PREP.box_source(fault)

    def execution_projection(self):
        spec = importlib.util.spec_from_file_location(
            'original_execution_projection', ROOT/'deploy/prepare-node-chain-execution-owner.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_original_execution_projection_keeps_guard_on_mobile_reentry(self):
        original = BOX+'\nfunc (s *Box) Close() error {\n\treturn preserveOriginalClose()\n}\n'
        execution = self.execution_projection()
        # These are the actual shipping transform functions in the observed
        # desktop owner -> execution -> mobile reentry order.
        first = PREP.box_source(original).decode()
        projected = execution.box_source(first).decode()
        replayed = PREP.box_source(projected).decode()
        self.assertEqual(replayed, projected)
        self.assertEqual(execution.box_source(replayed).decode(), projected)
        self.assertEqual(PREP.box_source(replayed).decode(), projected)
        self.assertEqual(projected.count('routerVPNNodeSOCKSOptions'), 1)
        self.assertLess(projected.index('routerVPNNodeSOCKSOptions'),
                        projected.index('preserveExistingPreparation()'))
        self.assertIn('func (s *Box) routerVPNCloseOriginal() error {', projected)

    def test_execution_neighbor_does_not_admit_moved_or_partial_guard(self):
        original = BOX+'\nfunc (s *Box) Close() error {\n\treturn preserveOriginalClose()\n}\n'
        source = self.execution_projection().box_source(PREP.box_source(original).decode()).decode()
        snapshot = '\tchainExecutionOptionsDigest := routerVPNNodeChainExecutionOptionsDigest(options.Context, options.Options)\n'
        guard = ('\tif err := routerVPNNodeSOCKSOptions(options.Context, options.Options); err != nil {\n'
                 '\t\treturn nil, err\n\t}\n')
        self.assertEqual(source.count(snapshot), 1)
        self.assertEqual(source.count(guard), 1)
        faults = {
            'duplicate': source.replace(guard, guard+guard),
            'late': source.replace(guard, '').replace('    preserveExistingPreparation()\n',
                                                     '    preserveExistingPreparation()\n'+guard),
            'unknown-neighbor': source.replace(snapshot, snapshot+'\tacquireForeignNativeComponent()\n'),
            'duplicate-execution': source.replace(snapshot, snapshot+snapshot),
            'changed-body': source.replace(guard, guard.replace('return nil, err', 'return nil, nil')),
            'changed-context': source.replace(guard, guard.replace('options.Context', 'context.Background()')),
        }
        for name, changed in faults.items():
            with self.subTest(name=name):
                self.assertNotEqual(changed, source)
                with self.assertRaises(ValueError):
                    PREP.box_source(changed)

    def test_source_tampering_and_foreign_ownership_are_rejected_before_mutation(self):
        for fault in ('owned-source', 'foreign-owner', 'unowned-source', 'linked-source', 'linked-parent', 'wrong-pin'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                vendor = self.vendor(directory)
                if fault in ('owned-source', 'foreign-owner'):
                    self.prepare(vendor)
                if fault == 'owned-source':
                    (vendor/'routervpn_node_chain.go').write_text('foreign edit\n')
                elif fault == 'foreign-owner':
                    record = json.loads((vendor/PREP.OWNER).read_bytes())
                    record['files']['box.go'] = hashlib.sha256((vendor/'box.go').read_bytes()).hexdigest()
                    (vendor/PREP.OWNER).write_text(json.dumps(record))
                elif fault == 'unowned-source':
                    (vendor/'routervpn_node_chain.go').write_text('unowned source\n')
                elif fault == 'linked-source':
                    (vendor/'routervpn_node_chain.go').symlink_to(vendor/'box.go')
                elif fault == 'linked-parent':
                    outside = Path(directory)/'outside'; outside.mkdir()
                    (vendor/'experimental').symlink_to(outside, target_is_directory=True)
                before = (vendor/'box.go').read_bytes(), (vendor/'route/network.go').read_bytes()
                with self.assertRaises((ValueError, FileNotFoundError)):
                    if fault == 'wrong-pin':
                        with patch.object(PREP.subprocess, 'check_output', return_value='0'*40+'\n'):
                            PREP.prepare(vendor)
                    else:
                        self.prepare(vendor)
                self.assertEqual(before, ((vendor/'box.go').read_bytes(), (vendor/'route/network.go').read_bytes()))

    def test_snapshot_and_callback_partial_edits_fail(self):
        for before, after in (
                ('type Box struct {\n', 'type Box struct {\n\trouterVPNNodeChainOptions string\n\trouterVPNNodeChainOptions string\n'),
                ('\treturn &Box{\n', '\treturn buildOtherBox(){\n'),
                ('func New(options Options) (*Box, error) {\n', 'func New(other Options) (*Box, error) {\n')):
            with self.subTest(anchor=before), self.assertRaises(ValueError):
                PREP.box_source(BOX.replace(before, after))
        for altered in (NETWORK.replace('atomic.Bool', 'bool'),
                        NETWORK.replace('.RegisterCallback(nm.notifyInterfaceUpdate)', '.RegisterCallback(nm.unowned)', 1),
                        NETWORK.replace('.RegisterCallback(nm.notifyInterfaceUpdate)', '.RegisterCallback(nm.routerVPNNodeChainInterfaceUpdate)', 1)):
            with self.subTest(source=altered), self.assertRaises(ValueError):
                PREP.network_source(altered)

    def test_both_shipping_producers_seal_and_install_the_same_native_source(self):
        mobile = (ROOT/'deploy/prepare-mobile-multihop.py').read_text()
        desktop = (ROOT/'deploy/prepare-desktop-external.py').read_text()
        for source, call in ((mobile, 'NODE_CHAIN.prepare(vendor)'), (desktop, 'NODE_CHAIN.prepare(vendor, mobile=False)')):
            self.assertIn('prepare-mobile-node-chain', source)
            self.assertIn('NODE_CHAIN.inputs()', source)
            self.assertIn(call, source)
            self.assertLess(source.index('STRATEGY.prepare(vendor'), source.index(call))
        native = (ROOT/'mobile/chain/box.go.tmpl').read_text()
        self.assertNotIn('.Close()', native[native.index('type routerVPNNodeChainObservation'):native.index('func (e *routerVPNNodeChainObservation) Dial')])
        self.assertNotIn('net.Dial', native)
        self.assertNotIn('net.Lookup', native)


    def test_typed_constructor_guard_and_infallible_factory_are_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            vendor = self.vendor(directory)
            with patch.object(PREP.subprocess, 'check_output', return_value=COMMAND.encode()):
                expected = PREP.command_source(vendor, COMMAND)
                self.assertEqual(PREP.command_source(vendor, expected.decode()), expected)
                self.assertIn(b'preserveOriginalRecorderAndService(ctx)', expected)
                self.assertIn(b'return newCommandServerWithContext(handler, platformInterface, baseContext(platformInterface)), nil', expected)
                self.assertEqual(expected.count(b'newCommandServerWithContext'), 2)
                for raw in (expected.replace(b'return server\n', b'return nil\n'),
                            expected.replace(b'preserveOriginalRecorderAndService(ctx)', b'replaceOriginalOwner(ctx)'),
                            expected+b'\n// foreign constructor projection\n'):
                    with self.assertRaises(ValueError):
                        PREP.command_source(vendor, raw.decode())
            native = PREP.box_source(BOX).decode()
            guard = ('\tif err := routerVPNNodeSOCKSOptions(options.Context, options.Options); err != nil {\n'
                     '\t\treturn nil, err\n\t}\n')
            self.assertEqual(native.count(guard), 1)
            self.assertLess(native.index(guard), native.index('preserveExistingPreparation()'))
            for bad in (native.replace(guard, guard+guard),
                        native.replace(guard, '').replace('    preserveExistingPreparation()\n', '    preserveExistingPreparation()\n'+guard)):
                with self.assertRaises(ValueError):
                    PREP.box_source(bad)

    def test_typed_socks_mtu_projects_original_native_receipts(self):
        expected = {
            'socks_mtu_box.go.tmpl': 'routervpn_node_chain_socks_mtu.go',
            'socks_mtu_box_test.go.tmpl': 'routervpn_node_chain_socks_mtu_test.go',
            'socks_mtu.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks_mtu.go',
            'socks_mtu_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks_mtu_test.go',
        }
        for template, target in expected.items():
            self.assertEqual(PREP.TEMPLATES.get(template), target)
            self.assertEqual(list(PREP.TEMPLATES.values()).count(target), 1)
        tests = (ROOT/'mobile/chain/socks_mtu_box_test.go.tmpl').read_text()
        self.assertEqual(set(re.findall(r'^func (Test\w+)\(', tests, re.M)), {
            'TestRouterVPNNodeChainSOCKSMTUJoinedNativeReader',
            'TestRouterVPNNodeChainSOCKSMTUHeldPauseAndForeignCaller',
            'TestRouterVPNNodeChainSOCKSMTUResumeKeepsNativeReadback',
            'TestRouterVPNNodeChainSOCKSMTUCleanupRestoresOnlyOriginalValue',
            'TestRouterVPNNodeChainSOCKSMTULateOriginalResultRetainsReader',
            'TestRouterVPNNodeChainSOCKSMTUManagerAndLockRemainOwned',
            'TestRouterVPNNodeChainSOCKSMTURetirementAfterWorkCannotRenewAuthority',
            'TestRouterVPNNodeChainSOCKSMTURetirementRetainsFailedJoin',
        })

    def test_typed_socks_mtu_wrapper_retains_each_executable_lifetime_root(self):
        tests = (ROOT/'mobile/chain/socks_mtu_test.go.tmpl').read_text()
        self.assertEqual(set(re.findall(r'^func (Test\w+)\(', tests, re.M)), {
            'TestRouterNodeChainSOCKSMTUProfileIsPureCapturedSource',
            'TestRouterNodeChainSOCKSMTUConstructorRequiresActualProof',
            'TestRouterNodeChainSOCKSMTUCloseKeepsOriginalCleanupToken',
            'TestRouterNodeChainSOCKSMTUFailedJoinRetainsOriginalRetry',
            'TestRouterNodeChainSOCKSMTUPlanCloseJoinsConstruction',
            'TestRouterNodeChainSOCKSMTUForeignStateCannotRetire',
            'TestRouterNodeChainSOCKSMTUCleanupTokenEndsWithExactAttempt',
        })

    def test_actual_native_roots_are_selected_in_each_shipping_build(self):
        roots = {}
        for template, relative in PREP.TEMPLATES.items():
            if not template.endswith('_test.go.tmpl'):
                continue
            package = './'+str(Path(relative).parent) if '/' in relative else '.'
            roots.setdefault(package, []).extend(re.findall(r'^func (Test\w+)\(', (ROOT/'mobile/chain'/template).read_text(), re.M))
        self.assertEqual({'.', './route', './experimental/libbox'}, set(roots))
        for relative in ('android/build-sing-box-libbox.sh', 'ios/RouterVPN/prepare-libbox.sh'):
            commands = [shlex.split(line) for line in (ROOT/relative).read_text().splitlines()
                        if re.match(r'\s*(?:go|go_retry) test ', line)]
            for package, names in roots.items():
                patterns = [command[command.index('-run')+1] for command in commands if package in command and '-run' in command]
                for name in names:
                    self.assertTrue(any(re.search(pattern, name) for pattern in patterns), (relative, package, name))
        desktop = ast.parse((ROOT/'deploy/build-native-runtime.py').read_text())
        commands = [[item.value if isinstance(item, ast.Constant) and isinstance(item.value, str) else ''
                     for item in node.elts] for node in ast.walk(desktop) if isinstance(node, ast.List)]
        for package, names in roots.items():
            if package == './experimental/libbox':
                continue  # Desktop owns its original command-process lifecycle.
            patterns = [command[command.index('-run')+1] for command in commands if package in command and '-run' in command]
            for name in names:
                self.assertTrue(any(re.search(pattern, name) for pattern in patterns), ('desktop', package, name))
        for template in ('node_chain_box_physical_test.go.tmpl',):
            package = '.' if template.startswith('node_chain_box') else './cmd/sing-box'
            patterns = [command[command.index('-run')+1] for command in commands if package in command and '-run' in command]
            for name in re.findall(r'^func (Test\w+)\(', (ROOT/'mobile/desktop'/template).read_text(), re.M):
                self.assertTrue(any(re.search(pattern, name) for pattern in patterns), ('desktop', package, name))


if __name__ == '__main__':
    unittest.main()
