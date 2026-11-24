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
\t}, nil
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


MULTIPLE_IMPORTED_ROOTS = ('TestRouterVPNMultipleImportedPublicRouteOriginalOwners',
                           'TestRouterVPNMultipleImportedPublicRouteRefusals')
MULTIPLE_IMPORTED_SELECTION = '^TestRouterVPNMultipleImportedPublicRoute(OriginalOwners|Refusals)$'


def multiple_imported_shipping_selection(source, executable):
    """Require the actual unconditional command in the owned vendor build."""
    start = '\n(\n  cd "$VENDOR"\n'
    if source.count(start) != 1 or not source.startswith('#!/usr/bin/env bash\nset -euo pipefail\n'):
        raise ValueError('original vendor build or fail-closed shell missing')
    block = source.split(start, 1)[1].split('\n)\n', 1)[0]
    command = [executable, 'test', '-race', '-ldflags=-checklinkname=0', '-tags',
               'with_quic,with_wireguard,with_gvisor', '.', '-run',
               MULTIPLE_IMPORTED_SELECTION, '-count=1', '-timeout=90s']
    lines = [line for line in source.splitlines() if MULTIPLE_IMPORTED_SELECTION in line]
    if len(lines) != 1 or shlex.split(lines[0]) != command or lines[0] not in block.splitlines():
        raise ValueError('original multiple-import Box selection missing, changed or duplicated')
    # The shipping prefix is a straight-line sequence with explicit failing
    # assertion blocks. Refuse a newly enclosing shell control flow, function,
    # subshell or heredoc before accepting this command as unconditional.
    prefix = block.split(lines[0], 1)[0]
    depth = []
    for line in prefix.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        words = shlex.split(stripped)
        first = words[0] if words else ''
        if first in ('if', 'for', 'while', 'until', 'case', 'select'):
            depth.append(first)
        elif first in ('fi', 'done', 'esac'):
            if not depth:
                raise ValueError('unbalanced vendor control flow')
            depth.pop()
        elif first in ('(', ')') or '<<' in stripped or re.match(r'[^ ]+\s*\(\)\s*\{', stripped) or first == 'function':
            raise ValueError('multiple-import command moved into another shell owner')
    if depth:
        raise ValueError('multiple-import Box selection became conditional')
    return command


class NodeChainPreparation(unittest.TestCase):
    def vendor(self, base):
        vendor = Path(base)/'core'
        (vendor/'route').mkdir(parents=True)
        (vendor/'box.go').write_text(BOX)
        (vendor/'route/network.go').write_text(NETWORK)
        (vendor/'option').mkdir()
        (vendor/'option/shadowsocks.go').write_text('package option\ntype ShadowsocksOutboundOptions struct {\n}\n')
        (vendor/'protocol/shadowsocks').mkdir(parents=True)
        (vendor/'protocol/shadowsocks/outbound.go').write_text('package shadowsocks\nfunc NewOutbound() {\n\toutbound := &Outbound{\n\t}\n}\n')
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
            self.assertFalse((vendor/'experimental/libbox/routervpn_node_chain.go').exists())
            self.assertTrue((vendor/'experimental/libbox/routervpn/mobilemultihop/routervpn_candidate_response_cipher.go').is_file())
            self.prepare(vendor)
            bridge = (vendor/'experimental/libbox/routervpn_node_chain.go').read_bytes()
            self.prepare(vendor, mobile=False)
            self.assertEqual((vendor/'experimental/libbox/routervpn_node_chain.go').read_bytes(), bridge)

    def test_openvpn_session_stays_on_the_original_box_across_repreparation(self):
        source = PREP.box_source(BOX).decode()
        anchor = '\trouterVPNNodeChainOptions string\n'
        field = '\trouterVPNNodeChainOpenVPN routerVPNNodeChainOpenVPNSession\n'
        self.assertEqual(source.count(anchor + field), 1)
        self.assertEqual(PREP.box_source(source).decode(), source)
        # Upgrade only the exact preceding owned shape, without allocating a
        # second native session or editing another owner's constructor.
        self.assertEqual(PREP.box_source(source.replace(field, '', 1)).decode(), source)
        for changed in (source + field,
                        source.replace(anchor + field, field + anchor, 1),
                        source.replace(field, '\trouterVPNNodeChainOpenVPN foreignSession\n', 1)):
            with self.assertRaises(ValueError):
                PREP.box_source(changed)

    def test_later_native_snapshot_neighbors_preserve_exact_repreparation(self):
        source = PREP.box_source(BOX).decode()
        for anchor, owned in (
            ('type Box struct {\n', '\trouterVPNExternalOptions string\n\trouterVPNTorOptions string\n\trouterVPNNodeOptions string\n'),
            ('func New(options Options) (*Box, error) {\n', '\texternalOptionsDigest := routerVPNExternalOptionsDigest(options.Context, options.Options)\n\ttorOptionsSnapshot := routerVPNTorOptionsSnapshot(options.Context, options.Options)\n\tnodeOptionsDigest := routerVPNNodeOptionsDigest(options.Context, options.Options)\n'),
            ('\treturn routerVPNNodeSOCKSBind(&Box{\n', '\t\trouterVPNExternalOptions: externalOptionsDigest,\n\t\trouterVPNTorOptions: torOptionsSnapshot,\n\t\trouterVPNNodeOptions: nodeOptionsDigest,\n')):
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

    def test_acquired_box_binding_is_exact_infallible_and_idempotent(self):
        source = PREP.box_source(BOX).decode()
        self.assertEqual(source.count('return routerVPNNodeSOCKSBind(&Box{'), 1)
        self.assertEqual(PREP.box_source(source).decode(), source)
        plain = PREP.box_close_binding(source, bind=False)
        self.assertIn('return &Box{', plain)
        self.assertEqual(PREP.box_close_binding(plain, bind=True), source)
        self.assertIn('return s', (ROOT/'mobile/chain/socks_box.go.tmpl').read_text())
        for changed in (
            source.replace('routerVPNNodeSOCKSBind', 'foreignBind'),
            source.replace('routerVPNNodeSOCKSBind(&Box{', 'routerVPNNodeSOCKSBind(other('),
            source.replace('\t}), nil\n}', '\t}, nil\n}'),
            source + '\n// routerVPNNodeSOCKSBind\n',
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(changed, source)
                with self.assertRaises(ValueError):
                    PREP.box_source(changed)

    def test_acquired_box_binding_preserves_external_snapshot_order(self):
        spec = importlib.util.spec_from_file_location('preclose_external', ROOT/'deploy/prepare-mobile-external-policy.py')
        external = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(external)
        with tempfile.TemporaryDirectory() as directory:
            vendor = self.vendor(directory)
            # Only the external Box projection executes; its unchanged later
            # selected-runtime source stage is stopped at the explicit boundary.
            class ProjectionFinished(Exception): pass
            def finish(_vendor): raise ProjectionFinished()
            for starting in (BOX, PREP.box_source(BOX).decode()):
                (vendor/'box.go').write_text(starting)
                with (
                    patch.object(external.subprocess, 'check_output', return_value=external.PIN+'\n'),
                    patch.object(external, 'selection_sources', side_effect=finish),
                ):
                    with self.assertRaises(ProjectionFinished):
                        external.prepare(vendor)
                projected = PREP.box_source((vendor/'box.go').read_text()).decode()
                self.assertEqual(projected.count('routerVPNNodeSOCKSBind'), 1)
                self.assertEqual(projected.count('routerVPNExternalOptions: externalOptionsDigest'), 1)
                self.assertEqual(PREP.box_source(projected).decode(), projected)

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
            'socks_prefix_mtu_test.go.tmpl': 'routervpn_node_chain_socks_prefix_mtu_test.go',
            'socks_prefix_run_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks_prefix_run_test.go',
            'socks_prefix_policy_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks_prefix_policy_test.go',
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

    def test_multiple_imported_public_route_shipping_commands_are_required(self):
        native = (ROOT/'mobile/chain/multiple_imported_box_test.go.tmpl').read_text()
        self.assertEqual(tuple(re.findall(r'^func (Test\w+)\(', native, re.M)), MULTIPLE_IMPORTED_ROOTS)
        for relative, executable in (('android/build-sing-box-libbox.sh', 'go_retry'),
                                     ('ios/RouterVPN/prepare-libbox.sh', 'go')):
            source = (ROOT/relative).read_text()
            command = multiple_imported_shipping_selection(source, executable)
            for name in MULTIPLE_IMPORTED_ROOTS:
                self.assertIsNotNone(re.fullmatch(command[command.index('-run')+1], name))
            self.assertIsNone(re.fullmatch(command[command.index('-run')+1], MULTIPLE_IMPORTED_ROOTS[0]+'Foreign'))

    def test_multiple_imported_shipping_omissions_and_substitutions_fail(self):
        for relative, executable in (('android/build-sing-box-libbox.sh', 'go_retry'),
                                     ('ios/RouterVPN/prepare-libbox.sh', 'go')):
            source = (ROOT/relative).read_text()
            multiple_imported_shipping_selection(source, executable)
            line = next(line for line in source.splitlines() if MULTIPLE_IMPORTED_SELECTION in line)
            faults = {
                'omitted': '', 'comment': '  # '+line.strip(), 'duplicate': line+'\n'+line,
                'conditional': '  if false; then\n'+line+'\n  fi',
                'optional': line+' || true', 'wrong-package': line.replace(' . -run ', ' ./route -run '),
                'no-race': line.replace(' -race ', ' '), 'missing-wireguard': line.replace(',with_wireguard', ''),
                'missing-positive': line.replace('(OriginalOwners|Refusals)', 'Refusals'),
                'missing-refusals': line.replace('(OriginalOwners|Refusals)', 'OriginalOwners'),
                'changed-bound': line.replace('-timeout=90s', '-timeout=180s'),
                'wrong-owner': line.replace(executable+' test', 'echo '+executable+' test', 1),
                'sibling-function': '  unrelated() {\n'+line+'\n  }',
            }
            for name, replacement in faults.items():
                with self.subTest(relative=relative, fault=name), self.assertRaises(ValueError):
                    multiple_imported_shipping_selection(source.replace(line, replacement, 1), executable)
            outside = source.replace(line, '', 1)+'\n'+line+'\n'
            with self.subTest(relative=relative, fault='outside-original-vendor'), self.assertRaises(ValueError):
                multiple_imported_shipping_selection(outside, executable)

    def test_actual_native_roots_are_selected_in_each_shipping_build(self):
        roots = {}
        for template, relative in PREP.TEMPLATES.items():
            if not template.endswith('_test.go.tmpl'):
                continue
            package = './'+str(Path(relative).parent) if '/' in relative else '.'
            roots.setdefault(package, []).extend(re.findall(r'^func (Test\w+)\(', (ROOT/'mobile/chain'/template).read_text(), re.M))
        shared_package = './experimental/libbox/routervpn/mobilemultihop'
        self.assertEqual({'.', './route', './experimental/libbox', './protocol/routervpnnodesocks', shared_package}, set(roots))
        extra_spec = importlib.util.spec_from_file_location('checked_multiple_original_roots', ROOT/'deploy/test_node_chain_multiple_imported_execution_owner.py')
        extra = importlib.util.module_from_spec(extra_spec)
        extra_spec.loader.exec_module(extra)
        candidate_spec = importlib.util.spec_from_file_location('checked_original_candidate_roots', ROOT/'deploy/test_node_chain_candidate_preparation.py')
        candidate = importlib.util.module_from_spec(candidate_spec)
        candidate_spec.loader.exec_module(candidate)
        # OpenVPN ownership has two real native build variants and private
        # shared fixtures. Follow its required executable driver rather than
        # adding an ungated shell selection that cannot supply those inputs.
        owner_spec = importlib.util.spec_from_file_location('node_chain_openvpn_owner_selection', ROOT/'deploy/test_node_chain_openvpn_execution_owner.py')
        owner = importlib.util.module_from_spec(owner_spec)
        owner_spec.loader.exec_module(owner)
        for relative in ('android/build-sing-box-libbox.sh', 'ios/RouterVPN/prepare-libbox.sh'):
            source = (ROOT/relative).read_text()
            calls = [line for line in source.splitlines() if 'deploy/test_node_chain_openvpn_execution_owner.py" --core "$VENDOR"' in line]
            self.assertEqual(len(calls), 1, relative)
            self.assertIn('--race --tags ', calls[0])
            self.assertIn('with_openvpn', calls[0])
            self.assertNotIn('||', calls[0])
            commands = [shlex.split(line) for line in source.splitlines()
                        if re.match(r'\s*(?:go|go_retry) test ', line)]
            for package, names in roots.items():
                patterns = [command[command.index('-run')+1] for command in commands if package in command and '-run' in command]
                platform = 'android' if relative.startswith('android/') else 'ios'
                if package in ('.', './route'):
                    # These two roots are compiled and enumerated by the mobile
                    # grouping driver after the direct, explicitly named phases.
                    scope = platform+'-chain'
                    prefix = '$ROOT/..' if platform == 'android' else '$ROOT/../..'
                    line = 'python3 "'+prefix+'/deploy/test_mobile_go_groups.py" '+scope+' "$VENDOR"'
                    self.assertEqual(sum(row.strip() == line for row in source.splitlines()),1)
                    group_source = (ROOT/'deploy/test_mobile_go_groups.py').read_text()
                    selector = '^TestRouterVPNNodeChain' if platform == 'android' else '^TestRouterVPN(Strategy|NodeChain)'
                    self.assertIn('"'+selector+'", 90',group_source)
                    self.assertIn('listing = subprocess.check_output([str(image), "-test.list=" + selector]',group_source)
                    self.assertIn('for root in roots]',group_source)
                    patterns.append(selector)
                if package == shared_package:
                    driver = '/deploy/test_node_chain_candidate_preparation.py" --vendor "$VENDOR" --go "$(command -v go)"'
                    calls = [line.strip() for line in source.splitlines() if driver in line]
                    prefix = '$ROOT/..' if relative.startswith('android/') else '$ROOT/../..'
                    self.assertEqual(calls, ['python3 "'+prefix+driver])
                    patterns += ['^'+re.escape(name)+'$' for name in candidate.ROOTS[candidate.PACKAGE+'/experimental/libbox/routervpn/mobilemultihop']]
                if package == '.':
                    imports = [row.strip() for row in source.splitlines() if 'deploy/test_node_chain_multiple_imported_execution_owner.py" --core "$VENDOR"' in row]
                    self.assertEqual(len(imports),1,relative)
                    self.assertTrue(imports[0].startswith('python3 "') and '--race --tags ' in imports[0] and '||' not in imports[0])
                    patterns += [owner.POSITIVE.selection(), owner.STUB.selection(), extra.BOX.selection()]
                for name in names:
                    self.assertTrue(any(re.search(pattern, name) for pattern in patterns), (relative, package, name))
        desktop = ast.parse((ROOT/'deploy/build-native-runtime.py').read_text())
        commands = [[item.value if isinstance(item, ast.Constant) and isinstance(item.value, str) else ''
                     for item in node.elts] for node in ast.walk(desktop) if isinstance(node, ast.List)]
        # The desktop builder discovers these roots from one retained native
        # image, then runs every original family. Follow that actual executable
        # invocation; a literal -run list is no longer the only selection path.
        loader = ast.parse("root_phases = load('desktop_native_root_phases', 'test_desktop_native_root_phases.py')").body[0]
        invoke = ast.parse("root_phases.execute(source, target, ','.join(tags(target)), env, run)").body[0].value
        self.assertEqual(sum(ast.dump(node) == ast.dump(loader) for node in ast.walk(desktop)), 1)
        self.assertEqual(sum(ast.dump(node) == ast.dump(invoke) for node in ast.walk(desktop)), 1)
        spec = importlib.util.spec_from_file_location('selected_desktop_root_phases', ROOT/'deploy/test_desktop_native_root_phases.py')
        phases = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(phases)
        # Verify the exact desktop invocation independently of its expression
        # arguments before accepting the driver's positive root selection.
        desktop_source = (ROOT/'deploy/build-native-runtime.py').read_text()
        self.assertEqual(desktop_source.count("ROOT/'deploy/test_node_chain_openvpn_execution_owner.py'"), 1)
        self.assertIn("'--core', source, '--go', 'go', '--tags', ','.join(tags(target))", desktop_source)
        self.assertIn("'--tagged-only', *(['--race'] if race else [])", desktop_source)
        stub_source = (ROOT/'mobile/chain/openvpn_execution_stub_test.go.tmpl').read_text()
        self.assertTrue(stub_source.startswith('//go:build !with_openvpn\n'))
        # Schema6's actual Linux driver owns the seventeen public-route Box
        # records separately from the generic native phases. Verify its existing
        # required builder invocation before accounting for those exact roots.
        imported_spec = importlib.util.spec_from_file_location('selected_multiple_imported_runner', ROOT/'deploy/test_node_chain_multiple_imported_native_runner.py')
        imported = importlib.util.module_from_spec(imported_spec)
        imported_spec.loader.exec_module(imported)
        imported.required_wiring(desktop_source)
        imported_patterns = ['^'+re.escape(name)+'$' for name in imported.RUN.BOX_CASES]
        def selected_patterns(package):
            direct = [command[command.index('-run')+1] for command in commands if package in command and '-run' in command]
            return direct + ([phases.SELECTION, owner.POSITIVE.selection(), extra.BOX.selection(), extra.DESKTOP_BOX.selection(), *imported_patterns] if package == '.' else [])
        for package, names in roots.items():
            if package == './experimental/libbox':
                continue  # Desktop owns its original command-process lifecycle.
            patterns = selected_patterns(package)
            for name in names:
                if package == '.' and name == owner.PREFIX+'WithoutSupport':
                    continue  # Excluded by its verified !with_openvpn build tag on desktop.
                self.assertTrue(any(re.search(pattern, name) for pattern in patterns), ('desktop', package, name))
        for template in ('node_chain_box_physical_test.go.tmpl',):
            package = '.' if template.startswith('node_chain_box') else './cmd/sing-box'
            patterns = selected_patterns(package)
            for name in re.findall(r'^func (Test\w+)\(', (ROOT/'mobile/desktop'/template).read_text(), re.M):
                self.assertTrue(any(re.search(pattern, name) for pattern in patterns), ('desktop', package, name))


    def test_android_sdk_selects_all_required_ordered_latency_families(self):
        # These are build-selection contracts, not evidence that native fixtures
        # ran. The separate native fifty gate supplies required peer/IO evidence.
        required = (
            'TestRouterNodeChainLatencyRequiresOriginalProvedFactory',
            'TestRouterNodeChainLatencyKeepsOriginalAdmissionDeadline',
            'TestRouterNodeChainOrdinaryEncryptedOrderedFifty',
            'TestRouterNodeChainRemainingEncryptedOrderedFifty',
        )
        original = ('Multihop', 'NativeWireGuard', 'NativeAmnezia', 'NativePerformance',
                    'NativeBaseStartLayer', 'NativeSIP003StartLayer', 'MTU',
                    'NodeChainBridge', 'NodeChainSOCKS', 'NodeChainCONNECT')
        def require_selected(shell):
            commands = [shlex.split(line) for line in shell.splitlines()
                        if re.match(r'\s*go_retry test ', line)]
            selected = [command for command in commands if './experimental/libbox' in command and '-run' in command]
            self.assertEqual(len(selected), 1, 'preserve the one explicit SDK libbox test selector')
            command = selected[0]
            self.assertIn('-count=1', command)
            self.assertIn('-tags', command)
            self.assertTrue({'with_quic', 'with_wireguard', 'with_gvisor'}.issubset(
                command[command.index('-tags')+1].split(',')))
            self.assertIn('-run', command)
            selector = re.compile(command[command.index('-run')+1])
            for name in (*required, *('TestRouter'+family for family in original)):
                self.assertIsNotNone(selector.search(name), 'actual SDK command omits '+name)
        shell = (ROOT/'android/build-sing-box-libbox.sh').read_text()
        require_selected(shell)
        for family in ('NodeChainLatency', 'NodeChainOrdinary', 'NodeChainRemaining'):
            anchor = '|'+family
            self.assertEqual(shell.count(anchor), 1)
            changed = shell.replace(anchor, '', 1)+'\n# decoy '+anchor+'\n'
            with self.subTest(omitted=family), self.assertRaises(AssertionError):
                require_selected(changed)


class OpenVPNPrefixProjection(unittest.TestCase):
    def test_exact_component_sources_and_original_clock_bounds(self):
        template = 'openvpn_prefix_box_test.go.tmpl'
        target = 'routervpn_node_chain_openvpn_prefix_test.go'
        self.assertEqual(PREP.TEMPLATES.get(template), target)
        self.assertEqual(list(PREP.TEMPLATES.values()).count(target), 1)
        spec = importlib.util.spec_from_file_location('openvpn_prefix_desktop_prep', ROOT/'deploy/prepare-desktop-external.py')
        desktop = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(desktop)
        physical = 'node_chain_openvpn_box_physical_test.go.tmpl'
        physical_target = 'routervpn_desktop_node_chain_openvpn_box_physical_test.go'
        self.assertNotIn(physical, PREP.TEMPLATES)
        self.assertEqual(desktop.BOX_TEMPLATES.get(physical), physical_target)
        self.assertEqual(list(desktop.BOX_TEMPLATES.values()).count(physical_target), 1)
        common = (ROOT/'mobile/chain'/template).read_text()
        self.assertNotIn('routerVPNDesktopNodeChainPhysicalTarget', common)
        self.assertNotIn('TestRouterVPNNodeChainOpenVPNPrefixPhysicalTarget', common)
        self.assertNotIn('TestRouterVPNNodeChainOriginalImportedSSPhysicalTarget', common)
        self.assertIn('TestRouterVPNNodeChainOpenVPNPrefixMTUOriginalEndpoint', common)
        physical_source = (ROOT/'mobile/desktop'/physical).read_text()
        self.assertIn('TestRouterVPNNodeChainOpenVPNPrefixPhysicalTarget', physical_source)
        self.assertIn('TestRouterVPNNodeChainOriginalImportedSSPhysicalTarget', physical_source)
        peer = 'node_chain_openvpn_prefix_test.go.tmpl'
        relative = 'protocol/routervpnamnezia/routervpn_desktop_node_chain_openvpn_prefix_test.go'
        self.assertEqual(desktop.PEER_TEMPLATES.get(peer), relative)
        self.assertEqual(list(desktop.PEER_TEMPLATES.values()).count(relative), 1)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            desktop.copy_encrypted_peer_templates(destination)
            self.assertEqual((destination/relative).read_bytes(), (ROOT/'mobile/desktop'/peer).read_bytes())
        old = (ROOT/'mobile/desktop/node_chain_openvpn_peer_test.go.tmpl').read_text()
        new = (ROOT/'mobile/desktop'/peer).read_text()
        self.assertIn('return nodeChainOpenVPNStartBounded(t, mode, network, fault, 12*time.Second)', old)
        self.assertIn('nodeChainOpenVPNStartBounded(t, mode, network, "", 45*time.Second)', old)
        self.assertIn('nodeChainOpenVPNStartPrefixes(t, mode, network, "", 170*time.Second, count)', new)
        self.assertIn('context.WithTimeout(f.ctx, 5*time.Second)', new)
        self.assertIn('for position := group * 2; position < group*2+2; position++', new)


class ImportedSSPrefixProjection(unittest.TestCase):
    def test_exact_mobile_desktop_and_peer_ownership(self):
        common = 'imported_prefix_box_test.go.tmpl'
        common_target = 'routervpn_node_chain_imported_prefix_test.go'
        self.assertEqual(PREP.TEMPLATES.get(common), common_target)
        spec = importlib.util.spec_from_file_location('ss_prefix_desktop_prep', ROOT/'deploy/prepare-desktop-external.py')
        desktop = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(desktop)
        physical = 'node_chain_imported_prefix_physical_test.go.tmpl'
        physical_target = 'routervpn_desktop_node_chain_imported_prefix_physical_test.go'
        self.assertNotIn(physical, PREP.TEMPLATES)
        self.assertEqual(desktop.BOX_TEMPLATES.get(physical), physical_target)
        self.assertNotIn('routerVPNDesktopNodeChainPhysicalTarget', (ROOT/'mobile/chain'/common).read_text())
        self.assertIn('TestRouterVPNNodeChainImportedSSPrefixMTUOriginalOwners', (ROOT/'mobile/chain'/common).read_text())
        peer = 'node_chain_imported_prefix_test.go.tmpl'
        target = 'protocol/routervpnamnezia/routervpn_desktop_node_chain_imported_prefix_test.go'
        self.assertEqual(desktop.PEER_TEMPLATES.get(peer), target)
        self.assertEqual(list(desktop.PEER_TEMPLATES.values()).count(target), 1)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            desktop.copy_encrypted_peer_templates(destination)
            self.assertEqual((destination/target).read_bytes(), (ROOT/'mobile/desktop'/peer).read_bytes())
        source = (ROOT/'mobile/desktop'/peer).read_text()
        self.assertIn('count, 170*time.Second)', source)
        self.assertIn('fault, 6, 12*time.Second)', source)
        self.assertIn('context.WithTimeout(f.ctx, 5*time.Second)', source)
        self.assertIn('for position := group * 2; position < group*2+2; position++', source)
        self.assertNotIn('OpenVPNMiddleStateContext', source)


if __name__ == '__main__':
    unittest.main()
