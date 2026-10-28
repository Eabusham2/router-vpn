#!/usr/bin/env python3
"""Exercise selective desktop PT preparation against actual pinned Git inputs.

Only the native checkout's metadata is read. All module edits, source mutation
controls and generated ownership are exercised in disposable directories.
"""
from pathlib import Path
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('desktop_tor_preparation', ROOT/'deploy/prepare-desktop-external.py')
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
GO, ORIGINALS = 'go', {}


def snapshot(root):
    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob('*') if path.is_file() and not path.is_symlink()}


class DesktopPTPreparation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='desktop-tor-preparation-')
        self.addCleanup(self.temp.cleanup)
        self.vendor = Path(self.temp.name)/'core'
        for relative, raw in ORIGINALS.items():
            path = self.vendor/relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.real_output = subprocess.check_output

        def captured_git(command, **kwargs):
            if command[0] != 'git':
                return self.real_output(command, **kwargs)
            args = command[3:] if command[1:2] == ['-C'] else command[1:]
            if args == ['rev-parse', 'HEAD']:
                return PREP.PIN+'\n' if kwargs.get('text') else (PREP.PIN+'\n').encode()
            if len(args) == 2 and args[0] == 'show' and args[1].startswith(PREP.PIN+':'):
                raw = ORIGINALS[args[1].split(':', 1)[1]]
                return raw.decode() if kwargs.get('text') else raw
            raise AssertionError('Unexpected native metadata command: '+repr(command))

        self.captured_git = captured_git
        self.addCleanup(patch.stopall)
        patch.object(PREP.subprocess, 'check_output', side_effect=captured_git).start()

    def prepare(self):
        with contextlib.redirect_stdout(io.StringIO()):
            PREP.prepare_desktop_pt(self.vendor, GO)

    def rejected_without_writes(self, match=None):
        before = snapshot(self.vendor)
        with self.assertRaises((ValueError, RuntimeError)) as caught:
            self.prepare()
        if match:
            self.assertIn(match, str(caught.exception))
        self.assertEqual(snapshot(self.vendor), before)

    def test_actual_selective_sources_and_repeat_preparation(self):
        forbidden = AssertionError('Desktop preparation invoked the embedded Tor/C pipeline')
        with patch.object(PREP.TOR, 'prepare', side_effect=forbidden), \
             patch.object(PREP.TOR, 'copies', side_effect=forbidden), \
             patch.object(PREP.TOR.TORPACK, 'prepare', side_effect=forbidden):
            self.prepare()
            first = snapshot(self.vendor)
            self.prepare()
            self.assertEqual(snapshot(self.vendor), first)
        content = PREP.pt_copies()
        for relative, raw in content.items():
            self.assertEqual((self.vendor/relative).read_bytes(), raw)
            self.assertFalse(relative.endswith(('/go.mod', '/go.sum')))
            if relative.endswith('.go'):
                self.assertNotIn(b'"router-vpn/', raw)
        for name in PREP.PT_TEMPLATES:
            self.assertEqual((self.vendor/'routervpn/desktoppt'/name.removesuffix('.tmpl')).read_bytes(),
                             (ROOT/'mobile/desktop'/name).read_bytes())
        # These real entry-routed PT exchanges belong to the same generated
        # native package selected by the mandatory shipping build gate.
        for name in ('tor_pt_entry_peers_test.go.tmpl', 'tor_pt_entry_traffic_test.go.tmpl',
                     'tor_physical.go.tmpl', 'tor_physical_test.go.tmpl',
                     'tor_physical_source_unix_test.go.tmpl'):
            self.assertIn(name, PREP.PT_TEMPLATES)
        traffic = (self.vendor/'routervpn/desktoppt/tor_pt_entry_traffic_test.go').read_text()
        for name in ('MeekTLS', 'WebTunnelTLS', 'SnowflakeTraffic'):
            self.assertIn('func TestRouterVPNDesktopTorPTEntryCarriesReal'+name+'(', traffic)
        self.assertEqual(PREP.BOX_TEMPLATES.get('tor_box_lastrelay.go.tmpl'), 'routervpn_desktop_tor_box_lastrelay.go')
        self.assertEqual(PREP.BOX_TEMPLATES.get('tor_box_lastrelay_test.go.tmpl'), 'routervpn_desktop_tor_box_lastrelay_test.go')
        self.assertEqual(PREP.BOX_TEMPLATES.get('tor_box_lastrelay_server_test.go.tmpl'), 'routervpn_desktop_tor_box_lastrelay_server_test.go')
        for name, relative in {**PREP.BOX_TEMPLATES, **PREP.ROUTE_TEMPLATES}.items():
            self.assertEqual((self.vendor/relative).read_bytes(),
                             (ROOT/'mobile/desktop'/name).read_bytes())
        for name in ('network.go', 'upstream.go'):
            self.assertEqual((self.vendor/'routervpn/desktoppt'/name).read_bytes(),
                             (ROOT/'mobile/toroutbound'/(name+'.tmpl')).read_bytes().replace(
                                 b'package routervpntor\n', b'package routervpndesktoppt\n', 1))
        self.assertFalse((self.vendor/'protocol/routervpntor').exists())
        self.assertFalse((self.vendor/'routervpn/nativetor').exists())
        self.assertEqual([path.relative_to(self.vendor).as_posix() for path in self.vendor.rglob('go.mod')], ['go.mod'])
        self.assertEqual((self.vendor/'dns/transport_adapter.go').read_bytes(),
                         (ROOT/'mobile/toroutbound/dns_adapter.go.tmpl').read_bytes())
        registry = (self.vendor/'include/registry.go').read_text()
        self.assertEqual(registry.count('routervpndesktoppt.RegisterNetworkOwner(registry)'), 1)
        self.assertEqual(registry.count('routervpndesktoppt.RegisterPhysicalOutbound(registry)'), 1)
        self.assertEqual((self.vendor/'route/network.go').read_text().count(PREP.NETWORK_DISPATCH), 1)
        record = json.loads((self.vendor/PREP.PT_OWNER).read_bytes())
        self.assertEqual(record['files'], {name: hashlib.sha256(raw).hexdigest() for name, raw in content.items()})
        self.assertEqual(record['source_sha256'], PREP.digest())

    def test_shipping_preparer_calls_selective_pipeline_without_mobile_tor(self):
        captured = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOENV='off')
        with patch.object(PREP, 'prepare_desktop_pt') as selective, patch.object(PREP, 'write') as writes, \
             patch.object(PREP.MTU, 'prepare'), patch.object(PREP.DESKTOP_MTU, 'prepare'), \
             patch.object(PREP.STRATEGY, 'prepare'), patch.object(PREP.EXTERNAL, 'prepare'), \
             patch.object(PREP, 'prepare_network_startup') as startup, \
             patch.object(PREP.RELAY.OPENVPN_REMOTE, 'prepare'), \
             contextlib.redirect_stdout(io.StringIO()):
            PREP.prepare(self.vendor, GO, env=captured)
            selective.assert_called_once_with(self.vendor.resolve(), GO, env=captured)
            startup.assert_called_once_with(self.vendor.resolve())
            generated = {call.args[1]: call.args[2] for call in writes.call_args_list}
            for name in ('external_tor_comparison.go.tmpl', 'external_tor_comparison_test.go.tmpl',
                         'external_tor_comparison_whole_test.go.tmpl'):
                self.assertEqual(generated['cmd/sing-box/routervpn_'+name.removesuffix('.tmpl')],
                                 (ROOT/'mobile/desktop'/name).read_bytes())
            self.assertEqual(generated['routervpn/mobiletor/desktop_lastrelay.go'],
                             (ROOT/'internal/mobiletor/desktop_lastrelay.go').read_bytes())
            self.assertEqual(generated['routervpn/mobiletor/desktop_socket_broker_test.go'],
                             (ROOT/'internal/mobiletor/desktop_socket_broker_test.go').read_bytes())
            for name in ('desktop_socket_source_unix_test.go', 'desktop_socket_source_privileged_test.go'):
                self.assertEqual(generated['routervpn/mobiletor/'+name], (ROOT/'internal/mobiletor'/name).read_bytes())
            for relative, raw in PREP.comparison_client_contract().items():
                self.assertEqual(generated[relative], raw)

    def test_native_receipts_compile_the_actual_published_controller_contract(self):
        source = ROOT/'cmd/client/desktop_tor_comparison_native.go'
        exact = ROOT/'cmd/client/multihop_exact_json.go'
        self.assertIn(source, PREP.inputs())
        self.assertIn(exact, PREP.inputs())
        generated = PREP.comparison_client_contract()
        validator = source.read_text().split('func desktopTorComparisonStatus(', 1)[1].split('func (c *desktopTorComparisonClient) read(', 1)[0]
        self.assertIn(('func desktopTorComparisonStatus('+validator).encode(), generated['cmd/sing-box/routervpn_tor_controller_status_test.go'])
        self.assertEqual(generated['cmd/sing-box/routervpn_tor_controller_json_test.go'], exact.read_bytes().replace(
            b'"router-vpn/internal/multihoprelay"', b'"github.com/sagernet/sing-box/experimental/libbox/routervpn/multihoprelay"'))
        read = Path.read_text
        def changed(path, *args, **kwargs):
            text = read(path, *args, **kwargs)
            return text.replace('func desktopTorComparisonStatus(', 'func removedTorStatus(') if path == source else text
        with patch.object(Path, 'read_text', changed), self.assertRaisesRegex(ValueError, 'receipt contract seam'):
            PREP.comparison_client_contract()

    def test_native_network_startup_joins_exact_callbacks_and_preserves_repeat_preparation(self):
        self.prepare()
        with contextlib.redirect_stdout(io.StringIO()):
            PREP.STRATEGY.prepare(self.vendor, mobile=False)
        PREP.prepare_network_startup(self.vendor)
        target = self.vendor/'route/network.go'
        first = target.read_bytes()
        self.assertEqual(first.count(b'r.routerVPNStartup.start(r.ctx,'), 1)
        self.assertEqual(first.count(b'r.routerVPNStartup.stop('), 1)
        self.assertEqual(first.count(b'r.routerVPNStartup.begin()'), 3)
        self.assertEqual(first.count(b'defer finish()'), 3)
        self.assertEqual(first.count(PREP.NETWORK_DISPATCH.encode()), 1)
        # Exercise the real shared strategy preparer again. Its atomic lifetime
        # edits must neither erase nor duplicate the owned callback joins.
        with contextlib.redirect_stdout(io.StringIO()):
            PREP.STRATEGY.prepare(self.vendor, mobile=False)
        PREP.prepare_network_startup(self.vendor)
        self.prepare()
        self.assertEqual(target.read_bytes(), first)
        for before, after in (
            ('r.routerVPNStartup.start(r.ctx,', 'r.routerVPNStartup.start(context.Background(),'),
            ('defer finish()', 'finish()'),
            ('r.routerVPNStartup.stop(func() { r.started.Store(false) })', 'r.started.Store(false)'),
            ('r.routerVPNStartup.begin()', 'foreignStartup.begin()'),
            ('r.updateInterface(updateContext, defaultInterface)', 'r.updateInterface(context.Background(), defaultInterface)'),
        ):
            with self.subTest(before=before):
                target.write_text(first.decode().replace(before, after, 1))
                captured = snapshot(self.vendor)
                with self.assertRaisesRegex(ValueError, 'startup differs'):
                    PREP.prepare_network_startup(self.vendor)
                self.assertEqual(snapshot(self.vendor), captured)
        target.write_bytes(first)

    def test_actual_module_commands_use_captured_toolchain_environment(self):
        captured = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOENV='off')
        before = snapshot(self.vendor)
        # No network/download is needed: the fixture uses the installed pinned
        # binary. Poison the ambient selector so dropping the captured env at
        # any actual version/read/edit command is an executable failure.
        with patch.dict(os.environ, {'GOTOOLCHAIN': 'invalid-routervpn-ambient-toolchain'}):
            with self.assertRaises(subprocess.CalledProcessError):
                self.prepare()
            self.assertEqual(snapshot(self.vendor), before)
            with contextlib.redirect_stdout(io.StringIO()):
                PREP.prepare_desktop_pt(self.vendor, GO, env=captured)
        self.assertTrue((self.vendor/PREP.PT_OWNER).is_file())
        actual = json.loads(self.real_output([GO, 'mod', 'edit', '-json'], cwd=self.vendor, env=captured))
        self.assertEqual(actual['Module']['Path'], PREP.MODULE)
        self.assertGreaterEqual(PREP.TOR.go_version_key(actual['Go']), PREP.TOR.go_version_key('1.26.0'))

    def test_real_module_edit_retains_newer_native_versions_and_single_module(self):
        subprocess.run([GO, 'mod', 'edit', '-go=1.26.3', '-require=golang.org/x/net@v0.59.1',
                        '-replace=example.invalid/retained=./retained'], cwd=self.vendor, check=True)
        self.prepare()
        actual = json.loads(self.real_output([GO, 'mod', 'edit', '-json'], cwd=self.vendor))
        self.assertEqual(actual['Module']['Path'], PREP.MODULE)
        self.assertEqual(actual['Go'], '1.26.3')
        self.assertEqual(next(row['Version'] for row in actual['Require'] if row['Path'] == 'golang.org/x/net'), 'v0.59.1')
        self.assertTrue(any(row['Old']['Path'] == 'example.invalid/retained' and row['New']['Path'] == './retained'
                            for row in actual['Replace']))
        self.assertFalse(any(row['Path'] == 'router-vpn' for row in actual['Require']))

    def test_crlf_preparation_keeps_exact_source_and_raw_replacement_guards(self):
        metadata = ('include/registry.go', 'route/network.go')
        windows_inputs = (*metadata, 'dns/transport_adapter.go', 'go.mod', 'go.sum')
        for name in windows_inputs:
            self.assertIn(b'\n', ORIGINALS[name])
            (self.vendor/name).write_bytes(ORIGINALS[name].replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
        self.prepare()
        first = snapshot(self.vendor)
        for name in metadata:
            self.assertNotIn(b'\r', first[name])
        self.assertEqual(first['include/registry.go'].count(b'routervpndesktoppt.RegisterNetworkOwner(registry)'), 1)
        self.assertEqual(first['route/network.go'].count(PREP.NETWORK_DISPATCH.encode()), 1)
        self.assertEqual(first['dns/transport_adapter.go'], (ROOT/'mobile/toroutbound/dns_adapter.go.tmpl').read_bytes())
        self.assertTrue(first['go.mod'].startswith(('module '+PREP.MODULE+'\n').encode()))
        # A previously prepared Windows file is the same exact Go source.
        for name in windows_inputs:
            (self.vendor/name).write_bytes(first[name].replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
        self.prepare()
        self.assertEqual(snapshot(self.vendor), first)
        # Normalization must not hide even a newline-only replacement while
        # the owned module update is staged: the final guard compares bytes.
        actual = PREP.TOR.prepare_modules
        def replace_captured_registry(staged, go, **kwargs):
            actual(staged, go, **kwargs)
            target = self.vendor/'include/registry.go'
            target.write_bytes(target.read_bytes().replace(b'\n', b'\r\n'))
        with patch.object(PREP.TOR, 'prepare_modules', side_effect=replace_captured_registry), \
             self.assertRaisesRegex(ValueError, 'target changed before adoption'):
            self.prepare()
        changed = snapshot(self.vendor)
        self.assertEqual(changed.pop('include/registry.go'), first['include/registry.go'].replace(b'\n', b'\r\n'))
        expected = dict(first)
        expected.pop('include/registry.go')
        self.assertEqual(changed, expected)

    def test_owned_module_staging_resolves_temp_alias_before_containment(self):
        actual_temp = tempfile.TemporaryDirectory
        actual_modules = PREP.TOR.prepare_modules
        staging = Path(self.temp.name)/'staging-real'
        alias = Path(self.temp.name)/'staging-alias'
        staging.mkdir()
        try:
            alias.symlink_to(staging, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('Temporary-directory alias creation unavailable on this host')
        observed = []
        @contextlib.contextmanager
        def owned_alias(**kwargs):
            with actual_temp(dir=alias, **kwargs) as directory:
                self.assertNotEqual(Path(directory), Path(directory).resolve())
                yield directory
        def prepare_actual_modules(directory, go, **kwargs):
            observed.append(directory)
            actual_modules(directory, go, **kwargs)
            self.assertEqual(directory, directory.resolve(strict=True))
        with patch.object(PREP.tempfile, 'TemporaryDirectory', side_effect=owned_alias), \
             patch.object(PREP.TOR, 'prepare_modules', side_effect=prepare_actual_modules):
            self.prepare()
        self.assertEqual(len(observed), 1)
        self.assertTrue((self.vendor/PREP.PT_OWNER).is_file())
        self.assertEqual(list(staging.iterdir()), [])
        # Canonicalizing our own temporary root does not admit an escaped
        # destination or relax validation of the caller's native checkout.
        with self.assertRaisesRegex(ValueError, 'Unsafe native Tor source destination'):
            PREP.TOR.destination(self.vendor, '../outside.go')

    def test_checksum_conflict_and_foreign_module_fail_before_adoption(self):
        lock = json.loads((ROOT/'mobile/torpt/SOURCE_LOCK.json').read_text())
        item = lock['modules'][0]
        prefix = item['path']+' '+item['version']+' '
        sums = [line for line in ORIGINALS['go.sum'].decode().splitlines() if not line.startswith(prefix)]
        (self.vendor/'go.sum').write_text('\n'.join([*sums, prefix+'h1:foreign-checksum'])+'\n')
        self.rejected_without_writes('checksum conflicts')
        (self.vendor/'go.sum').write_bytes(ORIGINALS['go.sum'])
        (self.vendor/'go.mod').write_text('module example.invalid/second-runtime\n\ngo 1.26.3\n')
        self.rejected_without_writes('single native Go module')

    def test_lock_version_and_toolchain_guards_do_not_partially_change_metadata(self):
        small = Path(self.temp.name)/'source/mobile/torpt'
        small.mkdir(parents=True)
        for name in ('go.mod', 'go.sum', 'SOURCE_LOCK.json'):
            shutil.copyfile(ROOT/'mobile/torpt'/name, small/name)
        lock = json.loads((small/'SOURCE_LOCK.json').read_text())
        lock['modules'][0]['version'] = 'v0.0.0'
        (small/'SOURCE_LOCK.json').write_text(json.dumps(lock))
        with patch.object(PREP.TOR, 'ROOT', small.parents[1]):
            self.rejected_without_writes('actual module requirements')
        with patch.object(PREP.subprocess, 'check_output', side_effect=lambda command, **kwargs:
                          'go version go1.25.0 linux/amd64\n' if command == [GO, 'version'] else self.captured_git(command, **kwargs)):
            self.rejected_without_writes('pinned Go 1.26.3')

    def test_generated_source_drift_extra_files_and_foreign_owner_are_rejected(self):
        self.prepare()
        target = self.vendor/'routervpn/desktoppt/tor_network.go'
        original = target.read_bytes()
        target.write_bytes(original+b'\n// foreign observer edit\n')
        self.rejected_without_writes('changed desktop PT')
        target.write_bytes(original)
        unknown = self.vendor/'routervpn/desktoppt/unowned.go'
        unknown.write_text('package routervpndesktoppt\n')
        self.rejected_without_writes('Unowned file')
        unknown.unlink()
        owner = self.vendor/PREP.PT_OWNER
        record = json.loads(owner.read_bytes())
        record['files']['cmd/sing-box/unrelated.go'] = 'a'*64
        owner.write_text(json.dumps(record))
        self.rejected_without_writes('unrelated native source')

    def test_unowned_and_linked_destinations_are_rejected(self):
        target = self.vendor/'routervpn/desktoppt/tor_pt.go'
        target.parent.mkdir(parents=True)
        target.write_text('foreign native source\n')
        self.rejected_without_writes('unowned desktop PT')
        target.unlink()
        outside = Path(self.temp.name)/'foreign.go'
        outside.write_text('must remain unchanged\n')
        try:
            target.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest('Symlink creation unavailable on this host')
        self.rejected_without_writes('Linked')
        self.assertEqual(outside.read_text(), 'must remain unchanged\n')

    def test_native_box_inputs_require_exact_owned_root_files(self):
        self.prepare()
        target = self.vendor/'routervpn_desktop_tor_box.go'
        original = target.read_bytes()
        target.write_bytes(original+b'\n// replaced native Box proof\n')
        self.rejected_without_writes('changed desktop PT')
        target.write_bytes(original)
        self.prepare()
        record = json.loads((self.vendor/PREP.PT_OWNER).read_bytes())
        for relative in PREP.BOX_TEMPLATES.values():
            self.assertEqual(record['files'][relative], hashlib.sha256((self.vendor/relative).read_bytes()).hexdigest())

    def test_wrong_core_namespace_type_and_root_alias_fail_without_writes(self):
        with patch.object(PREP.subprocess, 'check_output', return_value='different-native-core\n'):
            self.rejected_without_writes('exact pinned native core')
        directory = self.vendor/'routervpn/desktoppt'
        directory.parent.mkdir()
        directory.write_text('foreign file where a source directory should be\n')
        self.rejected_without_writes('not a directory')
        directory.unlink()
        alias = Path(self.temp.name)/'alias'
        try:
            alias.symlink_to(self.vendor, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('Symlink creation unavailable on this host')
        before = snapshot(self.vendor)
        with self.assertRaisesRegex(ValueError, 'unlinked native checkout'):
            PREP.prepare_desktop_pt(alias, GO)
        self.assertEqual(snapshot(self.vendor), before)

    def test_registry_rejects_duplicate_misplaced_or_wrong_owner_registration(self):
        target = self.vendor/'include/registry.go'
        generated = PREP.pt_registry_source(target.read_text()).decode()
        imported = '\t"'+PREP.MODULE+'/routervpn/desktoppt"'
        registered = '\troutervpndesktoppt.RegisterNetworkOwner(registry)'
        server_registered = '\troutervpndesktoppt.RegisterServerTor(registry)'
        local_registered = '\troutervpndesktoppt.RegisterLocalTor(registry)'
        dns_registered = '\troutervpndesktoppt.RegisterLocalTorDNS(registry)'
        forms = [
            generated.replace(imported, imported+'\n'+imported),
            generated.replace(registered, registered+'\n'+registered),
            generated.replace(registered, registered.replace('(registry)', '(foreignRegistry)')),
            generated.replace(imported, '\tforeign '+imported.strip()),
            generated.replace('\tresolved.RegisterService(registry)\n'+registered,
                              registered+'\n\tresolved.RegisterService(registry)'),
            generated.replace(registered, '')+'\nfunc foreign() {\n'+registered+'\n}\n',
            generated.replace(server_registered, server_registered+'\n'+server_registered),
            generated.replace(server_registered, server_registered.replace('(registry)', '(foreignRegistry)')),
            generated.replace(server_registered, '')+'\nfunc foreign() {\n'+server_registered+'\n}\n',
            generated.replace(local_registered, local_registered+'\n'+local_registered),
            generated.replace(local_registered, local_registered.replace('(registry)', '(foreignRegistry)')),
            generated.replace(local_registered, '')+'\nfunc foreign() {\n'+local_registered+'\n}\n',
            generated.replace(dns_registered, dns_registered+'\n'+dns_registered),
            generated.replace(dns_registered, dns_registered.replace('(registry)', '(foreignRegistry)')),
            generated.replace(dns_registered, '')+'\nfunc foreign() {\n'+dns_registered+'\n}\n',
            ORIGINALS['include/registry.go'].decode()+'\n// '+PREP.MODULE+'/protocol/routervpntor\n',
        ]
        for source in forms:
            with self.subTest(source=source[-100:]):
                target.write_text(source)
                self.rejected_without_writes()

    def test_network_dispatch_rejects_bypassed_moved_and_duplicate_listeners(self):
        target = self.vendor/'route/network.go'
        generated = PREP.pt_network_source(self.vendor, target.read_text()).decode()
        for source in (
            generated.replace('listener.InterfaceUpdated(ctx)', 'listener.InterfaceUpdated(context.Background())', 1),
            generated.replace(PREP.NETWORK_DISPATCH, PREP.NETWORK_DISPATCH+PREP.NETWORK_DISPATCH),
            generated.replace(PREP.NETWORK_DISPATCH, '')+'\n'+PREP.NETWORK_DISPATCH,
            generated.replace('for _, owned := range manager.Services()', 'for _, owned := range []adapter.Service{}'),
        ):
            target.write_text(source)
            self.rejected_without_writes('network service dispatch differs')
        # Keep the separately owned strategy atomic-lifetime changes outside
        # ResetNetwork while requiring the exact service dispatch inside it.
        preserved = generated.replace('\tstarted                  bool\n', '\tstarted                  atomic.Bool\n')
        self.assertNotEqual(preserved, generated)
        target.write_text(preserved)
        self.prepare()
        self.assertEqual(target.read_text(), preserved)

    def test_dns_bootstrap_drift_is_rejected_before_any_source_or_module_write(self):
        target = self.vendor/'dns/transport_adapter.go'
        target.write_bytes((ROOT/'mobile/toroutbound/dns_adapter.go.tmpl').read_bytes()+b'\n// foreign selected resolver\n')
        self.rejected_without_writes('changed outside its exact preparation')

    def test_metadata_change_during_module_staging_is_not_overwritten(self):
        actual = PREP.TOR.prepare_modules
        def change_target(staged, go, **kwargs):
            actual(staged, go, **kwargs)
            (self.vendor/'go.sum').write_bytes(ORIGINALS['go.sum']+b'\n# foreign replacement\n')
        with patch.object(PREP.TOR, 'prepare_modules', side_effect=change_target), self.assertRaisesRegex(ValueError, 'target changed'):
            self.prepare()
        self.assertEqual((self.vendor/'go.sum').read_bytes(), ORIGINALS['go.sum']+b'\n# foreign replacement\n')
        self.assertEqual((self.vendor/'go.mod').read_bytes(), ORIGINALS['go.mod'])
        self.assertFalse((self.vendor/'routervpn').exists())

    def test_notices_and_cache_identity_bind_actual_pt_sources_and_observer(self):
        raw = PREP.desktop_pt_notices()
        notices = json.loads(raw)
        self.assertGreater(len(raw), 256*1024)
        self.assertLess(len(raw), 2*1024*1024)
        for name, text in notices.items():
            self.assertEqual((ROOT/name).read_text(), text)
        self.assertIn('mobile/torpt/LICENSE-DEPENDENCIES.json', notices)
        self.assertIn('mobile/torpt/go.mod', notices)
        self.assertIn('mobile/torpt/go.sum', notices)
        inputs = PREP.inputs()
        for name in (*PREP.PT_TEMPLATES, *PREP.ROUTE_TEMPLATES):
            self.assertIn(ROOT/'mobile/desktop'/name, inputs)
        self.assertIn(ROOT/'deploy/prepare-mobile-tor.py', inputs)
        self.assertIn(ROOT/'mobile/toroutbound/dns_adapter.go.tmpl', inputs)
        expected = PREP.digest()
        actual_read = Path.read_bytes
        changed = ROOT/'mobile/desktop/tor_network.go.tmpl'
        with patch.object(Path, 'read_bytes', lambda path:
                          actual_read(path)+b'\n// changed observer\n' if path == changed else actual_read(path)):
            self.assertNotEqual(PREP.digest(), expected)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', type=Path, required=True)
    parser.add_argument('--go', default=shutil.which('go') or 'go')
    args = parser.parse_args()
    vendor = args.vendor.resolve()
    head = subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip()
    if head != PREP.PIN:
        raise ValueError('Desktop preparation fixture requires the actual pinned native core')
    GO = args.go
    if subprocess.check_output([GO, 'version'], text=True).split()[2] != 'go1.26.3':
        raise ValueError('Desktop preparation fixture requires the actual Go 1.26.3 toolchain')
    ORIGINALS = {name: subprocess.check_output(['git', '-C', str(vendor), 'show', head+':'+name])
                 for name in ('include/registry.go', 'route/network.go', 'dns/transport_adapter.go', 'go.mod', 'go.sum',
                              'adapter/inbound/manager.go', 'adapter/outbound/manager.go', 'adapter/endpoint/manager.go',
                              'adapter/service/manager.go', 'dns/transport_manager.go')}
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(DesktopPTPreparation))
    raise SystemExit(not result.wasSuccessful())
