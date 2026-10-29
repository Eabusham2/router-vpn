#!/usr/bin/env python3
"""Execute macOS installer transactions in temporary roots, without host services."""
from __future__ import annotations
import argparse
import errno
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import pwd
import shutil
import struct
import subprocess
import sys
import tempfile
import types
import unittest
import venv
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT/'client/install-macos-native.py'
SPEC = importlib.util.spec_from_file_location('mac_install_file_fixtures', ROOT/'deploy/test_linux_native_install.py')
F = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(F)


def load(source=None):
    module = types.ModuleType('mac_install_target')
    module.__file__ = str(TARGET)
    exec(compile(source if source is not None else TARGET.read_text(), str(TARGET), 'exec'), module.__dict__)
    return module


M = load()


class LaunchBoundary:
    def __init__(self, installer, root, system):
        self.installer, self.root, self.system = installer, root, system
        self.loaded = False; self.calls = []; self.fail = None; self.failed = False
        self.query_failure = False

    def __call__(self, arguments, *, check=True):
        args = tuple(map(str, arguments)); self.calls.append(args)
        if self.fail is not None and self.fail in args and not self.failed:
            self.failed = True
            raise subprocess.CalledProcessError(21, args)
        if args[:2] == ('/bin/launchctl', 'print'):
            if args != ('/bin/launchctl', 'print', 'system/'+M.LABEL):
                raise AssertionError('Read another launchd domain')
            code = 5 if self.query_failure else 0 if self.loaded else 113
            message = 'Could not find service "'+M.LABEL+'" in domain for system'
            return subprocess.CompletedProcess(args, code, stdout='', stderr=message if code == 113 else 'query failed')
        if args[:2] == ('/bin/launchctl', 'bootout'):
            if not self.loaded or args[2] != 'system/'+M.LABEL:
                raise AssertionError('Unowned service teardown')
            self.loaded = False
        elif args[:2] == ('/bin/launchctl', 'bootstrap'):
            if self.loaded or args[2] != 'system' or args[3] != str(self.system/M.PLIST.lstrip('/')):
                raise AssertionError('Unowned service bootstrap')
            definition = plistlib.loads(Path(args[3]).read_bytes())
            if definition['ProgramArguments'] != M.launch_definition_arguments():
                raise AssertionError('Privileged service did not use the fixed supervisor')
            self.loaded = True
        elif args[:2] == ('/usr/bin/plutil', '-lint'):
            plistlib.loads(Path(args[2]).read_bytes())
        else:
            expected = ('/usr/bin/env', '-i', 'PATH='+str(self.root/'bin')+':/usr/bin:/bin:/usr/sbin:/sbin',
                        'HOMEVPN_ROOT='+str(self.root), str(self.root/'bin/python3'),
                        str(self.root/'modes/kill-switch-platform.py'), 'reassert')
            if args != expected or not (self.root/'controller-owner.json').is_file():
                raise AssertionError('Unbounded or premature protection process: '+repr(args))
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')


class MacInstallTransactions(unittest.TestCase):
    installer = M

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='routervpn-mac-installer-')
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.root, self.system = self.base/'installed', self.base/'system'
        self.system.mkdir()
        self.source = F.package_fixture(self.base/'package')
        F.write(self.source/'RouterVPN.app/Contents/MacOS/RouterVPN', '#!/bin/sh\nexit 0\n', 0o755)
        F.write(self.source/'RouterVPN.app/Contents/Info.plist', plistlib.dumps({'CFBundleIdentifier': 'com.eabusham.routervpn'}))
        F.write(self.source/'modes/kill-switch-platform.py', '# test only\n')
        self.uid = pwd.getpwnam('daemon').pw_uid
        self.python = Path('/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13')
        self.boundary = LaunchBoundary(self.installer, self.root, self.system)
        self.integration = self.installer.LaunchIntegration(self.system, self.boundary)
        self.verifications = []
        self.processes = []

    def verify(self, stage, python):
        self.assertEqual('new', stage.name)
        self.assertEqual(self.python, python)
        self.assertEqual(self.uid, json.loads((stage/'controller-owner.json').read_text())['caller_uid'])
        self.assertTrue((stage/'RouterVPN.app/Contents/MacOS/RouterVPN').is_file())
        self.verifications.append(stage)

    def install(self, **options):
        self.installer.install(self.source, self.uid, self.python, root=self.root,
                               integration=self.integration, verifier=options.pop('verifier', self.verify),
                               process_reader=lambda: list(self.processes), **options)

    def renew_boundary(self):
        self.integration = self.installer.LaunchIntegration(self.system, self.boundary)

    def test_first_install_has_one_root_owned_authority_and_no_http_daemon(self):
        self.install()
        record = json.loads((self.root/'controller-owner.json').read_text())
        self.assertEqual({'schema': 1, 'caller_uid': self.uid}, record)
        self.assertEqual(0o600, (self.root/'controller-owner.json').stat().st_mode & 0o777)
        self.assertEqual(0o755, self.root.stat().st_mode & 0o777)
        self.assertIn(str(self.python)+' -EsS "$@"', (self.root/'bin/python3').read_text())
        definition = plistlib.loads((self.system/M.PLIST.lstrip('/')).read_bytes())
        self.assertEqual(M.launch_definition_arguments(), definition['ProgramArguments'])
        self.assertNotIn('EnvironmentVariables', definition)
        self.assertTrue(self.boundary.loaded)
        self.assertEqual(1, len(self.verifications))
        self.assertFalse(any('kickstart' in call or 'enable' in call for call in self.boundary.calls))

    def test_actual_runtime_wrapper_excludes_global_site_and_untrusted_current_directory(self):
        runtime = self.base/'private-python'
        venv.EnvBuilder(with_pip=False).create(runtime)
        self.python = runtime/'bin/python3'
        libraries = list((runtime/'lib').glob('python*/site-packages'))
        self.assertEqual(1, len(libraries))
        site_marker, cwd_marker = self.base/'site-ran', self.base/'cwd-ran'
        (libraries[0]/'routervpn-negative.pth').write_text(
            'import pathlib; pathlib.Path(' + repr(str(site_marker)) + ').write_text("global site ran")\n')
        untrusted = self.base/'untrusted-cwd'; untrusted.mkdir()
        (untrusted/'json.py').write_text('open(' + repr(str(cwd_marker)) + ',"w").write("cwd imported")\nraise RuntimeError("untrusted CWD module")\n')
        self.install()
        script = self.root/'client/interpreter-proof.py'
        script.write_text('import json, os, sys\nprint(json.dumps([sys.flags.ignore_environment, sys.flags.no_user_site, sys.flags.no_site, os.environ.get("DYLD_FALLBACK_LIBRARY_PATH"), os.environ.get("DYLD_FALLBACK_FRAMEWORK_PATH")]))\n')
        wrapper = self.root/'bin/python3'
        environment = dict(os.environ, PYTHONPATH=str(untrusted), PYTHONHOME=str(untrusted))
        result = subprocess.run([wrapper, script], cwd=untrusted, env=environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [1, 1, 1, '/usr/lib', '/System/Library/Frameworks'])
        self.assertFalse(site_marker.exists(), 'global site initialization ran before the protected helper')
        self.assertFalse(cwd_marker.exists(), 'an untrusted CWD/PYTHONPATH module replaced the captured helper dependency')
        # The negative control executes the same generated wrapper with only
        # -S removed, proving this fixture really exposes global site code.
        broken = self.root/'bin/python-with-site'
        broken.write_text(wrapper.read_text().replace(' -EsS ', ' -Es ')); broken.chmod(0o700)
        result = subprocess.run([broken, script], cwd=untrusted, env=environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [1, 1, 0, '/usr/lib', '/System/Library/Frameworks'])
        self.assertTrue(site_marker.exists(), 'the global-site negative control did not reach its actual startup hook')
        self.assertFalse(cwd_marker.exists())

    def test_upgrade_preserves_private_owner_settings_and_open_file_isolation(self):
        self.install()
        F.write(self.root/'routers.json', '{"selected_id":"private","key":"keep-secret"}', 0o600)
        F.write(self.root/'generated/private.conf', 'private bytes', 0o600)
        F.write(self.root/'state.json', '{"mode":"last"}', 0o600)
        old = os.open(self.root/'RouterVPN.app/Contents/MacOS/RouterVPN', os.O_WRONLY)
        try:
            self.renew_boundary(); self.install()
            os.write(old, b'old open handle cannot rewrite trusted code')
            self.assertEqual('#!/bin/sh\nexit 0\n', (self.root/'RouterVPN.app/Contents/MacOS/RouterVPN').read_text())
        finally:
            os.close(old)
        self.assertEqual('private bytes', (self.root/'generated/private.conf').read_text())
        self.assertIn('keep-secret', (self.root/'routers.json').read_text())
        self.assertEqual('{"mode":"last"}', (self.root/'state.json').read_text())
        self.assertTrue(self.boundary.loaded)

    def test_live_install_lock_prevents_even_service_probe(self):
        lock = self.root.with_name(self.root.name+'.install.lock')
        descriptor = os.open(lock, os.O_RDWR|os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            with self.assertRaises(RuntimeError): self.install()
            self.assertEqual([], self.boundary.calls)
        finally:
            os.close(descriptor)

    def test_running_legacy_native_owner_prevents_promotion(self):
        self.processes = [str(self.root/'runtime/native/sing-box')]
        with self.assertRaises(RuntimeError): self.install()
        self.assertFalse(self.root.exists())
        self.assertFalse(self.boundary.loaded)

    def test_legacy_or_foreign_service_is_never_stopped(self):
        self.boundary.loaded = True
        F.write(self.system/M.PLIST.lstrip('/'), plistlib.dumps({'Label': M.LABEL, 'ProgramArguments': ['/usr/local/bin/router-vpn-client']}), 0o600)
        with self.assertRaises(RuntimeError): self.install()
        self.assertFalse(any('bootout' in call for call in self.boundary.calls))
        self.assertTrue(self.boundary.loaded)

    def test_unknown_service_query_error_is_not_inactivity(self):
        self.boundary.query_failure = True
        with self.assertRaises(RuntimeError): self.install()
        self.assertFalse(self.root.exists())
        self.assertFalse(any('bootstrap' in call for call in self.boundary.calls))

    def test_verification_failure_preserves_existing_bytes_and_service(self):
        self.install(); before = F.snapshot(self.root, metadata=True)
        self.renew_boundary(); self.boundary.calls.clear()
        def broken(*_): raise ValueError('bad runtime')
        with self.assertRaises(ValueError): self.install(verifier=broken)
        self.assertEqual(before, F.snapshot(self.root, metadata=True))
        self.assertEqual([], self.boundary.calls)

    def test_system_failure_restores_old_root_files_and_supervisor(self):
        self.install(); F.write(self.root/'private-sentinel', 'old private state', 0o600)
        before, system = F.snapshot(self.root, metadata=True), F.file_bytes(self.system)
        self.renew_boundary(); self.boundary.fail = 'bootstrap'
        with self.assertRaises(subprocess.CalledProcessError): self.install()
        self.assertEqual(before, F.snapshot(self.root, metadata=True))
        self.assertEqual(system, F.file_bytes(self.system))
        self.assertTrue(self.boundary.loaded)

    def test_rollback_failure_retains_backup_and_blocks_next_attempt(self):
        self.install(); self.renew_boundary()
        def fail(_): raise RuntimeError('cannot restore old service')
        self.integration.install = fail
        self.integration.restore = lambda: (_ for _ in ()).throw(RuntimeError('rollback failed'))
        with self.assertRaisesRegex(RuntimeError, 'retained at'): self.install()
        recovery = list(self.base.glob('.installed.install-*'))
        self.assertEqual(1, len(recovery))
        self.renew_boundary()
        with self.assertRaisesRegex(RuntimeError, 'interrupted'): self.install()

    def test_unsafe_sources_and_private_symlinks_do_not_replace_root(self):
        self.install(); before = F.snapshot(self.root, metadata=True)
        self.renew_boundary()
        binary = self.source/'RouterVPN.app/Contents/MacOS/RouterVPN'
        binary.unlink(); binary.symlink_to('/bin/sh')
        with self.assertRaises(ValueError): self.install()
        self.assertEqual(before, F.snapshot(self.root, metadata=True))

    def test_private_configuration_escape_is_rejected(self):
        F.write(self.source/'client.json', '{"profiles_file":"/tmp/foreign.json"}')
        with self.assertRaises(ValueError): self.install()
        self.assertFalse(self.root.exists())

    def test_owner_record_is_not_adopted_from_a_generic_source(self):
        F.write(self.source/'controller-owner.json', '{"schema":1,"caller_uid":0}')
        self.install()
        self.assertEqual(self.uid, json.loads((self.root/'controller-owner.json').read_text())['caller_uid'])

    def test_existing_download_quarantine_is_preserved_on_code(self):
        # Exercise the Darwin attribute boundary without asking a Linux host
        # to manufacture macOS filesystem semantics. Actual Mac package runs
        # below also execute the unmodified native attribute operations.
        expected = {
            '.': b'0081;fixture;download;package-root',
            'RouterVPN.app': b'0081;fixture;download;app',
            'RouterVPN.app/Contents/MacOS/RouterVPN': b'0081;fixture;download;executable',
            'router-vpn-client': b'0081;fixture;download;controller',
        }
        captured = {}
        def read(path, name, *, follow_symlinks):
            self.assertEqual('com.apple.quarantine', name)
            self.assertFalse(follow_symlinks)
            relative = str(path.relative_to(self.source))
            if relative in expected: return expected[relative]
            raise OSError(errno.ENODATA, 'attribute absent')
        def write(path, name, value, *, follow_symlinks):
            self.assertEqual('com.apple.quarantine', name)
            self.assertFalse(follow_symlinks)
            relative = str(Path(*path.parts[path.parts.index('new')+1:]))
            captured[relative] = value
        platform_os = types.SimpleNamespace(**vars(os))
        platform_os.getxattr, platform_os.setxattr = read, write
        with mock.patch.object(self.installer, 'sys', types.SimpleNamespace(platform='darwin')), \
             mock.patch.object(self.installer, 'os', platform_os):
            self.install()
        self.assertEqual(expected, captured)

    def test_quarantine_read_failure_is_not_silently_cleared(self):
        platform_os = types.SimpleNamespace(**vars(os))
        def broken(*_, **__): raise OSError(errno.EACCES, 'cannot capture existing quarantine')
        platform_os.getxattr = broken
        with mock.patch.object(self.installer, 'sys', types.SimpleNamespace(platform='darwin')), \
             mock.patch.object(self.installer, 'os', platform_os):
            with self.assertRaises(OSError): self.install()
        self.assertFalse(self.root.exists())
        self.assertEqual([], self.boundary.calls)

    def test_native_acl_decoder_preserves_public_read_and_private_denial(self):
        def record(kind, rights):
            data = bytearray(12+44+24)
            struct.pack_into('<IiI', data, 0, len(data), 8, len(data)-12)
            struct.pack_into('<I', data, 12, 0x012cc16d)
            struct.pack_into('<I', data, 48, 1)
            struct.pack_into('<II', data, 72, kind, rights)
            return data
        for kind, rights, private, accepted in (
            (2, 1<<4, False, True), (2, 1<<4, True, True),
            (1, 1<<1, False, True), (1, 1<<1, True, False),
            (1, 1<<2, False, False), (1, 1<<4, False, False),
            (1, 1<<12, False, False), (1 | 1<<8, 1<<2, False, False),
            (3, 1<<1, False, False), (1, 1<<31, False, False),
        ):
            with self.subTest(kind=kind, rights=rights, private=private):
                if accepted: self.installer.validate_acl_buffer(record(kind, rights), private)
                else:
                    with self.assertRaises(ValueError): self.installer.validate_acl_buffer(record(kind, rights), private)
        malformed = record(1, 1<<1)
        struct.pack_into('<i', malformed, 4, -1)
        with self.assertRaises(ValueError): self.installer.validate_acl_buffer(malformed, False)


class MacNativeACL(unittest.TestCase):
    def test_actual_root_owned_objects_do_not_hide_acl_authority(self):
        if sys.platform != 'darwin': raise RuntimeError('Actual macOS ACL execution is required')
        with tempfile.TemporaryDirectory(prefix='routervpn-mac-acl-') as temporary:
            root = Path(temporary)
            for name, mode, entry, accepted in (
                ('public-read', 0o644, 'everyone allow read', True),
                ('deny-delete', 0o644, 'everyone deny delete', True),
                ('public-write', 0o644, 'everyone allow write', False),
                ('public-delete', 0o644, 'everyone allow delete', False),
                ('private-read', 0o600, 'everyone allow read', False),
            ):
                with self.subTest(name=name):
                    path = root/name
                    F.write(path, 'owned temporary ACL fixture', mode)
                    subprocess.run(['/bin/chmod', '+a', entry, path], check=True)
                    try:
                        self.assertEqual(mode, path.stat().st_mode & 0o777)
                        if accepted: M.FILES.ordinary(path, trusted=True)
                        else:
                            with self.assertRaises(ValueError): M.FILES.ordinary(path, trusted=True)
                    finally:
                        subprocess.run(['/bin/chmod', '-N', path], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        tool = F.INSTALLER_PATH.parent.parent/'deploy/test_desktop_socket_uid.py'
        spec = importlib.util.spec_from_file_location('mac_install_elevation', tool)
        owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
        sudo = owner.privilege_tool()
        if sudo is None: raise RuntimeError('Installer ownership tests require actual root in temporary directories')
        raise SystemExit(subprocess.run([sudo, '-n', '--', sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]]).returncode)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MacInstallTransactions))
    if not result.wasSuccessful(): raise SystemExit(1)
    for before, after, case in (
        ('with FILES.installation_lock(root):', 'with __import__("contextlib").nullcontext():', 'test_live_install_lock_prevents_even_service_probe'),
        ('            verifier(stage, python)', '            pass # bypass runtime validation', 'test_verification_failure_preserves_existing_bytes_and_service'),
        ('            reject_running_previous(root, process_reader)', '            pass # ignore legacy owner', 'test_running_legacy_native_owner_prevents_promotion'),
        ('                FILES.copy_checked(child, stage/child.name, private=True)', '                pass # discard private state', 'test_upgrade_preserves_private_owner_settings_and_open_file_isolation'),
        ('                integration.restore()', '                pass # omit restoration', 'test_system_failure_restores_old_root_files_and_supervisor'),
        ("    if sys.platform == 'darwin':\n        absent", "    if False:\n        absent", 'test_existing_download_quarantine_is_preserved_on_code'),
    ):
        source = TARGET.read_text()
        if source.count(before) != 1: raise AssertionError('Mutation lost its actual production seam')
        broken = type('BrokenMacInstall', (MacInstallTransactions,), {'installer': load(source.replace(before, after, 1))})
        result = unittest.TextTestRunner(stream=io.StringIO()).run(broken(case))
        if result.wasSuccessful(): raise AssertionError('Broken native installation was accepted: '+case)
        print('Rejected macOS installer defect: '+case)
    if sys.platform == 'darwin':
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MacNativeACL))
        if not result.wasSuccessful(): raise SystemExit(1)
        actual = {str(Path(path).resolve()) for path in M.running_executables()}
        if str(Path(sys.executable).resolve()) not in actual:
            raise AssertionError('Native process inventory lost the actual executing interpreter')
        print('Actual macOS libproc inventory captured the executing interpreter.')
    if arguments.package is not None:
        if sys.platform != 'darwin': raise RuntimeError('Bundled macOS runtime execution requires an actual matching Mac host')
        source = arguments.package.resolve()
        expected = F.runtime_digests(source/'runtime')
        with tempfile.TemporaryDirectory(prefix='routervpn-mac-package-install-') as temporary:
            base = Path(temporary); installed, system = base/'installed', base/'system'
            system.mkdir()
            boundary = LaunchBoundary(M, installed, system)
            for iteration in range(2):
                M.install(source, pwd.getpwnam('daemon').pw_uid, Path(sys.executable), root=installed,
                          integration=M.LaunchIntegration(system, boundary), process_reader=lambda: [])
                if F.runtime_digests(installed/'runtime') != expected:
                    raise AssertionError('Actual bundled runtime bytes changed through native installation')
                if iteration == 0: F.write(installed/'generated/private-upgrade-sentinel', 'keep exact private bytes', 0o600)
                elif (installed/'generated/private-upgrade-sentinel').read_text() != 'keep exact private bytes':
                    raise AssertionError('Actual package upgrade discarded private node material')
        print('Actual matching macOS package runtime/signature verification passed through install and upgrade.')


if __name__ == '__main__':
    main()
