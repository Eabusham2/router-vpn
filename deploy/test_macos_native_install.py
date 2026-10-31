#!/usr/bin/env python3
"""Execute macOS installer transactions in temporary roots, without host services."""
from __future__ import annotations
import argparse
import ctypes
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
import time
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


def native_inventory_with_failure_diagnostic(installer):
    """Keep the real inventory failure; subsequent BSD data is diagnostic only."""
    original = installer.native_executable

    def executable(library, pid):
        try:
            return original(library, pid)
        except Exception:
            # This later read may observe a reused PID. It grants no identity,
            # disappearance or installation authority, including on success.
            try:
                info = installer.NativeProcessBSDInfo()
                observed = time.time_ns()
                ctypes.set_errno(0)
                size = library.proc_pidinfo(pid, 3, 1, ctypes.byref(info), ctypes.sizeof(info))
                error = ctypes.get_errno()
                record = {'requested_pid': pid, 'observed_unix_ns': observed,
                          'identity_accepted': False, 'pid_reuse_possible': True,
                          'bsd_result': size, 'bsd_errno': error,
                          'expected_bsd_bytes': ctypes.sizeof(info)}
                if size == ctypes.sizeof(info):
                    def name(value, limit):
                        allowed = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-'
                        return ''.join(chr(byte) if byte in allowed else '?'
                                       for byte in bytes(value)[:limit].split(b'\0', 1)[0])
                    record.update(observed_start=[info.pbi_pid, info.pbi_start_tvsec, info.pbi_start_tvusec],
                                  ppid=info.pbi_ppid, status=info.pbi_status, uid=info.pbi_uid,
                                  comm=name(info.pbi_comm, 16), name=name(info.pbi_name, 32))
                print('Native inventory refusal diagnostic (not accepted identity): ' +
                      json.dumps(record, sort_keys=True), flush=True)
            except Exception:
                # Even a failed diagnostic write must not replace the original
                # shipping error or convert its failed gate to success.
                pass
            raise

    with mock.patch.object(installer, 'native_executable', executable):
        return installer.running_executables()


class NativeCall:
    def __init__(self, implementation):
        self.implementation = implementation
        self.argtypes = self.restype = None

    def __call__(self, *arguments):
        return self.implementation(*arguments)


class ProcessLibrary:
    """Darwin ABI double for the actual shipping inventory function."""
    def __init__(self, pids=(101,), paths=None, count=None, inventory=None, states=None):
        self.pids, self.paths = pids, dict(paths or {})
        self.states = dict(states or {})
        self.count = count if count is not None else (len(pids), errno.EBUSY)
        self.inventory = list(inventory or [(len(pids), errno.EBUSY)])
        self.calls = []
        self.proc_listallpids = NativeCall(self.list_pids)
        self.proc_pidpath = NativeCall(self.pid_path)
        self.proc_pidinfo = NativeCall(self.pid_info)

    @staticmethod
    def next_result(values, pid, default):
        result = values.get(pid, default)
        if isinstance(result, list):
            selected = result[0]
            if len(result) > 1: result.pop(0)
            return selected
        return result

    def list_pids(self, buffer, size):
        self.calls.append(('count' if buffer is None else 'inventory', ctypes.get_errno()))
        if buffer is None:
            if size != 0: raise AssertionError('Native PID sizing lost its null-buffer ABI')
            result, error = self.count
        else:
            if size != ctypes.sizeof(buffer): raise AssertionError('Native PID inventory used count instead of bytes')
            for index, pid in enumerate(self.pids): buffer[index] = pid
            result, error = self.inventory[0]
            if len(self.inventory) > 1: self.inventory.pop(0)
        if error is not None: ctypes.set_errno(error)
        return result

    def pid_path(self, pid, buffer, size):
        self.calls.append((pid, ctypes.get_errno()))
        if size != 4096: raise AssertionError('Native executable path lost its bounded capture')
        result, error = self.next_result(self.paths, pid, (b'/fixture/native-owner', errno.EBUSY))
        if error is not None: ctypes.set_errno(error)
        if isinstance(result, bytes):
            ctypes.memmove(buffer, result, min(len(result), size))
            return len(result)
        return result

    def pid_info(self, pid, flavor, argument, buffer, size):
        self.calls.append(('state', pid, ctypes.get_errno()))
        if (flavor, argument, size) != (3, 1, 136):
            raise AssertionError('Native process state lost its exact public ABI or zombie lookup')
        result, error = self.next_result(self.states, pid, ({}, errno.EBUSY))
        if error is not None: ctypes.set_errno(error)
        if result is None: return 0
        if isinstance(result, int): return result
        raw = bytearray(136)
        struct.pack_into('<I', raw, 4, result.get('status', 2))
        struct.pack_into('<I', raw, 12, result.get('pid', pid))
        struct.pack_into('<QQ', raw, 120, result.get('seconds', 1700000000), result.get('microseconds', 123))
        ctypes.memmove(buffer, bytes(raw), len(raw))
        return result.get('size', len(raw))


class MacProcessInventory(unittest.TestCase):
    installer = M

    def read(self, library):
        with mock.patch.object(self.installer.sys, 'platform', 'darwin'), \
             mock.patch.object(self.installer.ctypes, 'CDLL', return_value=library) as load_library:
            result = self.installer.running_executables()
        load_library.assert_called_once_with('/usr/lib/libproc.dylib', use_errno=True)
        return result

    def test_actual_inventory_captures_native_paths_and_clears_errno_for_each_call(self):
        library = ProcessLibrary(pids=(0, -1, 101, 102))
        ctypes.set_errno(errno.ESRCH)
        self.assertEqual(self.read(library), ['/fixture/native-owner'] * 2)
        self.assertEqual(library.calls, [('count', 0), ('inventory', 0), (101, 0), (102, 0)])
        self.assertEqual(library.proc_listallpids.argtypes, [ctypes.c_void_p, ctypes.c_int])
        self.assertEqual(library.proc_pidpath.argtypes, [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32])
        self.assertEqual(library.proc_pidinfo.argtypes,
                         [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int])

    def test_path_esrch_requires_independent_native_process_absence(self):
        library = ProcessLibrary(pids=(101, 102), paths={101: (0, errno.ESRCH)},
                                 states={101: (None, errno.ESRCH)})
        self.assertEqual(self.read(library), ['/fixture/native-owner'])
        self.assertEqual(library.calls[-3:], [(101, 0), ('state', 101, 0), (102, 0)])

    def test_unknown_or_denied_paths_fail_closed_with_only_numeric_diagnostics(self):
        for error in (errno.EPERM, errno.EACCES, errno.EIO, errno.EINVAL, 0):
            for returned in (0, -1):
                with self.subTest(error=error, returned=returned):
                    library = ProcessLibrary(pids=(101, 102), paths={
                        101: (b'/private/unrelated-process-name', None), 102: (returned, error)})
                    with self.assertRaises(RuntimeError) as failure:
                        self.read(library)
                    self.assertEqual(str(failure.exception),
                        'Cannot prove the previous native processes have exited '
                        f'(pid=102, errno={error}, result={returned})')
                    self.assertNotIn('/private/', str(failure.exception))

    def test_previous_esrch_cannot_hide_a_zero_result_without_errno(self):
        library = ProcessLibrary(pids=(101, 102), paths={101: (0, errno.ESRCH), 102: (0, None)},
                                 states={101: (None, errno.ESRCH)})
        with self.assertRaisesRegex(RuntimeError, r'pid=102, errno=0, result=0'):
            self.read(library)

    def test_inventory_count_and_capture_are_bounded_before_path_queries(self):
        for count in (-1, 0, 1000000):
            with self.subTest(count=count):
                library = ProcessLibrary(count=(count, errno.EIO))
                with self.assertRaisesRegex(RuntimeError, f'count={count}, errno={errno.EIO}'):
                    self.read(library)
                self.assertEqual(library.calls, [('count', 0)])
        for actual in (-1, 0, 129, 130):
            with self.subTest(actual=actual):
                library = ProcessLibrary(inventory=[(actual, errno.EIO)])
                with self.assertRaisesRegex(RuntimeError, f'count={actual}, capacity=129, errno={errno.EIO}'):
                    self.read(library)
                self.assertEqual(library.calls, [('count', 0), ('inventory', 0)] * 4)

    def test_full_inventory_retries_then_accepts_only_a_complete_capture(self):
        library = ProcessLibrary(inventory=[(129, 0), (1, 0)])
        self.assertEqual(self.read(library), ['/fixture/native-owner'])
        self.assertEqual(library.calls, [('count', 0), ('inventory', 0)] * 2 + [(101, 0)])

    def test_truncated_native_identity_is_not_accepted(self):
        library = ProcessLibrary(paths={101: (4096, 0)})
        with self.assertRaisesRegex(RuntimeError, r'identity was truncated \(pid=101, result=4096\)'):
            self.read(library)

    def test_missing_paths_require_native_absence_or_the_same_zombie(self):
        for path_error in (errno.ENOENT, errno.ESRCH):
            for states in (
                [(None, errno.ESRCH)],
                [({}, 0), (None, errno.ESRCH)],
                [({}, 0), ({'status': 5}, 0)],
                [({'status': 5}, 0), ({'status': 5}, 0)],
            ):
                with self.subTest(path_error=path_error, states=states):
                    library = ProcessLibrary(paths={101: (0, path_error)}, states={101: list(states)})
                    self.assertEqual([], self.read(library))
                    self.assertTrue(all(call[-1] == 0 for call in library.calls))

    def test_transient_missing_path_recovers_only_the_captured_live_identity(self):
        library = ProcessLibrary(paths={101: [(0, errno.ENOENT), (b'/fixture/native-owner', 0)]})
        self.assertEqual(['/fixture/native-owner'], self.read(library))
        self.assertEqual(library.calls[-4:], [(101, 0), ('state', 101, 0), (101, 0), ('state', 101, 0)])

    def test_live_missing_executable_is_rejected_after_bounded_retries(self):
        for path_error in (errno.ENOENT, errno.ESRCH):
            for status in (1, 2, 3, 4):
                with self.subTest(path_error=path_error, status=status):
                    library = ProcessLibrary(paths={101: (0, path_error)}, states={101: ({'status': status}, 0)})
                    with mock.patch.object(self.installer.time, 'sleep') as pause, self.assertRaisesRegex(
                            RuntimeError, f'pid=101, errno={path_error}, result=0, status={status}'):
                        self.read(library)
                    self.assertEqual([mock.call(0.01)] * 2, pause.call_args_list)
                    self.assertEqual(4, sum(call[0] == 101 for call in library.calls))
                    self.assertEqual(4, sum(call[0] == 'state' for call in library.calls))

    def test_missing_path_retry_rejects_pid_reuse_and_zombie_revival(self):
        for before, after in (({}, {'seconds': 1700000001}), ({}, {'microseconds': 124}),
                              ({}, {'seconds': 1700000001, 'status': 5}), ({'status': 5}, {})):
            with self.subTest(before=before, after=after):
                library = ProcessLibrary(paths={101: [(0, errno.ENOENT), (b'/fixture/replacement', 0)]},
                                         states={101: [(before, 0), (after, 0)]})
                with self.assertRaisesRegex(RuntimeError, 'identity changed during executable capture'):
                    self.read(library)

    def test_missing_path_state_errors_never_prove_absence(self):
        for error in (0, errno.EPERM, errno.EACCES, errno.EIO, errno.EINVAL, errno.ENOENT):
            for returned in (0, -1):
                with self.subTest(error=error, returned=returned):
                    library = ProcessLibrary(paths={101: (0, errno.ENOENT)}, states={101: (returned, error)})
                    with self.assertRaisesRegex(RuntimeError, f'pid=101, errno={error}, result={returned}, expected=136'):
                        self.read(library)
        library = ProcessLibrary(paths={101: (0, errno.ESRCH)}, states={101: (0, None)})
        with self.assertRaisesRegex(RuntimeError, 'pid=101, errno=0, result=0, expected=136'):
            self.read(library)

    def test_missing_path_rejects_short_or_malformed_native_state(self):
        for changed in ({'size': 135}, {'size': 137}, {'pid': 102}, {'status': 0}, {'status': 6},
                        {'seconds': 0}, {'microseconds': 1000000}):
            with self.subTest(changed=changed):
                record = {'status': 5, **changed}
                library = ProcessLibrary(paths={101: (0, errno.ENOENT)}, states={101: (record, 0)})
                with self.assertRaisesRegex(RuntimeError, 'Cannot capture native process state|Native process state is malformed'):
                    self.read(library)

    def test_native_state_abi_offsets_are_checked_before_any_inventory(self):
        class WrongLayout(ctypes.Structure):
            _fields_ = [('pbi_pid', ctypes.c_uint32), ('pbi_status', ctypes.c_uint32),
                        ('padding', ctypes.c_char * 112), ('pbi_start_tvusec', ctypes.c_uint64),
                        ('pbi_start_tvsec', ctypes.c_uint64)]
        self.assertEqual(136, ctypes.sizeof(WrongLayout))
        with mock.patch.object(self.installer, 'NativeProcessBSDInfo', WrongLayout), \
             mock.patch.object(self.installer.sys, 'platform', 'darwin'), \
             mock.patch.object(self.installer.ctypes, 'CDLL') as factory, \
             self.assertRaisesRegex(RuntimeError, 'identity ABI'):
            self.installer.running_executables()
        factory.assert_not_called()

    def test_retry_does_not_turn_denied_live_identity_into_absence(self):
        library = ProcessLibrary(paths={101: [(0, errno.ENOENT), (0, errno.EACCES)]})
        with mock.patch.object(self.installer.time, 'sleep') as pause, \
             self.assertRaisesRegex(RuntimeError, f'pid=101, errno={errno.EACCES}, result=0, status=2'):
            self.read(library)
        pause.assert_not_called()

    def test_failure_diagnostic_keeps_original_exception_even_if_capture_or_output_fails(self):
        original = RuntimeError('original native inventory refusal')
        for diagnostic_failure in (None, 'capture', 'output'):
            with self.subTest(diagnostic_failure=diagnostic_failure):
                library = ProcessLibrary()

                def capture(pid, flavor, argument, buffer, size):
                    self.assertEqual((101, 3, 1, 136, 0),
                                     (pid, flavor, argument, size, ctypes.get_errno()))
                    if diagnostic_failure == 'capture':
                        raise OSError('diagnostic capture failed')
                    info = ctypes.cast(buffer, ctypes.POINTER(self.installer.NativeProcessBSDInfo)).contents
                    # A different start tuple is deliberately only a later
                    # observation; no diagnostic can adopt the replacement.
                    info.pbi_pid, info.pbi_start_tvsec, info.pbi_start_tvusec = 101, 1700000001, 124
                    info.pbi_status, info.pbi_ppid, info.pbi_uid = 2, 1, 501
                    info.pbi_comm, info.pbi_name = b'fixture\n::bad', b'fixture/name\\with\tcontrol'
                    return size

                library.proc_pidinfo = NativeCall(capture)
                output = mock.Mock(side_effect=OSError('diagnostic output failed')
                                   if diagnostic_failure == 'output' else None)
                with mock.patch.object(self.installer.sys, 'platform', 'darwin'), \
                     mock.patch.object(self.installer.ctypes, 'CDLL', return_value=library), \
                     mock.patch.object(self.installer, 'native_executable', side_effect=original) as target, \
                     mock.patch('builtins.print', output), \
                     self.assertRaises(RuntimeError) as rejected:
                    native_inventory_with_failure_diagnostic(self.installer)
                self.assertIs(original, rejected.exception)
                target.assert_called_once_with(library, 101)
                if diagnostic_failure != 'capture':
                    output.assert_called_once()
                    record = json.loads(output.call_args.args[0].split(': ', 1)[1])
                    self.assertEqual([101, 1700000001, 124], record['observed_start'])
                    self.assertFalse(record['identity_accepted'])
                    self.assertTrue(record['pid_reuse_possible'])
                    self.assertGreater(record['observed_unix_ns'], 0)
                    self.assertEqual('fixture???bad', record['comm'])
                    self.assertEqual('fixture?name?with?control', record['name'])


class QuarantineLibrary:
    """Darwin ABI double; paths and descriptor ownership remain real."""
    def __init__(self, values=None):
        self.values = dict(values or {})
        self.read_error = self.write_error = None
        self.short_read = self.drop_write = False
        self.after_write = lambda: None
        self.calls = []
        self.fgetxattr = NativeCall(self.read)
        self.fsetxattr = NativeCall(self.write)

    @staticmethod
    def identity(descriptor):
        info = os.fstat(descriptor)
        return info.st_dev, info.st_ino

    def capture(self, descriptor, name, buffer, size, position, options):
        if name != b'com.apple.quarantine' or position != 0 or options != 0:
            raise AssertionError('Native quarantine lost its exact Darwin attribute/argument boundary')
        self.calls.append((name, size, position, options))
        return self.identity(descriptor)

    def read(self, descriptor, name, buffer, size, position, options):
        identity = self.capture(descriptor, name, buffer, size, position, options)
        value = self.values.get(identity)
        if self.read_error or value is None:
            ctypes.set_errno(self.read_error or getattr(errno, 'ENOATTR', 93))
            return -1
        if buffer is None:
            return len(value)
        if len(value) > size:
            ctypes.set_errno(errno.ERANGE)
            return -1
        ctypes.memmove(buffer, value, len(value))
        return len(value) - 1 if self.short_read else len(value)

    def write(self, descriptor, name, buffer, size, position, options):
        identity = self.capture(descriptor, name, buffer, size, position, options)
        if self.write_error:
            ctypes.set_errno(self.write_error)
            return -1
        if not self.drop_write:
            self.values[identity] = ctypes.string_at(buffer, size)
        self.after_write()
        return 0


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
        # macOS may spell its temporary parent as /tmp -> /private/tmp.
        # Capture the physical fixture root before supplying it to the real
        # installer's no-follow traversal; production path checks stay intact.
        self.base = Path(self.directory.name).resolve(strict=True)
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

    def test_temp_parent_alias_is_resolved_before_actual_installer_traversal(self):
        physical = self.base/'physical-temp'; physical.mkdir()
        alias = self.base/'temp-alias'; alias.symlink_to(physical, target_is_directory=True)
        fixture = types.SimpleNamespace(name=str(alias), cleanup=lambda: None)
        independent = MacInstallTransactions('test_first_install_has_one_root_owned_authority_and_no_http_daemon')
        try:
            with mock.patch.object(tempfile, 'TemporaryDirectory', return_value=fixture):
                independent.setUp()
            self.assertEqual(physical, independent.base)
            independent.test_first_install_has_one_root_owned_authority_and_no_http_daemon()
        finally:
            independent.doCleanups()

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
        # Only the Darwin native calls are doubled. The shipping descriptor
        # capture, size bounds, source recheck and installed readback execute.
        expected = {
            '.': b'0081;fixture;download;package-root',
            'RouterVPN.app': b'',
            'RouterVPN.app/Contents/MacOS/RouterVPN': b'0081;fixture;download;\0executable',
            'router-vpn-client': b'0081;fixture;download;controller',
        }
        values = {(path.stat().st_dev, path.stat().st_ino): value
                  for name, value in expected.items() for path in [self.source/name]}
        native = QuarantineLibrary(values)
        self.install_with_quarantine(native)
        self.assertEqual(expected, {name: native.values[(path.stat().st_dev, path.stat().st_ino)]
                                  for name in expected for path in [self.root/name]})
        self.assertEqual(len(expected)*2, len(native.values), 'installation copied unrelated extended metadata')

    def native_quarantine(self, library):
        with mock.patch.object(self.installer.ctypes, 'CDLL', return_value=library) as factory:
            attributes = self.installer.NativeQuarantine()
        factory.assert_called_once_with('/usr/lib/libSystem.B.dylib', use_errno=True)
        expected = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p,
                    ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
        self.assertEqual(expected, library.fgetxattr.argtypes)
        self.assertEqual(expected, library.fsetxattr.argtypes)
        self.assertIs(ctypes.c_ssize_t, library.fgetxattr.restype)
        self.assertIs(ctypes.c_int, library.fsetxattr.restype)
        return attributes

    def install_with_quarantine(self, library):
        attributes = self.native_quarantine(library)
        # Simulate CPython's actual Darwin os surface on Linux too. These
        # methods must not be required by the installation path.
        platform_os = types.SimpleNamespace(**{name: value for name, value in vars(os).items()
                                               if name not in ('getxattr', 'setxattr')})
        with mock.patch.object(self.installer, 'sys', types.SimpleNamespace(platform='darwin')), \
             mock.patch.object(self.installer, 'os', platform_os), \
             mock.patch.object(self.installer, 'NativeQuarantine', return_value=attributes):
            self.install()

    def test_quarantine_read_failure_is_not_silently_cleared(self):
        native = QuarantineLibrary()
        native.read_error = errno.EACCES
        with self.assertRaises(OSError):
            self.install_with_quarantine(native)
        self.assertFalse(self.root.exists())
        self.assertEqual([], self.boundary.calls)

    def test_quarantine_write_and_readback_fail_before_promotion(self):
        source = self.source/'router-vpn-client'
        identity = source.stat().st_dev, source.stat().st_ino
        for fault in ('write-error', 'dropped-write', 'changed-input'):
            native = QuarantineLibrary({identity: b'0081;fixture;preserve-me'})
            if fault == 'write-error': native.write_error = errno.EPERM
            if fault == 'dropped-write': native.drop_write = True
            if fault == 'changed-input':
                native.after_write = lambda: native.values.__setitem__(identity, b'0081;changed-after-read')
            with self.subTest(fault=fault), self.assertRaises((OSError, ValueError)):
                self.install_with_quarantine(native)
            self.assertFalse(self.root.exists())
            self.assertEqual([], self.boundary.calls)

    def test_native_quarantine_absence_bounds_and_exact_size(self):
        with self.installer.quarantine_object(self.source/'router-vpn-client') as descriptor:
            identity = QuarantineLibrary.identity(descriptor)
            native = QuarantineLibrary()
            attributes = self.native_quarantine(native)
            self.assertIsNone(attributes.read(descriptor))
            for error in (errno.EACCES, errno.EIO, errno.ENOTSUP):
                native.read_error = error
                with self.subTest(error=error), self.assertRaises(OSError):
                    attributes.read(descriptor)
            native.read_error = None
            native.values[identity] = b'x'*(self.installer.QUARANTINE_LIMIT+1)
            with self.assertRaisesRegex(ValueError, 'bounded capture'):
                attributes.read(descriptor)
            native.values[identity] = b'actual-value'
            native.short_read = True
            with self.assertRaisesRegex(ValueError, 'changed during capture'):
                attributes.read(descriptor)
            with self.assertRaisesRegex(ValueError, 'Invalid captured'):
                attributes.write(descriptor, b'x'*(self.installer.QUARANTINE_LIMIT+1))

    def test_quarantine_capture_rejects_linked_or_replaced_objects(self):
        regular = self.base/'quarantine-source'; F.write(regular, 'retained input')
        leaf = self.base/'quarantine-alias'; leaf.symlink_to(regular)
        parent = self.base/'quarantine-parent'; parent.symlink_to(self.source, target_is_directory=True)
        hardlink = self.base/'quarantine-hardlink'; os.link(regular, hardlink)
        for path in (leaf, parent/'router-vpn-client', regular, hardlink):
            with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                with self.installer.quarantine_object(path):
                    self.fail('quarantine capture followed a linked object')
        hardlink.unlink()
        descriptor = None
        with self.assertRaisesRegex(ValueError, 'changed during preservation'):
            with self.installer.quarantine_object(regular) as descriptor:
                regular.rename(self.base/'quarantine-original')
                F.write(regular, 'another inode')
        with self.assertRaises(OSError):
            os.fstat(descriptor)

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


class MacNativeQuarantine(MacInstallTransactions):
    def test_real_download_quarantine_survives_native_installation(self):
        if sys.platform != 'darwin': raise RuntimeError('Actual macOS quarantine execution is required')
        expected = {'.': b'0081;fixture;download;package-root',
                    'RouterVPN.app': b'0081;fixture;download;app',
                    'RouterVPN.app/Contents/MacOS/RouterVPN': b'0081;fixture;download;executable',
                    'router-vpn-client': b'0081;fixture;download;controller'}
        for name, value in expected.items():
            subprocess.run(['/usr/bin/xattr', '-wx', 'com.apple.quarantine', value.hex(), self.source/name], check=True)
        self.install()
        for name, value in expected.items():
            captured = subprocess.run(['/usr/bin/xattr', '-px', 'com.apple.quarantine', self.root/name],
                                      check=True, stdout=subprocess.PIPE, text=True)
            self.assertEqual(value, bytes.fromhex(captured.stdout))


class MacNativeProcesses(unittest.TestCase):
    def test_actual_native_state_identifies_owned_live_zombie_and_reaped_child(self):
        if sys.platform != 'darwin': raise RuntimeError('Actual macOS process-state execution is required')
        library = M.native_process_library()
        current = M.native_process_state(library, os.getpid())
        self.assertIsNotNone(current)
        self.assertEqual(os.getpid(), current[0])
        self.assertNotEqual(5, current[3])
        child = subprocess.Popen(['/bin/cat'], stdin=subprocess.PIPE,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            captured = M.native_process_state(library, child.pid)
            self.assertIsNotNone(captured)
            self.assertNotEqual(5, captured[3])
            child.stdin.close()  # Exit on EOF, but retain the unreaped child.
            deadline = time.monotonic() + 3
            while True:
                ended = M.native_process_state(library, child.pid)
                self.assertIsNotNone(ended, 'Unreaped native child vanished without its captured zombie')
                self.assertEqual(captured[:3], ended[:3])
                if ended[3] == 5: break
                if time.monotonic() >= deadline:
                    self.fail('Owned native child did not reach its independently observed zombie state')
                time.sleep(0.01)
            self.assertIsNone(M.native_executable(library, child.pid))
            child.wait(timeout=3)
            self.assertIsNone(M.native_process_state(library, child.pid))
            print(f'Actual libproc identity retained owned PID {child.pid} through SZOMB and independent ESRCH.')
        finally:
            if child.poll() is None: child.kill()
            child.wait(timeout=3)
            if not child.stdin.closed: child.stdin.close()

    def test_actual_unlinked_live_executable_never_proves_absence(self):
        if sys.platform != 'darwin': raise RuntimeError('Actual macOS unlinked-process execution is required')
        library = M.native_process_library()
        with tempfile.TemporaryDirectory(prefix='routervpn-mac-live-image-') as temporary:
            root = Path(temporary).resolve(strict=True)
            executable = root/'owned-live-image'
            shutil.copyfile('/bin/sleep', executable)
            executable.chmod(0o755)
            child = subprocess.Popen([str(executable), '30'], stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                captured = M.native_process_state(library, child.pid)
                self.assertIsNotNone(captured)
                self.assertNotEqual(5, captured[3])
                self.assertEqual(str(executable), M.native_executable(library, child.pid))
                executable.unlink()
                path, error, size = M.native_process_path(library, child.pid)
                live = M.native_process_state(library, child.pid)
                self.assertIsNotNone(live)
                self.assertEqual(captured[:3], live[:3])
                self.assertNotEqual(5, live[3])
                # Darwin versions may return a retained path or an executable
                # vnode error. Both observations must still block this owner.
                try:
                    retained = M.native_executable(library, child.pid)
                except RuntimeError as failure:
                    self.assertIn('Cannot prove the previous native processes have exited', str(failure))
                else:
                    self.assertIsNotNone(retained, 'Live unlinked native executable was classified as absent')
                    self.assertEqual(str(executable), retained)
                    with self.assertRaisesRegex(RuntimeError, 'previous owned native processes'):
                        M.reject_running_previous(root, lambda: [retained])
                after = M.native_process_state(library, child.pid)
                self.assertIsNotNone(after)
                self.assertEqual(captured[:3], after[:3])
                self.assertNotEqual(5, after[3])
                print(f'Actual unlinked live owner remains blocked (pid={child.pid}, errno={error}, result={size}, status={after[3]}).')
            finally:
                if child.poll() is None: child.kill()
                child.wait(timeout=3)


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
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MacProcessInventory))
    if not result.wasSuccessful(): raise SystemExit(1)
    for before, after, case in (
        ('with FILES.installation_lock(root):', 'with __import__("contextlib").nullcontext():', 'test_live_install_lock_prevents_even_service_probe'),
        ('            verifier(stage, python)', '            pass # bypass runtime validation', 'test_verification_failure_preserves_existing_bytes_and_service'),
        ('            reject_running_previous(root, process_reader)', '            pass # ignore legacy owner', 'test_running_legacy_native_owner_prevents_promotion'),
        ('                FILES.copy_checked(child, stage/child.name, private=True)', '                pass # discard private state', 'test_upgrade_preserves_private_owner_settings_and_open_file_isolation'),
        ('                integration.restore()', '                pass # omit restoration', 'test_system_failure_restores_old_root_files_and_supervisor'),
        ('        preserve_download_quarantine(source, stage)', '        pass # discard download provenance', 'test_existing_download_quarantine_is_preserved_on_code'),
        ('        if self.read(descriptor) != value:', '        if False:', 'test_quarantine_write_and_readback_fail_before_promotion'),
        ('            if attributes.read(incoming) != quarantine:', '            if False:', 'test_quarantine_write_and_readback_fail_before_promotion'),
    ):
        source = TARGET.read_text()
        if source.count(before) != 1: raise AssertionError('Mutation lost its actual production seam')
        broken = type('BrokenMacInstall', (MacInstallTransactions,), {'installer': load(source.replace(before, after, 1))})
        result = unittest.TextTestRunner(stream=io.StringIO()).run(broken(case))
        if result.wasSuccessful(): raise AssertionError('Broken native installation was accepted: '+case)
        print('Rejected macOS installer defect: '+case)
    for before, after, case in (
        ('    captured = native_process_state(library, pid)', '    return None\n    captured = native_process_state(library, pid)',
         'test_live_missing_executable_is_rejected_after_bounded_retries'),
        ('        if captured[:3] != current[:3] or captured[3] == 5 and current[3] != 5:', '        if False:',
         'test_missing_path_retry_rejects_pid_reuse_and_zombie_revival'),
        ('    if size != ctypes.sizeof(info):', '    if size < 0:',
         'test_missing_path_rejects_short_or_malformed_native_state'),
        ('    ctypes.set_errno(0)\n    # Nonzero arg explicitly includes zombie processes,',
         '    # Nonzero arg explicitly includes zombie processes,',
         'test_missing_path_state_errors_never_prove_absence'),
    ):
        source = TARGET.read_text()
        if source.count(before) != 1: raise AssertionError('Mutation lost its actual native inventory seam')
        broken = type('BrokenMacInventory', (MacProcessInventory,), {'installer': load(source.replace(before, after, 1))})
        result = unittest.TextTestRunner(stream=io.StringIO()).run(broken(case))
        if result.wasSuccessful(): raise AssertionError('Broken native process inventory was accepted: '+case)
        print('Rejected macOS native inventory defect: '+case)
    if sys.platform == 'darwin':
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MacNativeACL))
        if not result.wasSuccessful(): raise SystemExit(1)
        result = unittest.TextTestRunner(verbosity=2).run(MacNativeQuarantine('test_real_download_quarantine_survives_native_installation'))
        if not result.wasSuccessful(): raise SystemExit(1)
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MacNativeProcesses))
        if not result.wasSuccessful(): raise SystemExit(1)
        actual = {str(Path(path).resolve()) for path in native_inventory_with_failure_diagnostic(M)}
        if str(Path(sys.executable).resolve()) not in actual:
            raise AssertionError('Native process inventory lost the actual executing interpreter')
        print('Actual macOS libproc inventory captured the executing interpreter.')
    if arguments.package is not None:
        if sys.platform != 'darwin': raise RuntimeError('Bundled macOS runtime execution requires an actual matching Mac host')
        source = arguments.package.resolve()
        expected = F.runtime_digests(source/'runtime')
        with tempfile.TemporaryDirectory(prefix='routervpn-mac-package-install-') as temporary:
            base = Path(temporary).resolve(strict=True); installed, system = base/'installed', base/'system'
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
