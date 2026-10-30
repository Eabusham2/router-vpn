#!/usr/bin/env python3
"""Execute the final macOS shell handoff under actual ordinary/root UIDs.

Only the adjacent native installer is a harmless recording fixture. The exact
shipping entry runs in real Bash with an untrusted PATH, actual file checks,
PID/argument/exit observation, and no installation or network activity. This
does not replace the separate privileged native installer/Apple device gates.
"""
from pathlib import Path
import hashlib
import io
import os
import pwd
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'client/install-macos-final.sh'


class MacFinalEntry(unittest.TestCase):
    source = TARGET.read_text(encoding='utf-8')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='routervpn-mac-final-entry-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.base.chmod(0o755)
        if os.geteuid() == 0:
            requested = int(os.environ.get('SUDO_UID', '0'))
            account = pwd.getpwuid(requested) if requested > 0 else pwd.getpwnam('nobody')
            if account.pw_uid <= 0:
                raise RuntimeError('Entry test needs an actual ordinary account')
            self.uid, self.gid = account.pw_uid, account.pw_gid
        else:
            self.uid, self.gid = os.geteuid(), os.getegid()
        self.home = self.base / 'home'
        self.home.mkdir(mode=0o700)
        self.observed = self.base / 'observed'
        self.observed.mkdir(mode=0o700)
        if os.geteuid() == 0:
            os.chown(self.home, self.uid, self.gid)
            os.chown(self.observed, self.uid, self.gid)
        self.package = self.make_package("package with spaces ' and $(literal)")
        self.entry = self.package / 'client/install-macos-final.sh'
        self.entry.write_text(self.source, encoding='utf-8')
        self.entry.chmod(0o755)
        self.native = self.package / 'client/install-macos-native.sh'
        self.native.write_text('#!/bin/bash\nset -eu\n'
                               'printf "%s\\0" "$$" "$EUID" "$#" "$@" > "$ENTRY_RECORD"\n'
                               'printf "native stdout\\n"\n'
                               'printf "native stderr\\n" >&2\n'
                               'exit "$ENTRY_STATUS"\n', encoding='utf-8')
        self.native.chmod(0o755)
        self.path = self.base / 'untrusted-path'
        self.path.mkdir()
        for name in ('bash', 'dirname', 'pwd', 'ditto', 'xattr', 'cp', 'mv', 'rm', 'open'):
            candidate = self.path / name
            candidate.write_text('#!/bin/bash\nprintf "ambient command" > "$ENTRY_RECORD"\nexit 91\n', encoding='utf-8')
            candidate.chmod(0o755)

    def make_package(self, name):
        package = self.base / name
        (package / 'client').mkdir(parents=True)
        app = package / 'RouterVPN.app/Contents/MacOS/RouterVPN'
        app.parent.mkdir(parents=True)
        for executable in (app, package / 'router-vpn-client'):
            executable.write_text('#!/bin/bash\nexit 92\n', encoding='utf-8')
            executable.chmod(0o755)
        (package / 'client.json').write_text('{}\n', encoding='utf-8')
        (package / 'LICENSE').write_text('fixture license\n', encoding='utf-8')
        return package

    def invoke(self, arguments=(), *, cwd=None, status=0, root=False):
        record = self.observed / 'native-record'
        record.unlink(missing_ok=True)
        environment = {'PATH': str(self.path), 'HOME': str(self.home), 'LC_ALL': 'C',
                       'ENTRY_RECORD': str(record), 'ENTRY_STATUS': str(status)}
        command = ['/bin/bash', str(self.entry), *map(str, arguments)]
        options = {}
        if os.geteuid() == 0:
            options = {'user': 0 if root else self.uid, 'group': 0 if root else self.gid, 'extra_groups': []}
        elif root:
            # sudo failure is not evidence: the test requires the entry's own
            # root rejection, before its harmless recording fixture executes.
            command = ['/usr/bin/sudo', '-n', '--', '/usr/bin/env', '-i',
                       *(name + '=' + value for name, value in environment.items()), *command]
        process = subprocess.Popen(command, cwd=cwd or self.package, env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **options)
        stdout, stderr = process.communicate(timeout=10)
        values = None
        if record.exists():
            values = record.read_bytes().split(b'\0')
            if values[-1] == b'':
                values.pop()
            values = [value.decode('utf-8') for value in values]
        self.assertFalse((self.home / 'Applications').exists(), 'final entry resumed a separate user-copy installation')
        return process.pid, process.returncode, stdout, stderr, values

    def require_native(self, observed, package, status=0):
        pid, code, stdout, stderr, values = observed
        self.assertEqual(code, status, 'final entry changed the native installer exit')
        self.assertEqual(values, [str(pid), str(self.uid), '1', str(package.resolve())],
                         'final entry did not exec the fixed native wrapper with one exact package argument')
        self.assertEqual(stdout, 'native stdout\n', 'final entry changed native stdout or resumed after dispatch')
        self.assertEqual(stderr, 'native stderr\n', 'final entry changed native stderr or resumed after dispatch')

    def test_default_directory_exec_preserves_pid_streams_and_status(self):
        for status in (0, 23, 77):
            with self.subTest(status=status):
                self.require_native(self.invoke(status=status), self.package, status)

    def test_explicit_relative_package_is_canonical_and_literal(self):
        self.require_native(self.invoke([self.package.name], cwd=self.base), self.package)

    def test_dispatch_uses_fixed_sibling_not_the_selected_package_script(self):
        other = self.make_package('separately selected package')
        foreign = other / 'client/install-macos-native.sh'
        foreign.write_text('#!/bin/bash\nprintf "foreign installer" > "$ENTRY_RECORD"\nexit 93\n')
        foreign.chmod(0o755)
        self.require_native(self.invoke([other]), other)

    def test_root_is_rejected_before_any_native_dispatch(self):
        _, code, _, stderr, values = self.invoke(root=True)
        self.assertNotEqual(code, 0, 'root entry bypassed the ordinary-user requirement')
        self.assertIn('Run this as your normal Mac user', stderr, 'actual root admission was not exercised')
        self.assertIsNone(values, 'root entry reached a native installer')

    def test_unknown_arguments_are_rejected_without_ignoring_them(self):
        _, code, _, stderr, values = self.invoke([self.package, 'unexpected'])
        self.assertEqual(code, 2, 'extra installer arguments were silently discarded')
        self.assertIn('Usage:', stderr)
        self.assertIsNone(values)

    def test_source_preflight_rejects_missing_native_app_runtime_config_or_license(self):
        for relative in ('RouterVPN.app/Contents/MacOS/RouterVPN', 'router-vpn-client', 'client.json', 'LICENSE'):
            with self.subTest(relative=relative):
                path = self.package / relative
                content, mode = path.read_bytes(), path.stat().st_mode & 0o777
                path.unlink()
                try:
                    _, code, _, _, values = self.invoke()
                    self.assertNotEqual(code, 0, 'incomplete native package passed entry preflight')
                    self.assertIsNone(values, 'incomplete native package reached installer dispatch')
                finally:
                    path.write_bytes(content)
                    path.chmod(mode)

    def test_nonexecutable_native_app_is_rejected(self):
        app = self.package / 'RouterVPN.app/Contents/MacOS/RouterVPN'
        app.chmod(0o644)
        _, code, _, _, values = self.invoke()
        self.assertNotEqual(code, 0, 'nonexecutable AppKit package passed entry preflight')
        self.assertIsNone(values)

    def test_missing_or_linked_sibling_is_rejected_before_execution(self):
        body = self.native.read_bytes()
        self.native.unlink()
        for linked in (False, True):
            with self.subTest(linked=linked):
                if linked:
                    target = self.base / 'foreign-native.sh'
                    target.write_bytes(body)
                    target.chmod(0o755)
                    self.native.symlink_to(target)
                _, code, _, stderr, values = self.invoke()
                self.assertNotEqual(code, 0, 'unretained adjacent native entry was dispatched')
                self.assertIn('adjacent native macOS installer', stderr)
                self.assertIsNone(values)


def main():
    before = hashlib.sha256(TARGET.read_bytes()).hexdigest()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MacFinalEntry))
    if not result.wasSuccessful():
        raise SystemExit(1)
    mutations = (
        ('unjoined-child', 'exec /bin/bash "$NATIVE_INSTALLER" "$BUNDLE"', '/bin/bash "$NATIVE_INSTALLER" "$BUNDLE"',
         'test_default_directory_exec_preserves_pid_streams_and_status', 'did not exec the fixed native wrapper'),
        ('ambient-bash', 'exec /bin/bash "$NATIVE_INSTALLER" "$BUNDLE"', 'exec bash "$NATIVE_INSTALLER" "$BUNDLE"',
         'test_default_directory_exec_preserves_pid_streams_and_status', 'changed the native installer exit'),
        ('dropped-package', 'exec /bin/bash "$NATIVE_INSTALLER" "$BUNDLE"', 'exec /bin/bash "$NATIVE_INSTALLER"',
         'test_explicit_relative_package_is_canonical_and_literal', 'did not exec the fixed native wrapper'),
        ('foreign-wrapper', 'NATIVE_INSTALLER="$INSTALLER_DIR/install-macos-native.sh"', 'NATIVE_INSTALLER="$BUNDLE/client/install-macos-native.sh"',
         'test_dispatch_uses_fixed_sibling_not_the_selected_package_script', 'changed the native installer exit'),
        ('root-admission', '[[ $EUID -ne 0 ]]', '[[ $EUID -ge 0 ]]',
         'test_root_is_rejected_before_any_native_dispatch', 'bypassed the ordinary-user requirement'),
        ('app-preflight', '[[ -x "$APP_SRC/Contents/MacOS/RouterVPN" ]]', '[[ -n "$APP_SRC" ]]',
         'test_nonexecutable_native_app_is_rejected', 'nonexecutable AppKit package passed entry preflight'),
    )
    for name, original, replacement, case, witness in mutations:
        if MacFinalEntry.source.count(original) != 1:
            raise AssertionError('Installer entry mutation lost its exact shipping boundary: ' + name)
        broken = type('BrokenMacFinalEntry', (MacFinalEntry,), {'source': MacFinalEntry.source.replace(original, replacement, 1)})
        output = io.StringIO()
        result = unittest.TextTestRunner(stream=output).run(broken(case))
        if result.wasSuccessful() or result.errors or witness not in output.getvalue():
            raise AssertionError('Installer entry defect missed its intended executable witness: ' + name + '\n' + output.getvalue())
        print('Rejected actual shell installer-entry defect: ' + name)
    if hashlib.sha256(TARGET.read_bytes()).hexdigest() != before:
        raise AssertionError('Shipping final installer changed during verification')
    print('Final macOS entry: actual ordinary UID, fixed sibling, same-PID exec, exact arguments and native exit propagation PASS. Native installation remains a separate gate.')


if __name__ == '__main__':
    main()
