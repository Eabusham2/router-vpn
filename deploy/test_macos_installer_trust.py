#!/usr/bin/env python3
"""Run the real interpreter trust gate with temporary root-owned file fixtures."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import os
import platform
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('installer_trust_namespace', ROOT/'deploy/test_linux_controller_privilege.py')
P = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(P)
BOOTSTRAP_CASES = {
    'TestMacOSInstallerBootstrapExecOwnsPIDStatusAndCleanup': (
        'help', 'entry-failure', 'capture-replaced', 'exec-failure'),
    'TestMacOSInstallerBootstrapPackage': ('actual-import', 'actual-entrypoint'),
    'TestMacOSInstallerBootstrapRejectsUnsafeCapture': (
        'missing-helper', 'wrong-helper-location', 'linked-helper', 'directory-helper',
        'empty-helper', 'oversized-helper', 'existing-client', 'existing-modes',
        'linked-client', 'linked-modes', 'linked-private', 'public-private',
        'linked-source-root', 'linked-source-client', 'linked-source-modes'),
    'TestMacOSInstallerBootstrapRetainsOriginalDirectories': ('root', 'client', 'modes'),
    'TestMacOSInstallerBootstrapRejectsMissingOrWrongImport': (
        'missing-with-ambient-helper', 'wrong-captured-helper'),
}
COMMON_CASES = ('TestNativeInstallerPythonTrust', 'TestMacPythonStaticLoadCapture',
                'TestMacPythonEnvironmentAndLoaderPaths', *BOOTSTRAP_CASES)
COMMON_PATTERN = '^(' + '|'.join(COMMON_CASES) + ')$'


def identities():
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted([*(ROOT/'cmd/client').glob('install_macos_*.go'),
                                *(ROOT/'cmd/client').glob('owned_path_acl*.go'),
                                *(ROOT/'internal/common').glob('owned_path_acl*.go'),
                                Path(__file__).resolve(),
                                *(ROOT/name for name in (
                                    'client/install-macos-native.py', 'client/install-linux-native.py',
                                    'client/install-macos-generation.py', 'client/install-macos-image.py',
                                    'modes/darwin_install_capability.py'))])}


def require_bootstrap_cases(output):
    passed = re.findall(r'(?m)^\s*--- PASS: (\S+) \([0-9]+(?:\.[0-9]+)?s\)$', output)
    if '--- SKIP:' in output or '--- FAIL:' in output:
        raise RuntimeError('Installer package bootstrap skipped or failed a captured input boundary')
    for root, cases in BOOTSTRAP_CASES.items():
        for name in (root, *(root+'/'+case for case in cases)):
            if passed.count(name) != 1:
                raise RuntimeError('Installer package bootstrap omitted or duplicated its actual boundary: '+name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linux-namespace-binary', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.linux_namespace_binary is not None:
        raise SystemExit(P.namespace_test(args.linux_namespace_binary, COMMON_PATTERN))
    if platform.system() not in ('Linux', 'Darwin'):
        raise RuntimeError('Interpreter trust needs a real Unix ownership boundary')
    sudo = P.UID.privilege_tool()
    before = identities()
    compiler, environment = P.UID.compiler_toolchain(ROOT, 'go', dict(os.environ, GOWORK='off'))
    with tempfile.TemporaryDirectory(prefix='routervpn-python-trust-') as temporary:
        binary = Path(temporary)/'installer-trust.test'
        P.UID.run([compiler, 'test', '-c', '-race', '-mod=readonly', '-tags=routervpn_installer_privileged',
                   '-o', binary, './cmd/client'], cwd=ROOT, env=environment)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        if before != identities(): raise RuntimeError('Installer trust source changed during compilation')
        if platform.system() == 'Linux':
            command = [sys.executable, str(Path(__file__).resolve()), '--linux-namespace-binary', str(binary)]
        else:
            pattern = '^(' + '|'.join((*COMMON_CASES, 'TestNativeInstallerDarwinACLTrust')) + ')$'
            command = [str(binary), '-test.run='+pattern, '-test.v', '-test.count=1', '-test.timeout=60s']
        if sudo is not None: command = [sudo, '-n', '--', *command]
        output = P.UID.run(command, cwd=ROOT, timeout=90, sudo=sudo)
        if any('--- PASS: '+name+' (' not in output for name in COMMON_CASES) or '--- SKIP:' in output:
            raise RuntimeError('Actual interpreter ownership gate was not executed')
        require_bootstrap_cases(output)
        if '--- PASS: TestNativeInstallerPythonTrust/captured-runtime (' not in output:
            raise RuntimeError('Actual static interpreter runtime closure was not executed')
        if platform.system() == 'Darwin' and '--- PASS: TestNativeInstallerDarwinACLTrust (' not in output:
            raise RuntimeError('Actual macOS ACL authority gate was not executed')
        if before != identities() or digest != hashlib.sha256(binary.read_bytes()).hexdigest():
            raise RuntimeError('Installer trust source or executable changed during verification')
        print(output, end='')


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        if error.output: sys.stderr.write(error.output[-12000:].decode('utf-8', errors='replace'))
        raise
