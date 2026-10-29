#!/usr/bin/env python3
"""Run the real interpreter trust gate with temporary root-owned file fixtures."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import os
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('installer_trust_namespace', ROOT/'deploy/test_linux_controller_privilege.py')
P = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(P)


def identities():
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted([*(ROOT/'cmd/client').glob('install_macos_*.go'),
                                *(ROOT/'cmd/client').glob('owned_path_acl*.go'),
                                *(ROOT/'internal/common').glob('owned_path_acl*.go')])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linux-namespace-binary', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.linux_namespace_binary is not None:
        raise SystemExit(P.namespace_test(args.linux_namespace_binary, '^TestNativeInstallerPythonTrust$'))
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
            command = [str(binary), '-test.run=^TestNativeInstaller(PythonTrust|DarwinACLTrust)$', '-test.v', '-test.count=1', '-test.timeout=60s']
        if sudo is not None: command = [sudo, '-n', '--', *command]
        output = P.UID.run(command, cwd=ROOT, timeout=90, sudo=sudo)
        if '--- PASS: TestNativeInstallerPythonTrust (' not in output or '--- SKIP:' in output:
            raise RuntimeError('Actual interpreter ownership gate was not executed')
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
