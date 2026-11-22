#!/usr/bin/env python3
"""Run the complete imported SS controller roots on their actual native host.

These are original controller/source/ownership fixtures. Native encrypted Box,
privileged packet execution and physical-device acceptance remain separate.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'router-vpn/cmd/client'
PREFIX = 'TestDesktopImported'
METHODS = ('2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305')
FAULTS = ('hostname', 'mapped', 'noncanonical', 'zero', 'multicast', 'wrong-endpoint',
          'bad-key', 'layer', 'paired-id', 'duplicate-proof', 'duplicate-id', 'long',
          'other-mode', 'wrong-final')
CASES = {
    'TrioExecutionOriginalPreparation': ('linux/2022-blake3-aes-128-gcm/server', 'linux/2022-blake3-aes-128-gcm/auto', 'linux/2022-blake3-aes-256-gcm/server', 'linux/2022-blake3-aes-256-gcm/auto', 'linux/2022-blake3-chacha20-poly1305/server', 'linux/2022-blake3-chacha20-poly1305/auto', 'windows/2022-blake3-aes-128-gcm/server', 'windows/2022-blake3-aes-128-gcm/auto', 'windows/2022-blake3-aes-256-gcm/server', 'windows/2022-blake3-aes-256-gcm/auto', 'windows/2022-blake3-chacha20-poly1305/server', 'windows/2022-blake3-chacha20-poly1305/auto'),
    'TrioExecutionSelectionAndSourceRefusals': ('server', 'server/hostname', 'server/mapped', 'server/noncanonical', 'server/zero', 'server/multicast', 'server/wrong-endpoint', 'server/bad-key', 'server/layer', 'server/paired-id', 'server/duplicate-proof', 'server/duplicate-id', 'server/long', 'server/other-mode', 'server/wrong-final', 'auto', 'auto/hostname', 'auto/mapped', 'auto/noncanonical', 'auto/zero', 'auto/multicast', 'auto/wrong-endpoint', 'auto/bad-key', 'auto/layer', 'auto/paired-id', 'auto/duplicate-proof', 'auto/duplicate-id', 'auto/long', 'auto/other-mode', 'auto/wrong-final'),
    'TrioExecutionPublicConnectUsesOriginalChild': ('3-server-server', '3-auto-local', '3-auto-server'),
    'TrioExecutionRestoreRetainsChosenSource': ('local', 'server'),
    'TrioExecutionRefusesMissingOrForeignNativeMiddle': ('omitted', 'foreign'),
    'TrioExecutionSavedProfileRetainsSource': ('server', 'auto'),
    'PrefixExecutionSelectionBounds': ('1-wg', '1-awg2-fast', '1-awg2-strong', '2-wg', '2-awg2-fast', '2-awg2-strong', '3-wg', '3-awg2-fast', '3-awg2-strong', '4-wg', '4-awg2-fast', '4-awg2-strong', '5-wg', '5-awg2-fast', '5-awg2-strong', '6-wg', '6-awg2-fast', '6-awg2-strong'),
    'PrefixExecutionMixedPreparation': ('2-linux-server', '2-linux-auto', '2-windows-server', '2-windows-auto', '6-linux-server', '6-linux-auto', '6-windows-server', '6-windows-auto'),
    'PrefixExecutionRecapturesMovedSource': ('server', 'auto'),
    'PrefixExecutionRejectsChangedShape': ('prefix-mode', 'two-imports', 'wrong-position', 'custom-entry', 'imported-final', 'duplicate-id', 'duplicate-proof', 'missing-proof', 'hostname', 'paired-import', 'wrong-final', 'over-bound', 'connect-family', 'socks-family'),
    'PrefixExecutionOriginalPreparation': ('linux/4/server', 'linux/4/auto', 'linux/8/server', 'linux/8/auto', 'windows/4/server', 'windows/4/auto', 'windows/8/server', 'windows/8/auto'),
    'PrefixExecutionSourceRefusals': ('old-middle', 'second-import', 'middle-key', 'hostname', 'prefix-mode', 'prefix-proof', 'prefix-id', 'final-mode', 'too-many', 'connect-long'),
    'PrefixExecutionRefusesForeignNativeMiddle': ('omitted', 'foreign'),
    'PrefixExecutionSavedBounds': ('old-middle', 'wrong-prefix', 'other-family', 'missing-token'),
    'PrefixExecutionPublic4Server': ('4-server-server',),
    'PrefixExecutionPublic4CompareLocal': ('4-auto-local',),
    'PrefixExecutionPublic4CompareServer': ('4-auto-server',),
    'PrefixExecutionPublic8Server': ('8-server-server',),
    'PrefixExecutionPublic8CompareLocal': ('8-auto-local',),
    'PrefixExecutionPublic8CompareServer': ('8-auto-server',),
    'PrefixExecutionRestoreRetainsChosenSource': ('4', '4/local', '4/server', '8', '8/local', '8/server'),
    'PrefixExecutionSavedProfileRetainsSource': ('4', '4/server', '4/auto', '8', '8/server', '8/auto'),
}

def load():
    spec = importlib.util.spec_from_file_location('imported_controller_native_builder', ROOT/'deploy/build-native-runtime.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

BUILDER = load()

def expected(root=None):
    if root is not None and root not in CASES:
        raise ValueError('unknown imported controller root')
    return {PREFIX+name+suffix for name, children in CASES.items() if root is None or name == root
            for suffix in ('', *('/'+child for child in children))}

def source_identity():
    # Retain the existing native builder's complete shipping inputs, including
    # embedded app assets and every original helper used by these controllers.
    rows = []
    sources = set(BUILDER.inputs()) | {ROOT/'deploy/native_multihop_audit.py', ROOT/'deploy/test_native_shipping_audit_gates.py'}
    for path in sorted(sources):
        if path.is_symlink() or not path.is_file():
            raise ValueError('imported controller lost original regular source')
        rows.append((path.relative_to(ROOT).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()))
    required = {'cmd/client/desktop_node_chain_imported_execution.go',
                'cmd/client/connection_profile_node_chain.go',
                'cmd/client/desktop_node_chain_execution_launch.go',
                'cmd/client/desktop_node_chain_execution_launch_test.go',
                'cmd/client/desktop_node_chain_launch.go',
                'cmd/client/desktop_node_chain_owned.go',
                'cmd/client/desktop_node_owned_observation.go',
                'cmd/client/desktop_node_chain_execution_observation.go',
                'cmd/client/multihop_native_ordered_status.go',
                'cmd/client/multihop_native_execution_retained_status_test.go',
                'internal/mobilemultihop/node_chain_execution_desktop.go',
                'internal/mobilemultihop/node_chain_execution_desktop_test.go',
                'internal/mobilemultihop/desktop_node_chain_execution_ready.go',
                'internal/mobilemultihop/desktop_node_chain_execution_ready_test.go',
                'cmd/client/desktop_node_chain_imported_prefix_execution_test.go',
                'cmd/client/desktop_node_chain_imported_prefix_observation_test.go',
                'cmd/client/desktop_node_chain_execution_owned_test.go',
                'cmd/client/desktop_node_chain_imported_execution_test.go',
                'cmd/client/desktop_node_chain_imported_execution_product_test.go',
                'cmd/client/desktop_node_chain_imported_execution_profile_test.go',
                'deploy/native_multihop_audit.py',
                'deploy/test_native_shipping_audit_gates.py',
                'deploy/test_desktop_imported_trio_controller.py',
                'deploy/test_desktop_imported_trio_controller_runner.py'}
    if not required.issubset({name for name, _ in rows}):
        raise ValueError('imported controller inputs omitted an original source or gate')
    return hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()

def native_environment(go, without_race):
    executable = shutil.which(go)
    if not executable:
        raise ValueError('selected native Go compiler is unavailable')
    environment = dict(os.environ, GOTOOLCHAIN='local')
    environment.pop('GOROOT', None)
    environment['GOROOT'] = subprocess.check_output([executable, 'env', 'GOROOT'], env=environment, text=True, timeout=15).strip()
    target = BUILDER.native_host_target()
    if target not in ('linux/amd64', 'linux/arm64', 'windows/amd64', 'windows/arm64') or without_race != (target == 'windows/arm64'):
        raise ValueError('imported controller requires its native Windows/Linux host and supported race mode')
    if environment.get('GOOS', target.split('/')[0]) != target.split('/')[0] or environment.get('GOARCH', target.split('/')[1]) != target.split('/')[1]:
        raise ValueError('imported controller cannot execute a cross-compiled host')
    return executable, environment, target

def run(go='go', receipt=None, without_race=False):
    executable, environment, target = native_environment(go, without_race)
    source = source_identity()
    records = []
    with tempfile.TemporaryDirectory(prefix='routervpn-imported-controller-') as directory:
        binary = Path(directory)/('controller.test.exe' if target.startswith('windows/') else 'controller.test')
        command = [executable, 'test', '-c', *([] if without_race else ['-race']), '-p=1', '-mod=readonly', '-o', str(binary), './cmd/client']
        subprocess.run(command, cwd=ROOT, env=environment, check=True, timeout=240)
        image = hashlib.sha256(binary.read_bytes()).hexdigest()
        if source_identity() != source:
            raise ValueError('imported controller source changed during compilation')
        for root in CASES:
            if binary.is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest() != image:
                raise ValueError('imported controller original image changed before its root')
            invocation = [executable, 'tool', 'test2json', '-p', PACKAGE, str(binary), '-test.v=test2json', '-test.count=1', '-test.timeout=120s', '-test.run=^'+PREFIX+root+'$']
            print('Imported controller root: '+root, flush=True)
            try:
                completed = subprocess.run(invocation, cwd=ROOT/'cmd/client', env=environment, capture_output=True, text=True, timeout=135)
            except subprocess.TimeoutExpired as error:
                # Preserve the original child's partial verdict and timeout
                # stacks. An incomplete root still fails without a receipt.
                output = error.stdout or ''
                failure = error.stderr or ''
                if isinstance(output, bytes):
                    output = output.decode('utf-8', errors='replace')
                if isinstance(failure, bytes):
                    failure = failure.decode('utf-8', errors='replace')
                print(output, end='', flush=True)
                print(failure, end='', flush=True)
                if receipt:
                    Path(str(receipt)+'.'+root+'.jsonl').write_text(output)
                raise
            print(completed.stdout, end='', flush=True)
            if completed.stderr:
                print(completed.stderr, end='', flush=True)
            if receipt:
                Path(str(receipt)+'.'+root+'.jsonl').write_text(completed.stdout)
            if completed.returncode:
                raise ValueError('imported controller original native root failed: '+root)
            BUILDER.verify_imported_native_verdicts(completed.stdout, PACKAGE, expected(root))
            if source_identity() != source or binary.is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest() != image:
                raise ValueError('imported controller source/image changed during its root')
            records.append({'root': PREFIX+root, 'tests': len(expected(root)), 'image_sha256': image,
                            'output_sha256': hashlib.sha256(completed.stdout.encode()).hexdigest(), 'command': invocation})
    if len(records) != len(CASES) or sum(row['tests'] for row in records) != len(expected()):
        raise ValueError('imported controller lost its complete original root inventory')
    result = {'schema': 1, 'target': target, 'race': not without_race, 'source_sha256': source,
              'image_sha256': image, 'compile_command': command, 'roots': records, 'tests': len(expected()),
              'scope': 'actual native-host controller/source/ownership fixtures; encrypted prefixes, child process records and privileged kernel state retain declared model boundaries'}
    if receipt:
        Path(receipt).write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    print(json.dumps(result, sort_keys=True), flush=True)
    return result

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--without-race', action='store_true', help='Required only on native Windows ARM64')
    args = parser.parse_args()
    run(args.go, args.receipt, args.without_race)
