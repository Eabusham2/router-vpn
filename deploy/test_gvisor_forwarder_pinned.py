#!/usr/bin/env python3
"""Run the actual pinned TCP forwarder reuse, packet and retirement controls."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('pinned_gvisor_forwarder', ROOT / 'deploy/prepare-gvisor-scheduler.py')
POLICY = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(POLICY)
PACKAGE = 'github.com/sagernet/gvisor/pkg/tcpip/transport/tcp'
GROUPS = (
    'TestRouterVPNForwarderTimeWaitRealTupleReopens',
    'TestRouterVPNForwarderTimeWaitQueuedDuplicatesDoNotResetReplacement',
    'TestRouterVPNForwarderTimeWaitRechecksRetainedHandler',
    'TestRouterVPNForwarderTimeWaitRegisteredListenerPrecedesForwarder',
    'TestRouterVPNForwarderRetainedRequestCannotEnterClosedStack',
    'TestRouterVPNForwarderCloseJoinsHandshakeBeforePeerACK',
    'TestRouterVPNForwarderTimeWaitQueuedEligibility',
)
SUBCASES = ('newer', 'stale', 'equal', 'syn-ack', 'syn-rst', 'syn-fin', 'checksum',
            'foreign-port', 'foreign-address', 'wrong-network', 'foreign-stack',
            'wrap-newer', 'wrap-stale')
REQUIRED = frozenset((*GROUPS, *(GROUPS[-1] + '/' + case for case in SUBCASES)))


def source_inputs():
    records = {}
    for path in POLICY.inputs():
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError('Pinned forwarder gate lost an owned source input')
        records[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return records


def check_verdicts(output):
    started, passed, package_passed = set(), set(), False
    for line in output.splitlines():
        row = json.loads(line)
        if row.get('Package') not in (None, PACKAGE):
            raise ValueError('Pinned forwarder execution reported a foreign package')
        if row.get('Action') in ('skip', 'fail', 'build-fail') or 'WARNING: DATA RACE' in row.get('Output', ''):
            raise ValueError('Pinned forwarder control failed, raced or skipped')
        name = row.get('Test')
        if name is not None:
            if row.get('Package') != PACKAGE or name not in REQUIRED:
                raise ValueError('Pinned forwarder execution changed its required inventory')
            collection = started if row.get('Action') == 'run' else passed if row.get('Action') == 'pass' else None
            if collection is not None:
                if name in collection:
                    raise ValueError('Pinned forwarder control reported a duplicate verdict')
                if collection is passed and name not in started:
                    raise ValueError('Pinned forwarder control passed without starting')
                collection.add(name)
        elif row.get('Package') == PACKAGE and row.get('Action') == 'pass':
            if package_passed:
                raise ValueError('Pinned forwarder package reported duplicate completion')
            package_passed = True
    if started != REQUIRED or passed != REQUIRED or not package_passed:
        raise ValueError('Pinned forwarder package omitted an actual required verdict')


def run(vendor, go='go', env=None):
    vendor = Path(vendor).resolve()
    captured = dict(os.environ if env is None else env, GOWORK='off')
    POLICY.verify(vendor, go, env=captured)
    before = source_inputs()
    target = subprocess.check_output([go, 'env', 'GOOS', 'GOARCH'], cwd=vendor, env=captured, text=True).split()
    host = [('darwin' if platform.system() == 'Darwin' else platform.system().lower()),
            {'x86_64': 'amd64', 'AMD64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64', 'ARM64': 'arm64'}.get(platform.machine(), '')]
    if target != host or target[0] not in ('darwin', 'linux', 'windows') or target[1] not in ('amd64', 'arm64'):
        raise ValueError('Pinned forwarder controls must execute on the selected native host')
    # The Go race detector is unavailable on Windows ARM64. That actual host
    # still executes every real tuple, packet, cancellation and close control.
    race = [] if target == ['windows', 'arm64'] else ['-race']
    command = [go, 'test', '-json', *race, '-mod=readonly', PACKAGE,
               '-run', '^TestRouterVPNForwarder', '-count=1', '-timeout=45s']
    completed = subprocess.run(command, cwd=vendor, env=captured, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, check=False, timeout=180)
    output = completed.stdout.decode('utf-8')
    print(output, end='', flush=True)
    if completed.returncode:
        raise subprocess.CalledProcessError(completed.returncode, command)
    check_verdicts(output)
    POLICY.verify(vendor, go, env=captured)
    if source_inputs() != before:
        raise ValueError('Pinned forwarder source changed during actual execution')
    print('Verified all seven native forwarder groups and thirteen packet controls with unchanged pinned source.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    run(args.vendor, args.go)
