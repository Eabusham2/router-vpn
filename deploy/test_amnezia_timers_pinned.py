#!/usr/bin/env python3
"""Execute the actual pinned AWG timer locking and joined-expiration controls."""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_amnezia_timers', ROOT/'deploy/prepare-amnezia-timers.py')
POLICY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(POLICY)
RACE_SPEC = importlib.util.spec_from_file_location('darwin_race_pinned', ROOT/'deploy/darwin_race_toolchain.py')
RACE = importlib.util.module_from_spec(RACE_SPEC)
RACE_SPEC.loader.exec_module(RACE)

REQUIRED = frozenset({
    'TestRouterVPNAmneziaTimerExpirationAndDeleteShareLock',
    'TestRouterVPNAmneziaTimerDelSyncJoinsEnteredExpiration',
    'TestRouterVPNAmneziaTimerCallbackCanRearmWithoutLostDuration',
})
PACKAGE = 'github.com/amnezia-vpn/amneziawg-go/v3/device'


def run(vendor, go='go', env=None):
    if platform.system() == 'Darwin':
        go, env = RACE.capture(vendor, go, dict(os.environ if env is None else env))
    vendor = Path(vendor).resolve()
    env = dict(os.environ if env is None else env)
    POLICY.verify(vendor, go, env=env)
    target = subprocess.check_output([go, 'env', 'GOOS', 'GOARCH'], cwd=vendor, env=env).decode('utf-8').split()
    host = [('darwin' if platform.system() == 'Darwin' else platform.system().lower()),
            {'x86_64': 'amd64', 'AMD64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64', 'ARM64': 'arm64'}.get(platform.machine(), '')]
    if target != host:
        raise ValueError('AWG timer validation must execute on the selected native host')
    # Go does not supply a Windows ARM64 race detector. That actual host still
    # executes all three callback, deletion and rearm controls unchanged.
    race = [] if target == ['windows', 'arm64'] else ['-race']
    command = [go, 'test', '-json', *race, '-mod=readonly', PACKAGE,
               '-run', '^TestRouterVPNAmneziaTimer', '-count=1', '-timeout=30s']
    completed = subprocess.run(command, cwd=vendor, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, check=False, timeout=180)
    output = completed.stdout.decode('utf-8')
    print(output, end='', flush=True)
    if completed.returncode:
        raise subprocess.CalledProcessError(completed.returncode, command)
    started, passed = set(), set()
    package_passed = False
    for line in output.splitlines():
        record = json.loads(line)
        if record.get('Action') in ('skip', 'fail') or 'WARNING: DATA RACE' in record.get('Output', ''):
            raise ValueError('Native AWG timer control skipped, raced or failed')
        name = record.get('Test')
        if name is not None:
            if record.get('Package') != PACKAGE or name not in REQUIRED:
                raise ValueError('Native AWG timer execution changed its required case inventory')
            if record.get('Action') == 'run':
                if name in started:
                    raise ValueError('Native AWG timer control ran more than once')
                started.add(name)
            elif record.get('Action') == 'pass':
                if name in passed:
                    raise ValueError('Native AWG timer control passed more than once')
                passed.add(name)
        elif record.get('Package') == PACKAGE and record.get('Action') == 'pass':
            if package_passed:
                raise ValueError('Native AWG timer package reported duplicate completion')
            package_passed = True
    if started != REQUIRED or passed != REQUIRED or not package_passed:
        raise ValueError('Native AWG timer package omitted an actual required verdict')
    POLICY.verify(vendor, go, env=env)
    print('Verified all three actual AWG timer controls and unchanged pinned source.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    run(args.vendor, args.go)
