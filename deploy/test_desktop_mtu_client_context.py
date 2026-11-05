#!/usr/bin/env python3
"""Run the actual desktop client MTU observation boundary and require every verdict."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CLIENT = 'router-vpn/cmd/client'
NETWORK = 'router-vpn/internal/desktopnetwork'
PROCESS = 'router-vpn/internal/linuxprocess'
PROTECTION = 'router-vpn/internal/linuxprotection'
SNAPSHOT = 'TestDesktopMTUSnapshotOriginalContextAdmission'
EXPECTED = {
    CLIENT: [SNAPSHOT, SNAPSHOT+'/external', SNAPSHOT+'/tor',
             *[SNAPSHOT+'/'+family+'/'+boundary for family in ('external', 'tor')
               for boundary in ('app', 'runtime', 'workspace', 'proof')
               if family != 'external' or boundary != 'proof'],
             'TestDesktopMTURunCreatesCallerContextBeforeSnapshot',
             'TestDesktopMTUProofObservationRetainsMixedFailure',
             'TestDesktopMTUSnapshotRejectsOriginalSessionReplacement',
             'TestDesktopMTUActualWritersKeepCallerDeadline',
             'TestDesktopMTUActualWritersKeepCallerDeadline/retest',
             'TestDesktopMTUActualWritersKeepCallerDeadline/captured-restore'],
    NETWORK: ['TestNetworkInterfaceInventoryRetainsOriginalObservation',
              *['TestNetworkInterfaceInventoryRetainsOriginalObservation/'+leaf
                for leaf in ('exact-fields', 'late-cancel', 'duplicate-index')]],
    PROCESS: ['TestProcessObservationExpiryAfterAdmissionPreservesWitness'],
    PROTECTION: ['TestNodeControlOriginalContextGatePreservesAdmission', 'TestNodeControlOriginalContextKeepsRealFailure'],
}
SELECTOR = '^Test(DesktopMTU(SnapshotOriginalContextAdmission|RunCreatesCallerContextBeforeSnapshot|ProofObservationRetainsMixedFailure|SnapshotRejectsOriginalSessionReplacement|ActualWritersKeepCallerDeadline)|NetworkInterfaceInventoryRetainsOriginalObservation|ProcessObservationExpiryAfterAdmissionPreservesWitness|NodeControlOriginalContext(GatePreservesAdmission|KeepsRealFailure))$'


NATIVE_EXPECTED = {
    PROCESS: ['TestLinuxObservationContextNestedOriginalGates',
              *['TestLinuxObservationContextNestedOriginalGates/'+leaf for leaf in ('parent-task', 'created-child', 'child-task')],
              'TestLinuxObservationContextRejectsRealLossAndCapture',
              *['TestLinuxObservationContextRejectsRealLossAndCapture/'+leaf for leaf in ('native-loss', 'native-loss-with-expiry')]],
    PROTECTION: ['TestNodeControlContextWaitsForOriginalBootstrap'],
}
NATIVE_SELECTOR = '^Test(LinuxObservationContext(NestedOriginalGates|RejectsRealLossAndCapture)|NodeControlContextWaitsForOriginalBootstrap)$'

def check(output, expected=None):
    expected = EXPECTED if expected is None else expected
    terminal = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        action, package, test = row.get('Action'), row.get('Package'), row.get('Test', '')
        if action in ('fail', 'skip'):
            raise ValueError('MTU caller observation gate failed or skipped: '+package+'/'+test)
        if action == 'pass':
            key = package, test
            terminal[key] = terminal.get(key, 0)+1
    wanted = {(package, test) for package, tests in expected.items() for test in ['', *tests]}
    if set(terminal) != wanted or any(value != 1 for value in terminal.values()):
        raise ValueError('MTU caller observation gate has missing, duplicate or foreign verdicts')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--go', default='go')
    parser.add_argument('--check-json', type=Path)
    parser.add_argument('--native-only', action='store_true', help='run original process/pidfd/bootstrap tests under the native controller privilege gate')
    args = parser.parse_args()
    expected = NATIVE_EXPECTED if args.native_only else EXPECTED
    if args.check_json:
        check(args.check_json.read_text(), expected)
    else:
        packages = ['./internal/linuxprocess', './internal/linuxprotection'] if args.native_only else ['./cmd/client', './internal/desktopnetwork', './internal/linuxprocess', './internal/linuxprotection']
        command = [args.go, 'test', '-mod=readonly', '-race']
        if args.native_only:
            command += ['-tags=routervpn_controller_privileged']
        command += packages + ['-run', NATIVE_SELECTOR if args.native_only else SELECTOR, '-count=1', '-timeout=120s', '-json']
        result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(result.stdout, end='')
        if result.returncode:
            raise SystemExit(result.returncode)
        check(result.stdout, expected)
    print('All exact desktop MTU caller-context verdicts passed.')


if __name__ == '__main__':
    main()
