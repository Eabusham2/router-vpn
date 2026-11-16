"""Finite case and verdict contracts for the required installed Naive H2 phase.

Synthetic verdict tests exercise this parser only. Native receipts are written
only by the separate real Linux/Darwin installed-host executor.
"""
from collections import Counter
import re

LINUX_ACTIONS = ('public-connect', 'public-off', 'home-lan', 'wrong-key', 'wrong-user',
                 'wrong-trust', 'wrong-server-name', 'resolver-failure', 'wrong-node',
                 'active-network-change', 'cancelled-proof', 'restore-sealed', 'always',
                 'mtu-rollback', 'mtu-commit')
LINUX_CASES = tuple('naive-h2-'+layer+'-'+action for layer in ('off', 'aes', 'whitening')
                    for action in LINUX_ACTIONS) + (
    'naive-h2-aes-wrong-layer-key', 'naive-h2-whitening-wrong-layer-key',
    'naive-h2-whitening-wrong-whitening')
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
POLICIES = ('off', 'on-connect', 'always')
DARWIN_ACTIONS = ('home-lan-wrong-node', 'resolver-failure', 'wrong-key', 'wrong-user',
                  'wrong-trust', 'wrong-server-name', 'restore-sealed', 'mtu-rollback')
DARWIN_CASES = tuple(case for layer in LAYERS for case in (
    *('naive-h2/'+layer+'/'+policy+'/connect' for policy in POLICIES),
    *('naive-h2/'+layer+'/on-connect/'+action for action in DARWIN_ACTIONS))) + (
    'naive-h2/aes-256-gcm/on-connect/wrong-layer-key',
    'naive-h2/aes-256-gcm+xor-whitening/on-connect/wrong-layer-key',
    'naive-h2/aes-256-gcm+xor-whitening/on-connect/wrong-whitening')
LINUX_TEST = 'TestDesktopLinuxGuardianKernelNodeHostTUN'
DARWIN_TEST = 'TestMacOSRetainedPairedNaiveH2NativePublicGraphs'
DARWIN_MTU_RECEIPT = 'actual paired Darwin MTU: Auto and Retest transferred original encrypted UDP, held Cancel joined exact rollback, original process PF and reader succession retained'


def linux_action(case):
    if case not in LINUX_CASES:
        raise ValueError('Unknown original Naive H2 Linux scenario')
    return next(case.removeprefix(prefix) for prefix in ('naive-h2-off-', 'naive-h2-aes-', 'naive-h2-whitening-') if case.startswith(prefix))


def receipts(target, case):
    if target == 'darwin' and case in DARWIN_CASES:
        result = ['actual paired Darwin public host verified '+case+': original encrypted proof boundary, joined native PF and utun retirement']
        if case.endswith('/mtu-rollback'):
            result.append(DARWIN_MTU_RECEIPT)
        return result
    if target != 'linux' or case not in LINUX_CASES:
        raise ValueError('Unknown original Naive H2 native target or case')
    action = linux_action(case)
    names = ['captured Naive H2 TLS UoT and TCP-only lower', 'native lifecycle']
    if not case.startswith('naive-h2-off-'):
        names.append('captured Start Layer')
    public = action in ('public-connect', 'public-off')
    mtu = action in ('mtu-rollback', 'mtu-commit')
    restore = action == 'restore-sealed'
    if public or mtu or restore or action == 'active-network-change':
        names.append('active lifetime')
    if public:
        names.extend(('retained DNS observation', 'public Connect and Disconnect'))
    if public or mtu:
        names.append('live MTU status')
    if mtu:
        names.append('original MTU lease')
    if restore:
        names.append('sealed temporary restoration')
    if action == 'public-off':
        names.append('saved Linux protection Off')
    return ['verified installed host '+name+': '+case for name in names]


def check_verdict(output, target, case):
    root = LINUX_TEST if target == 'linux' else DARWIN_TEST
    wanted = Counter(receipts(target, case))
    if not isinstance(output, str) or re.search(r'(?im)^\s*(?:--- (?:FAIL|SKIP):|FAIL(?:\s|$)|SKIP(?:\s|$)|WARNING: DATA RACE|panic:|fatal error:)|\[build failed\]', output):
        raise ValueError('Naive H2 native execution failed, skipped or raced')
    expected = {root, root+'/'+case}
    runs, passed, observed = Counter(), Counter(), Counter()
    complete = 0
    for line in output.replace('\r\n', '\n').splitlines():
        run = re.fullmatch(r'=== RUN   (\S+)', line)
        success = re.fullmatch(r'(?:    )?--- PASS: (\S+) \([0-9]+(?:\.[0-9]+)?s\)', line)
        witness = re.fullmatch(r'\s+[A-Za-z0-9_]+\.go:\d+: ((?:verified installed host|actual paired Darwin).*)', line)
        if run:
            name = run[1]
            if name not in expected or complete or runs[name] or passed[root] or name != root and runs[root] != 1:
                raise ValueError('Naive H2 native run lost its original owner')
            runs[name] += 1
        if success:
            name = success[1]
            if name not in expected or complete or runs[name] != 1 or passed[name]:
                raise ValueError('Naive H2 native pass was missing, duplicated or borrowed')
            passed[name] += 1
        if witness:
            if complete or runs[root+'/'+case] != 1 or passed[root]:
                raise ValueError('Naive H2 receipt escaped its original execution')
            observed[witness[1]] += 1
        if line == 'PASS':
            if set(passed) != expected:
                raise ValueError('Naive H2 native package completed without its exact case')
            complete += 1
    if set(runs) != expected or set(passed) != expected or observed != wanted or complete != 1:
        raise ValueError('Naive H2 native omitted exact traffic, policy or joined lifecycle receipts')
