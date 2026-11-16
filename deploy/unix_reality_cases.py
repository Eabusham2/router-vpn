"""Finite case and verdict contracts for the required installed REALITY phase.

Synthetic verdict tests exercise this parser only. Native receipts are written
only by the separate real Linux/Darwin installed-host executor.
"""
from collections import Counter
import re

MODES = ('reality-vision', 'reality-pq-vision', 'reality-xhttp')
LINUX_LAYERS = ('off', 'aes', 'whitening')
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
POLICIES = ('off', 'on-connect', 'always')
LINUX_ACTIONS = ('public-connect', 'public-off', 'home-lan', 'wrong-key', 'wrong-user',
                 'wrong-server-name', 'wrong-short-id', 'resolver-failure', 'wrong-node',
                 'active-network-change', 'cancelled-proof', 'restore-sealed', 'always',
                 'mtu-rollback', 'mtu-commit')
DARWIN_ACTIONS = ('home-lan-wrong-node', 'resolver-failure', 'wrong-key', 'wrong-user',
                  'wrong-server-name', 'wrong-short-id', 'restore-sealed', 'mtu-rollback')
LINUX_CASES = tuple(case for mode in MODES for case in (
    *(mode+'-'+layer+'-'+action for layer in LINUX_LAYERS
      for action in (*LINUX_ACTIONS, *(('wrong-pq-key',) if mode != 'reality-vision' else ()),
                     *(('wrong-path',) if mode == 'reality-xhttp' else ()))),
    mode+'-aes-wrong-layer-key', mode+'-whitening-wrong-layer-key', mode+'-whitening-wrong-whitening'))
DARWIN_CASES = tuple(case for mode in MODES for case in (
    *(case for layer in LAYERS for case in (
      *(mode+'/'+layer+'/'+policy+'/connect' for policy in POLICIES),
      *(mode+'/'+layer+'/on-connect/'+action for action in (
        *DARWIN_ACTIONS, *(('wrong-pq-key',) if mode != 'reality-vision' else ()),
        *(('wrong-path',) if mode == 'reality-xhttp' else ()))))),
    mode+'/aes-256-gcm/on-connect/wrong-layer-key',
    mode+'/aes-256-gcm+xor-whitening/on-connect/wrong-layer-key',
    mode+'/aes-256-gcm+xor-whitening/on-connect/wrong-whitening'))
LINUX_TEST = 'TestDesktopLinuxGuardianKernelNodeHostTUN'
DARWIN_TEST = 'TestMacOSRetainedPairedREALITYNativePublicGraphs'
DARWIN_MTU_RECEIPT = 'actual paired Darwin MTU: Auto and Retest transferred original encrypted UDP, held Cancel joined exact rollback, original process PF and reader succession retained'


def mode_cases(target, mode):
    """One mandatory closed partition; the workflow requires all three modes."""
    if target not in ('linux', 'darwin') or mode not in MODES:
        raise ValueError('Unknown original REALITY native target or mode')
    cases = LINUX_CASES if target == 'linux' else DARWIN_CASES
    separator = '-' if target == 'linux' else '/'
    return tuple(case for case in cases if case.startswith(mode+separator))


def linux_action(case):
    if case not in LINUX_CASES:
        raise ValueError('Unknown original REALITY Linux scenario')
    return next(case.removeprefix(prefix) for prefix in (mode+'-'+layer+'-' for mode in MODES for layer in LINUX_LAYERS) if case.startswith(prefix))


def receipts(target, case):
    if target == 'darwin' and case in DARWIN_CASES:
        result = ['actual paired Darwin public host verified '+case+': original encrypted proof boundary, joined native PF and utun retirement']
        if case.endswith('/mtu-rollback'):
            result.append(DARWIN_MTU_RECEIPT)
        return result
    if target != 'linux' or case not in LINUX_CASES:
        raise ValueError('Unknown original REALITY native target or case')
    action = linux_action(case)
    names = ['captured REALITY source and TCP-only lower', 'native lifecycle']
    if not any(case.startswith(mode+'-off-') for mode in MODES):
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
        raise ValueError('REALITY native execution failed, skipped or raced')
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
                raise ValueError('REALITY native run lost its original owner')
            runs[name] += 1
        if success:
            name = success[1]
            if name not in expected or complete or runs[name] != 1 or passed[name]:
                raise ValueError('REALITY native pass was missing, duplicated or borrowed')
            passed[name] += 1
        if witness:
            if complete or runs[root+'/'+case] != 1 or passed[root]:
                raise ValueError('REALITY receipt escaped its original execution')
            observed[witness[1]] += 1
        if line == 'PASS':
            if set(passed) != expected:
                raise ValueError('REALITY native package completed without its exact case')
            complete += 1
    if set(runs) != expected or set(passed) != expected or observed != wanted or complete != 1:
        raise ValueError('REALITY native omitted exact traffic, policy or joined lifecycle receipts')
