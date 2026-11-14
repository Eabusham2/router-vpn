#!/usr/bin/env python3
"""Mandatory compiled retained-parent controls; these are not native kernel acceptance."""
import hashlib
import re

COMMON = {
    'TestDesktopSOCKSOwnedParentRetainsStartProofAndJoinedRetirement': ('wg', 'awg2-fast', 'awg2-strong'),
    'TestDesktopSOCKSProtectionRejectsForeignAndMixedOwners': ('foreign-policy', 'ordinary-policy', 'foreign-source', 'foreign-attempt', 'foreign-launch', 'wrong-command'),
    'TestDesktopSOCKSPhysicalPolicyKeepsConcreteFamily': ('linux', 'windows', 'darwin'),
}
LINUX = {
    'TestDesktopLinuxSOCKSParentKeepsExactPolicyAndPrivateInputs': (),
    'TestDesktopLinuxSOCKSParentRejectsMixedOrForeignPolicy': ('foreign-policy', 'foreign-source', 'ordinary-policy', 'foreign-ready', 'foreign-input', 'foreign-selection'),
    'TestDesktopLinuxSOCKSActivationPinsOriginalConcreteOwner': ('original', 'host-policy', 'transaction-policy', 'active-policy', 'mixed-policy', 'joined', 'ended'),
    'TestDesktopLinuxSOCKSPhysicalRetainsClosedFamily': (),
}


def inventory(target):
    if target not in ('linux', 'windows'):
        raise ValueError('Parent controls require their captured Windows/Linux target')
    roots = dict(COMMON)
    if target == 'linux':
        roots.update(LINUX)
    return roots, tuple(name for root, leaves in roots.items() for name in (root, *(root + '/' + leaf for leaf in leaves)))


def require_verdicts(output, target):
    _, required = inventory(target)
    if any(value in output for value in ('--- FAIL:', '--- SKIP:', 'WARNING: DATA RACE', 'panic:', 'fatal error:')):
        raise ValueError('Retained typed parent controls failed, skipped or raced')
    runs = re.findall(r'^\s*=== RUN\s+(\S+)\s*$', output, re.M)
    passes = re.findall(r'^\s*--- PASS:\s+(\S+)\s+\([0-9.]+s\)$', output, re.M)
    if sorted(runs) != sorted(required) or sorted(passes) != sorted(required) or len(re.findall(r'^PASS\s*$', output, re.M)) != 1:
        raise ValueError('Retained typed parent omitted or duplicated an exact control')


def execute(binary, target, run, root, captured):
    roots, required = inventory(target)
    status, output = run([str(binary), '-test.v', '-test.count=1', '-test.timeout=60s',
                          '-test.run=^(' + '|'.join(roots) + ')$'], cwd=root, env=captured, timeout=70)
    if status:
        raise ValueError('Compiled retained typed parent controls failed:\n' + output[-16384:])
    require_verdicts(output, target)
    print(output, end='' if output.endswith('\n') else '\n', flush=True)
    return {'scope': 'compiled-parent-model-and-source-controls', 'native_kernel_acceptance': False,
            'target': target, 'cases': list(required), 'output_sha256': hashlib.sha256(output.encode()).hexdigest()}
