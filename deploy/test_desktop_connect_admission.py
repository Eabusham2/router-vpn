#!/usr/bin/env python3
"""Require the real public CONNECT source transaction before installed acceptance."""
import hashlib
import re

PROTOCOLS = ('http-connect', 'https-connect')
CAPABILITY_FAULTS = ('original', 'anonymous', 'hostname', 'wrong-endpoint', 'layer',
    'paired-token', 'paired-proof', 'paired-api', 'missing-source', 'opposite-source',
    'partial-auth', 'oversized-auth', 'bad-port', 'bad-sni', 'socks5')
REQUEST_FAULTS = ('stale-middle', 'stale-final', 'partial-capture', 'cancelled', 'server',
    'auto', 'layer', 'hostname', 'first', 'final', 'wrong-protocol')
ROOTS = {
    'TestDesktopCONNECTPublicAdmissionRequiresOriginalHost': (),
    'TestDesktopCONNECTPublicCapabilityRetainsExactProtocolAndSecrets': tuple(
        name for protocol in PROTOCOLS for name in (protocol, *(protocol+'/'+fault for fault in CAPABILITY_FAULTS))),
    'TestDesktopCONNECTPublicHandlerReachesOriginalTypedCapture': tuple(
        name for mode in ('wg', 'awg2-fast', 'awg2-strong') for name in (mode, *(mode+'/'+protocol for protocol in PROTOCOLS))),
    'TestDesktopCONNECTRegisteredRouteRefusesChangedSourceAndGraph': tuple(
        name for protocol in PROTOCOLS for name in (protocol, *(protocol+'/'+fault for fault in REQUEST_FAULTS))),
    'TestDesktopCONNECTCandidateProfileLoadReachesPublicCapture': PROTOCOLS,
}
REQUIRED = tuple(name for root, leaves in ROOTS.items() for name in (root, *(root+'/'+leaf for leaf in leaves)))


def require_verdicts(output):
    if any(value in output for value in ('--- FAIL:', '--- SKIP:', 'WARNING: DATA RACE', 'panic:', 'fatal error:')):
        raise ValueError('Public CONNECT source controls failed, skipped or raced')
    runs = re.findall(r'^\s*=== RUN\s+(\S+)\s*$', output, re.M)
    passes = re.findall(r'^\s*--- PASS:\s+(\S+)\s+\([0-9.]+s\)$', output, re.M)
    if sorted(runs) != sorted(REQUIRED) or sorted(passes) != sorted(REQUIRED) or len(re.findall(r'^PASS\s*$', output, re.M)) != 1:
        raise ValueError('Public CONNECT omitted or duplicated an exact source/control verdict')


def execute(binary, target, run, root, captured):
    if target not in ('linux', 'windows', 'darwin'):
        raise ValueError('Public CONNECT source gate requires its admitted Windows/Linux/Darwin target')
    command = [str(binary), '-test.v', '-test.count=1', '-test.timeout=90s',
               '-test.run=^('+'|'.join(ROOTS)+')$']
    status, output = run(command, cwd=root, env=captured, timeout=100)
    if status:
        raise ValueError('Public CONNECT source transaction failed:\n'+output[-16384:])
    require_verdicts(output)
    print(output, end='' if output.endswith('\n') else '\n', flush=True)
    return {'scope': 'registered-public-connect-source-controls', 'native_kernel_acceptance': False,
            'target': target, 'cases': list(REQUIRED), 'output_sha256': hashlib.sha256(output.encode()).hexdigest()}
