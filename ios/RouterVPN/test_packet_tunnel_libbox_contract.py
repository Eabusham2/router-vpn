#!/usr/bin/env python3
from pathlib import Path
import re
import subprocess
import sys
root=Path(__file__).resolve().parent
provider=(root/'PacketTunnel/PacketTunnelProvider.swift').read_text()
engine=(root/'PacketTunnel/RouterVPNLibboxEngine.swift').read_text()
platform=(root/'PacketTunnel/RouterVPNLibboxPlatform.swift').read_text()
for marker in [
    'case "wireguard"','case "libbox"','rawProfileID',
    'layeredProfile(root, rawProfileID: rawProfileID)',
    'RouterVPNLibboxEngine(tunnel: self)',
    'proxyPort: RouterVPNLibboxEngine.proofProxyPort',
    'expectedNodeID.range(of: "^[0-9a-f]{64}$"',
    'if self.libboxEngine === engine { self.libboxEngine = nil }',
    'guard self.libboxEngine === engine else',
    'guard self.wireGuardAdapter === adapter else',
    'kCFNetworkProxiesHTTPProxy','NetworkProofGuard',
    'owner?.invalidateSelectedPathProof(self)',
    'invalidateSelectedPathProof(_ guardState: NetworkProofGuard)',
    'guard pathProofGuard === guardState else',
    'installProof(session: session, task: task)',
    'if proofSession === session',
    'cancelActiveProof()',
    'clearPathProofGuard()',
    'currentPathProofGuard()',
    'override func wake()',
    'if let guardState = currentPathProofGuard() { invalidateSelectedPathProof(guardState) }',
    'Sleep is a path-proof lifetime boundary',
    'every reconnect must',
    'Underlying network changed; selected-node/public-exit proof was invalidated',
    'cancelTunnelWithError',
]:
    assert marker in provider, marker

def verify_proof_lifecycle(source):
    # Check the shipping dispatch and each individual success path. A global
    # count can miss a missing guard in one runtime plus a duplicate elsewhere.
    proof_calls = {
        'startWireGuard': ['self.proveSelectedNode('],
        'startMultihop': ['proveSelectedNode(url: entryURL', 'self.proveSelectedNode(url: exitURL'],
        'startLibbox': ['proveSelectedNode('],
        'startExternalLibbox': ['proveExternalExit('],
    }
    dispatch = set(re.findall(r'case "[^"\n]+": try (start\w+)\(', source))
    assert dispatch == set(proof_calls), 'every dispatched runtime must have an explicit proof-lifecycle contract'
    for name, calls in proof_calls.items():
        body = source.split('    private func ' + name + '(', 1)[1].split('\n    private func ', 1)[0]
        arm = body.find('self.armNetworkProofGuard()')
        success = body.find('completionHandler(nil)')
        assert arm >= 0 and success > arm, name + ': success must follow network-proof guard activation'
        assert body.count('self.armNetworkProofGuard()') == 1, name + ': network proof must be armed once'
        owner = 'guard self.wireGuardAdapter === adapter else' if name == 'startWireGuard' else 'guard self.libboxEngine === engine else'
        if name == 'startMultihop':
            # This longer path arms BEFORE comparison. The SAME captured guard
            # must remain current after comparison and each node proof; a second
            # arm would incorrectly clear a network-change invalidation.
            assert 'let comparisonGuard = self.armNetworkProofGuard()' in body
            compare = body.index('engine.completeMultihopExecution')
            assert arm < compare < body.index(calls[0]) < body.index(calls[1]) < success
            assert body.index('if let comparisonError') < body.index(calls[0])
            assert body.index('if let entryError') < body.index(calls[1])
            assert body.index('if let exitError') < success
            guard = 'guard self.currentPathProofGuard() === comparisonGuard else'
            phases = (body[compare:body.index(calls[0])],
                      body[body.index(calls[0]):body.index(calls[1])],
                      body[body.index(calls[1]):success])
            for phase in phases:
                assert guard in phase, 'multihop must retain its network generation through every asynchronous phase'
                assert 'self.libboxEngine === engine else' in phase, 'multihop must retain the exact runtime through every asynchronous phase'
        else:
            for call in calls:
                assert 0 <= body.find(call) < arm, name + ': guard activation must follow routed identity proof'
            assert body.rfind(owner, 0, arm) >= 0, name + ': success must retain the exact runtime owner'

verify_proof_lifecycle(provider)
for runtime in ('startWireGuard', 'startMultihop', 'startLibbox', 'startExternalLibbox'):
    prefix = provider.index('    private func ' + runtime + '(')
    guard_at = provider.index('self.armNetworkProofGuard()', prefix)
    # Negative control: deleting ANY one runtime's guard must fail this test.
    broken = provider[:guard_at] + provider[guard_at:].replace('self.armNetworkProofGuard()', '', 1)
    try:
        verify_proof_lifecycle(broken)
    except AssertionError:
        pass
    else:
        raise AssertionError('lifecycle contract accepted an unguarded ' + runtime)

# Each generation checkpoint is independently required, not a marker count.
checkpoint = 'guard self.currentPathProofGuard() === comparisonGuard else'
start = provider.index('    private func startMultihop(')
end = provider.index('    private func multihopWireGuardEndpoint(', start)
for match in re.finditer(re.escape(checkpoint), provider[start:end]):
    at = start + match.start()
    broken = provider[:at] + provider[at:].replace(checkpoint, 'guard true else', 1)
    try:
        verify_proof_lifecycle(broken)
    except AssertionError:
        pass
    else:
        raise AssertionError('lifecycle contract accepted a stale multihop generation')

assert 'adapter.stop { [weak self] _ in self?.wireGuardAdapter = nil' not in provider, 'old async stop callback can clobber a newer WireGuard owner'
assert 'defer { self.proofTask = nil; self.proofSession?.finishTasksAndInvalidate(); self.proofSession = nil }' not in provider, 'old proof callback can clobber a newer proof session'
for marker in ['"routervpn-proof"','"type": "mixed"','"listen": "127.0.0.1"','proofProxyPort = 1099','LibboxNewCommandServer','setup.oomKillerEnabled = true']:
    assert marker in engine, marker
for marker in ['LibboxPlatformInterfaceProtocol','LibboxCommandServerHandlerProtocol','options.getAutoRoute()','options.getDNSServerAddress()','NEIPv4Route.default()','NEIPv6Route.default()','LibboxGetTunnelFileDescriptor()','NWPathMonitor()','includeAllNetworksRequested']:
    assert marker in platform, marker
subprocess.run([sys.executable, str(root.parents[1] / 'deploy/test_ios_multihop_host_environment.py')], check=True, timeout=45)
assert 'fake Connected' not in provider
print('iOS PacketTunnel Libbox + async ownership/network-change/wake proof contract OK')
