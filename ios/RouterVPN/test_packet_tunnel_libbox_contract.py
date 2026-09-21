#!/usr/bin/env python3
from pathlib import Path
import re
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
        for call in calls:
            assert 0 <= body.find(call) < arm, name + ': guard activation must follow routed identity proof'
        owner = 'guard self.wireGuardAdapter === adapter else' if name == 'startWireGuard' else 'guard self.libboxEngine === engine else'
        assert body.rfind(owner, 0, arm) >= 0, name + ': success must retain the exact runtime owner'
        if name == 'startMultihop':
            assert body.index(calls[0]) < body.index(calls[1]) < arm, 'both hop identities must be proved in order'
            assert body.index('if let entryError') < body.index(calls[1]), 'failed entry proof must stop before exit proof'
            assert body.index('if let exitError') < arm, 'failed exit proof must stop before connection completion'

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

assert 'adapter.stop { [weak self] _ in self?.wireGuardAdapter = nil' not in provider, 'old async stop callback can clobber a newer WireGuard owner'
assert 'defer { self.proofTask = nil; self.proofSession?.finishTasksAndInvalidate(); self.proofSession = nil }' not in provider, 'old proof callback can clobber a newer proof session'
for marker in ['"routervpn-proof"','"type": "mixed"','"listen": "127.0.0.1"','proofProxyPort = 1099','LibboxNewCommandServer','LibboxSetMemoryLimit(true)']:
    assert marker in engine, marker
for marker in ['LibboxPlatformInterfaceProtocol','LibboxCommandServerHandlerProtocol','options.getAutoRoute()','options.getDNSServerAddress()','NEIPv4Route.default()','NEIPv6Route.default()','LibboxGetTunnelFileDescriptor()','NWPathMonitor()','includeAllNetworksRequested']:
    assert marker in platform, marker
assert 'fake Connected' not in provider
print('iOS PacketTunnel Libbox + async ownership/network-change/wake proof contract OK')
