#!/usr/bin/env python3
from pathlib import Path
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
assert provider.count('self.armNetworkProofGuard()') == 3, 'every proven iOS engine must arm network-change proof invalidation'
assert 'adapter.stop { [weak self] _ in self?.wireGuardAdapter = nil' not in provider, 'old async stop callback can clobber a newer WireGuard owner'
assert 'defer { self.proofTask = nil; self.proofSession?.finishTasksAndInvalidate(); self.proofSession = nil }' not in provider, 'old proof callback can clobber a newer proof session'
for marker in ['"routervpn-proof"','"type": "mixed"','"listen": "127.0.0.1"','proofProxyPort = 1099','LibboxNewCommandServer','LibboxSetMemoryLimit(true)']:
    assert marker in engine, marker
for marker in ['LibboxPlatformInterfaceProtocol','LibboxCommandServerHandlerProtocol','options.getAutoRoute()','options.getDNSServerAddress()','NEIPv4Route.default()','NEIPv6Route.default()','LibboxGetTunnelFileDescriptor()','NWPathMonitor()','includeAllNetworksRequested']:
    assert marker in platform, marker
assert 'fake Connected' not in provider
print('iOS PacketTunnel Libbox + async ownership/network-change/wake proof contract OK')
