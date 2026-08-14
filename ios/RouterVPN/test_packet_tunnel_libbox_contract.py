#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parent
provider=(root/'PacketTunnel/PacketTunnelProvider.swift').read_text()
engine=(root/'PacketTunnel/RouterVPNLibboxEngine.swift').read_text()
platform=(root/'PacketTunnel/RouterVPNLibboxPlatform.swift').read_text()
for marker in ['case "wireguard"','case "libbox"','rawProfileID','layeredProfile(root, rawProfileID: rawProfileID)','RouterVPNLibboxEngine(tunnel: self)','proxyPort: RouterVPNLibboxEngine.proofProxyPort','expectedNodeID.range(of: "^[0-9a-f]{64}$"','engine.stop(); self.libboxEngine = nil','kCFNetworkProxiesHTTPProxy']:
    assert marker in provider, marker
for marker in ['"routervpn-proof"','"type": "mixed"','"listen": "127.0.0.1"','proofProxyPort = 1099','LibboxNewCommandServer','LibboxSetMemoryLimit(true)']:
    assert marker in engine, marker
for marker in ['LibboxPlatformInterfaceProtocol','LibboxCommandServerHandlerProtocol','options.getAutoRoute()','options.getDNSServerAddress()','NEIPv4Route.default()','NEIPv6Route.default()','LibboxGetTunnelFileDescriptor()','NWPathMonitor()','includeAllNetworksRequested']:
    assert marker in platform, marker
assert 'fake Connected' not in provider
print('iOS PacketTunnel Libbox runtime contract OK')
