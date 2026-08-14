#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parent
platform=(root/'PacketTunnel/RouterVPNLibboxPlatform.swift').read_text()
engine=(root/'PacketTunnel/RouterVPNLibboxEngine.swift').read_text()
for marker in [
 'LibboxPlatformInterfaceProtocol', 'LibboxCommandServerHandlerProtocol',
 'func openTun(_ options: LibboxTunOptionsProtocol?', 'options.getAutoRoute()',
 'NEIPv4Route.default()', 'NEIPv6Route.default()', 'options.getDNSServerAddress()',
 'LibboxGetTunnelFileDescriptor()', 'NWPathMonitor()', 'underNetworkExtension() -> Bool { true }',
 'includeAllNetworksRequested', 'systemCertificates() -> (any LibboxStringIteratorProtocol)? { nil }',
]: assert marker in platform, marker
for marker in [
 'RouterVPNLibboxCompileProbe.verifyPinnedRuntime()', 'LibboxSetupOptions()',
 'LibboxSetup(setup, &setupError)', 'LibboxSetMemoryLimit(true)',
 'LibboxNewCommandServer(platform, platform, &createError)', 'server.startOrReloadService',
 'files["sing-box.json"]', '.posixPermissions: 0o700', '.posixPermissions: 0o600',
 'data.count <= 4 * 1024 * 1024', 'total <= 12 * 1024 * 1024',
]: assert marker in engine, marker
assert 'WebKit' not in platform+engine
print('Router VPN iOS Libbox bridge source contract OK')
