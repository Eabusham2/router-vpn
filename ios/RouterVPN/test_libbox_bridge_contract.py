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
 'LibboxSetup(setup, &setupError)', 'setup.oomKillerEnabled = true',
 'LibboxNewCommandServer(platform, platform, &createError)', 'server.startOrReloadService',
 'files["sing-box.json"]', '.posixPermissions: 0o700', '.posixPermissions: 0o600',
 'data.count <= 4 * 1024 * 1024', 'total <= 12 * 1024 * 1024',
]: assert marker in engine, marker
assert 'WebKit' not in platform+engine
# Compile the complete shipping engine, including the asynchronous bridge, with
# non-Sendable generated-handle doubles before the expensive native build.
# The subsequent Xcode job still checks the actual pinned Objective-C framework.
import platform
import subprocess
import sys
if platform.system() == 'Darwin':
    subprocess.run([sys.executable, str(root.parents[1] / 'deploy/test_ios_libbox_delivery.py')], check=True, timeout=180)
print('Router VPN iOS Libbox bridge source contract OK')
