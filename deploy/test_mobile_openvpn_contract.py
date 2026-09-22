#!/usr/bin/env python3
"""Shipping-chain guard; behavioral parsing lives in mobile/*_test.go."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
def need(path, *markers):
    text = (ROOT/path).read_text()
    for marker in markers:
        assert marker in text, f"{path}: missing shipping OpenVPN connection {marker!r}"
    return text

need('mobile/routervpn_openvpn.go', 'func RouterOpenVPNEndpoint(', '"openvpn-client"', '"system": false', '"remote_certificate_tls": "server"', 'netip.ParseAddr', 'file references are never read')
for path in ('ios/RouterVPN/prepare-libbox.sh', 'android/build-sing-box-libbox.sh'):
    need(path, 'VERSION=1.14.1', 'COMMIT=1ac1a339cb1223e9c70eae14c44411c75033c02d', 'routervpn_openvpn.go', "grep -Fq 'with_openvpn'")
need('ios/RouterVPN/prepare-libbox.sh', 'BRIDGE_SHA', 'BRIDGE_STAMP', 'LibboxRouterOpenVPNEndpoint')
need('android/build-sing-box-libbox.sh', 'OPENVPN_SHA', 'OPENVPN_STAMP', 'routerOpenVPNEndpoint', 'exactly one gomobile go.Seq runtime class', 'test_mobile_openvpn_pinned.sh')
need('ios/RouterVPN/project.yml', 'test_mobile_openvpn_pinned.sh', '- framework: .deps/Libbox.xcframework')
need('deploy/test_mobile_openvpn_pinned.sh', 'go test -count=1', 'with_openvpn', 'TestRouterOpenVPNNative', 'SDKROOT=', 'trap')
need('mobile/routervpn_openvpn_native_test.go.tmpl', 'TestRouterOpenVPNNativeConfig', 'TestRouterOpenVPNNativeLoopback', 'CheckConfig', 'instance.Start()', 'openvpn-server', 'client.Close()', 'if test.accept && !proved', 'untrusted-CA-rejected', 'wrong-peer-name-rejected', 'malformed-CA-rejected', 'requests.Load() != before', '"override_address": "127.0.0.1"', 'map[string]any{"action": "reject"}')
for path in ('ios/RouterVPN/App/IOSExternalNodeBuilderView.swift', 'ios/RouterVPN/PacketTunnel/RouterVPNExternalExit.swift'):
    need(path, 'LibboxRouterOpenVPNEndpoint', 'openvpn-client', '"system"] as? Bool == false')
need('ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift', 'startExternalLibbox', 'proveExternalExit', 'expectedPublicIP: runtime.expectedPublicIP')
model=need('ios/RouterVPN/App/RouterVPNModelExternal.swift', '.loadAllFromPreferences().filter', 'managers.count <= 1', 'self.bundle?.profiles == bundle.profiles', 'exact public-exit proof')
need('android/app/src/main/java/com/eabusham/routervpn/AndroidOpenVPN.java', 'Libbox.routerOpenVPNEndpoint', 'Libbox.version()', '!detour.equals', 'result.optBoolean("system", true)')
store=need('android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java', 'AndroidOpenVPN.endpoint(e, "")', '.put("openvpn_config",e.openVPNConfig)', 'AndroidPrivateFileStore.write')
summary=store.split('JSONObject summary()',1)[1].split('private final Context',1)[0]
assert 'openVPNConfig' not in summary and '.put("password"' not in summary, 'raw credentials leaked in external summary'
need('android/app/src/main/java/com/eabusham/routervpn/AndroidDirectStandardExitController.java', 'AndroidOpenVPN.endpoint(e, "")', '"openvpn".equals(exit.protocol)) endpoints.put(custom)')
need('android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitController.java', 'AndroidOpenVPN.endpoint(e,"entry-wg")', '"openvpn".equals(exit.protocol))endpoints.put(custom)')
need('android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitRuntime.java', 'proveExpectedPublicIp(exit.expectedPublicIp)', 'stopEmbeddedAndProve()')
for path in ('ios/RouterVPN/App/IOSUnifiedSecureTransport.swift','android/app/src/main/java/com/eabusham/routervpn/AndroidUnifiedControlCenterPolicy.java'):
    text=need(path, '"openvpn"', 'Tor bridges')
    assert 'OpenVPN is unavailable' not in text
need('android/app/src/main/java/com/eabusham/routervpn/StandardExitActivity.java', 'showOpenVPNForm()', 'entry.openVPNConfig=config.getText().toString()', 'entry.password=password.getText().toString()', 'exitStore.save(entry)', 'config.setSaveEnabled(false)', 'dialog.setOnDismissListener')
# Match the generated 1.14 binding contract on both platforms. Native CI still
# compiles against the actual headers/AAR; these guards prevent old adapters
# from being restored unnoticed during source composition.
need('ios/RouterVPN/PacketTunnel/RouterVPNLibboxPlatform.swift',
     'let dnsIterator = try options.getDNSServerAddress()',
     'while dnsIterator.hasNext()', 'NEDNSSettings(servers: dnsAddresses)',
     'dnsAddresses.count < 16', 'guard !dnsAddresses.isEmpty',
     'func lookupSFTPServer(_ failure: NSErrorPointer) -> String',
     'func readSystemSSHHostKey(_ failure: NSErrorPointer) -> String',
     'failure?.pointee = error(')
need('android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java',
     'StringIterator dns = options.getDNSServerAddress()', 'while (dns.hasNext())',
     'builder.addDnsServer(address.trim())', 'dnsCount > 16', 'dnsCount == 0')
for path in ('ios/RouterVPN/App/IOSExternalNodeBuilderView.swift',
             'ios/RouterVPN/PacketTunnel/RouterVPNExternalExit.swift'):
    text=need(path, 'guard let data = encoded.data(using: .utf8)')
    assert 'guard let encoded,' not in text, 'OpenVPN binding returns a non-optional String'
subprocess.run(['go','test','-count=1','./mobile'],cwd=ROOT,check=True,timeout=45)
print('Mobile OpenVPN shipping, private-store, owned-graph and parser contracts: PASS')
