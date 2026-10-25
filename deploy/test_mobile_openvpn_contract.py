#!/usr/bin/env python3
"""Shipping-chain guard; behavioral parsing lives in mobile/*_test.go."""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
def need(path, *markers):
    text = (ROOT/path).read_text()
    for marker in markers:
        assert marker in text, f"{path}: missing shipping OpenVPN connection {marker!r}"
    return text


def swift_member(source, signature):
    start = source.index(signature)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        if source[end] == '{': depth += 1
        if source[end] == '}': depth -= 1
        end += 1
    return source[start:end]


def external_preparation_contract(source):
    body = swift_member(source, 'func connectSelectedExternal(startupAdmission:')
    launch = body.index('try manager.connection.startVPNTunnel(options: options)')
    preparation = body[:launch]
    revalidate = 'try requireExternalPreparation(generation, source: bundle, entry: capturedEntry, manager: manager)'
    awaits = list(re.finditer(r'try await (NETunnelProviderManager|manager)\.(loadAllFromPreferences|saveToPreferences|loadFromPreferences)\(\)', preparation))
    assert awaits and awaits[0].group(2) == 'loadAllFromPreferences', 'external startup must first capture its owned manager'
    initial = preparation[awaits[0].end():preparation.index('let proto = NETunnelProviderProtocol()')]
    ordered = ['guard iosConnectGeneration == generation, !iosUserDisconnectInProgress, !Task.isCancelled',
               'guard managers.count <= 1', 'let manager = managers.first ?? NETunnelProviderManager()', revalidate]
    positions = [initial.index(item) for item in ordered]
    assert positions == sorted(positions), 'manager selection must retain generation and source ownership before configuration'
    assert {'saveToPreferences', 'loadFromPreferences'}.issubset({item.group(2) for item in awaits}), 'external preferences must be saved and read back'
    for awaited in awaits[1:]:
        assert preparation[awaited.end():].lstrip().startswith(revalidate), f'{awaited.group(2)} must immediately revalidate the captured source after its await'
    startup = swift_member(preparation, 'if startupAdmission != nil')
    assert startup.index('let available = try await NETunnelProviderManager.loadAllFromPreferences()') < startup.index(revalidate) < startup.index('guard available.allSatisfy'), 'startup manager refresh must revalidate ownership before checking other VPNs'
    assert '$0.connection.status == .disconnected || $0.connection.status == .invalid' in startup
    saved = preparation[preparation.index('guard let saved ='):]
    for marker in ['saved.providerConfiguration?["bundle"] as? Data == encodedBundle',
                   'saved.providerConfiguration?[entryBundleKey] as? Data == capturedEntry',
                   'saved.includeAllNetworks == strict, saved.enforceRoutes == strict',
                   'manager.isEnabled, manager.isOnDemandEnabled == strict']:
        assert marker in saved, 'the native launch must retain exact preference and protection readback'
    owner = swift_member(source, 'private func requireExternalPreparation(')
    for marker in ['try Task.checkCancellation()', 'iosConnectGeneration == generation, !iosUserDisconnectInProgress',
                   'current.selectedRouterID == source.selectedRouterID',
                   'current.routerProfiles == source.routerProfiles, current.profiles == source.profiles',
                   'guard try externalTorEntryData(source: source) == entry',
                   'manager.connection.status == .disconnected || manager.connection.status == .invalid']:
        assert marker in owner, 'external preparation lost captured ownership: ' + marker


def check_preparation_controls(source):
    external_preparation_contract(source)
    guard = 'try requireExternalPreparation(generation, source: bundle, entry: capturedEntry, manager: manager)'
    mutants = []
    for call in ['try await manager.saveToPreferences()', 'try await manager.loadFromPreferences()',
                 'let available = try await NETunnelProviderManager.loadAllFromPreferences()']:
        expression = re.compile(re.escape(call) + r'(\s*)' + re.escape(guard))
        assert len(expression.findall(source)) == 1, 'preference mutation anchor drifted: ' + call
        mutants.append(expression.sub(lambda match: call + match.group(1), source, count=1))
        mutants.append(expression.sub(lambda match: guard + match.group(1) + call, source, count=1))
    for original, replacement in [('try Task.checkCancellation()', '/* cancellation check removed */'),
                     ('iosConnectGeneration == generation, !iosUserDisconnectInProgress', 'true'),
                     ('current.selectedRouterID == source.selectedRouterID', 'true'),
                     ('current.routerProfiles == source.routerProfiles, current.profiles == source.profiles', 'true'),
                     ('guard try externalTorEntryData(source: source) == entry', 'guard true')]:
        owner = swift_member(source, 'private func requireExternalPreparation(')
        assert owner.count(original) == 1, original
        mutants.append(source.replace(owner, owner.replace(original, replacement, 1), 1))
    for original, replacement in [
        ('let manager = managers.first ?? NETunnelProviderManager()\n            ' + guard, 'let manager = managers.first ?? NETunnelProviderManager()'),
        ('guard managers.count <= 1', 'guard true'),
        ('saved.providerConfiguration?["bundle"] as? Data == encodedBundle', 'true'),
        ('guard available.allSatisfy', 'guard available.contains'),
    ]:
        assert source.count(original) == 1, original
        mutants.append(source.replace(original, replacement, 1))
    for mutant in mutants:
        try:
            external_preparation_contract(mutant)
        except (AssertionError, ValueError):
            continue
        raise AssertionError('external preparation gate accepted a missing or reordered ownership guard')
    print(f'Apple external preference ownership/order gate: PASS ({len(mutants)} defect mutations rejected)')

need('mobile/routervpn_openvpn.go', 'func RouterOpenVPNEndpoint(', 'return nativeopenvpn.CompileEndpoint(config, username, password, tag, detour)')
need('internal/nativeopenvpn/profile.go', 'func CompileEndpoint(', '"openvpn-client"', '"system": false', '"remote_certificate_tls": "server"', 'netip.ParseAddr', 'file references are never read')
for path in ('ios/RouterVPN/prepare-libbox.sh', 'android/build-sing-box-libbox.sh'):
    need(path, 'VERSION=1.14.1', 'COMMIT=1ac1a339cb1223e9c70eae14c44411c75033c02d', 'routervpn_openvpn.go', 'prepare-mobile-openvpn.py', "grep -Fq 'with_openvpn'")
need('ios/RouterVPN/prepare-libbox.sh', 'BRIDGE_SHA', 'BRIDGE_STAMP', 'LibboxRouterOpenVPNEndpoint')
need('android/build-sing-box-libbox.sh', 'OPENVPN_SHA', 'OPENVPN_STAMP', 'routerOpenVPNEndpoint', 'exactly one gomobile go.Seq runtime class', 'test_mobile_openvpn_pinned.sh')
need('ios/RouterVPN/project.yml', 'test_mobile_openvpn_pinned.sh', '- framework: .deps/Libbox.xcframework')
need('deploy/test_mobile_openvpn_pinned.sh', 'go test -count=1', 'with_openvpn', 'TestRouterOpenVPNNative', 'SDKROOT=', 'trap')
need('mobile/routervpn_openvpn_native_test.go.tmpl', 'TestRouterOpenVPNNativeConfig', 'TestRouterOpenVPNNativeLoopback', 'CheckConfig', 'instance.Start()', 'openvpn-server', 'client.Close()', 'if test.accept && !proved', 'untrusted-CA-rejected', 'wrong-peer-name-rejected', 'malformed-CA-rejected', 'requests.Load() != before', '"override_address": "127.0.0.1"', 'map[string]any{"action": "reject"}')
for path in ('ios/RouterVPN/App/IOSExternalNodeBuilderView.swift', 'ios/RouterVPN/PacketTunnel/RouterVPNExternalExit.swift'):
    need(path, 'LibboxRouterOpenVPNEndpoint', 'openvpn-client', '"system"] as? Bool == false')
need('ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift', 'startExternalLibbox', 'proveExternalExit', 'expectedPublicIP: runtime.expectedPublicIP')
model=need('ios/RouterVPN/App/RouterVPNModelExternal.swift', '.loadAllFromPreferences().filter', 'managers.count <= 1', 'private func requireExternalPreparation(', 'current.selectedRouterID == source.selectedRouterID', 'current.routerProfiles == source.routerProfiles, current.profiles == source.profiles', 'guard try externalTorEntryData(source: source) == entry', 'saved.providerConfiguration?["bundle"] as? Data == encodedBundle', 'exact public-exit proof')
check_preparation_controls(model)
need('android/app/src/main/java/com/eabusham/routervpn/AndroidOpenVPN.java', 'Libbox.routerOpenVPNEndpoint', 'Libbox.version()', '!detour.equals', 'result.optBoolean("system", true)')
store=need('android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java', 'AndroidOpenVPN.endpoint(e, "")', '.put("openvpn_config",e.openVPNConfig)', 'AndroidPrivateFileStore.write')
summary=store.split('JSONObject summary()',1)[1].split('private final Context',1)[0]
assert 'openVPNConfig' not in summary and '.put("password"' not in summary, 'raw credentials leaked in external summary'
need('android/app/src/main/java/com/eabusham/routervpn/AndroidDirectStandardExitController.java', 'AndroidOpenVPN.endpoint(e, "")', 'AndroidExternalPolicy.prepare(context, null, exit, "external")')
need('android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitController.java', 'AndroidExternalPolicy.prepare(context, entryBundle, exit, entryMode)')
need('android/app/src/main/java/com/eabusham/routervpn/AndroidExternalPolicy.java',
     'ext.put("openvpn", new JSONObject().put("config", exit.openVPNConfig)',
     '.put("username", exit.username).put("password", exit.password)',
     'AndroidDirectStandardExitController.customExitJson(exit)',
     '"openvpn".equals(exit.protocol)) endpoints.put(transport)',
     'Libbox.routerCompileExternalPolicy(source, capture)',
     'AndroidExternalEntry.prepare(context,entryFile,entry,entryMode)',
     '"predecessor_config",captured.config', 'Libbox.checkConfig(compiled.config)')
need('android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitRuntime.java',
     'capturedExternalExit(capturedHome)',
     'LayeredVpnService.externalExitIP(externalNativeSession,externalID)',
     'stopEmbeddedAndProve()')
need('internal/mobilemultihop/external_openvpn.go',
     'nativeopenvpn.CompileEndpoint(config, credentials[0], credentials[1]',
     'reflect.DeepEqual(endpoint, expected)', 'externalOpenVPNRequiresUDP',
     'externalOpenVPNMTU')
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
subprocess.run([sys.executable, str(ROOT/'deploy/test_mobile_openvpn_close_policy.py')], cwd=ROOT, check=True, timeout=180)
subprocess.run(['go','test','-count=1','./mobile'],cwd=ROOT,check=True,timeout=45)
subprocess.run(['python3',str(ROOT/'deploy/test_mobile_openvpn_source.py')],cwd=ROOT,check=True,timeout=90)
print('Mobile OpenVPN shipping, private-store, owned-graph and parser contracts: PASS')
