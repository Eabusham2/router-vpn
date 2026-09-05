#!/usr/bin/env python3
import runpy
from pathlib import Path

root=Path(__file__).resolve().parents[2]
app=Path(__file__).with_name('App')
p=app.joinpath('IOSRuntimeSelection.swift').read_text()
for marker in [
    'case wireGuard = "wireguard"',
    'case libbox = "libbox"',
    'logical.id == "base-raw"',
    'selectRaw(bundle: ClientBundle, rawProfileID: String)',
    'encoded["sing-box.json"] != nil',
    'maxAssetBytes = 4 * 1024 * 1024',
    'maxProfileBytes = 12 * 1024 * 1024',
    'unsupportedHelperAssets: Set<String>',
    '"xray.json", "outer-xray.json", "sslocal.json", "middle-sing-box.json", "chain.env"',
    '"wg.conf", "wg-socks.conf", "awg.conf", "awg-socks.conf"',
    'usesUnsupportedLoopbackHelper(object)',
    'loopbackHosts: Set<String> = ["127.0.0.1", "::1", "localhost"]',
    'no validated WireGuardKit/self-contained Libbox variant is present',
    'remain unavailable instead of faking Connected',
]:
    assert marker in p, marker
assert 'Data(base64Encoded:' in p
assert 'value.contains("..")' in p
assert p.index('unsupportedHelperAssets.first') < p.index('return IOSRuntimeSelection(engine: .libbox')
assert p.index('usesUnsupportedLoopbackHelper(object)') < p.index('return IOSRuntimeSelection(engine: .libbox')

# Keep the source contract tied to the real generated profiles that motivated
# the iOS fail-closed boundary. Desktop Xray/sslocal wrappers must not become
# iOS-runnable merely because they also ship a sing-box TUN wrapper.
xray=(root/'server/scripts/generate-xray-pq.sh').read_text()
stack=(root/'server/scripts/generate-stack-profiles.py').read_text()
tls=(root/'server/scripts/generate-tls-alternates.sh').read_text()
for marker in ['"server":"127.0.0.1"', '"server_port":socks_port']:
    assert marker in xray, marker
for marker in ['"server": "127.0.0.1"', '"server_port": 1090']:
    assert marker in stack, marker
for marker in ['"server":"127.0.0.1"', '"server_port":1092']:
    assert marker in tls, marker

models=app.joinpath('Models.swift').read_text()
for marker in [
    'profileSchemaVersion: 4', 'profileSchemaVersion <= 4',
    'autoRequireEncrypted', 'auto_require_encrypted',
    'autoRequireObfuscation', 'auto_require_obfuscation',
]:
    assert marker in models, marker

strategy=app.joinpath('IOSStrategySupport.swift').read_text()
for marker in [
    'runIOSSmartAuto()', 'runIOSCustom(layers requestedRaw: [String])',
    'SMART AUTO is unavailable while iOS Always/strict route lockdown is enabled',
    'selected-node proof passed', 'IOSRuntimeSelector.selectRaw',
    'customLayers = requested', 'applyIOSStartupPolicyIfNeeded()',
    'router-vpn.ios.last-runtime-v1', 'autoRequirementFailure',
    'encryptedLayers', 'obfuscationLayers', 'skipping simplification',
]:
    assert marker in strategy, marker

model=app.joinpath('RouterVPNModel.swift').read_text()
for marker in [
    'IOSStrategyCatalog.autoRequirementFailure',
    'AUTO failed closed: no iOS-runnable candidate satisfies the saved requirements',
]:
    assert marker in model, marker

product=app.joinpath('ProductRootView.swift').read_text()
unified=app.joinpath('IOSUnifiedProductView.swift').read_text()
for marker in ['IOSUnifiedProductView()', 'map-first', 'SMART AUTO default', 'CUSTOM preset builder']:
    assert marker in product, marker
for marker in [
    'AUTO / SMART', 'runUnifiedIOSAuto()', 'runUnifiedIOSSmartAuto()',
    'runIOSCustom(layers:', 'applyIOSStartupPolicyIfNeeded()', 'recordIOSLastRuntime()',
    'IOSUnifiedMap', 'Connect', 'Disconnect', 'Kill switch', 'Multihop', 'Settings', 'Mode', 'DNS',
    'New CUSTOM preset', 'systemBlue', 'systemOrange', 'systemPink', 'real coordinates',
    'IOSHomeSummaryView', 'Require encrypted', 'Require obfuscation',
    'static func dismantleUIView(_ uiView: MKMapView, coordinator: Coordinator)',
    'coordinator.stopPacketAnimation()', 'func stopPacketAnimation()', 'timer = nil', 'map = nil',
    'Button { Task { await selectFastest() } }', 'Test & select fastest',
    'Button { selectSpecific(profile) } label:', 'private func selectSpecific',
    'private func selectFastest() async', 'Press Connect when ready.',
    'VPN state changed while Fastest was measuring; the result was not selected.',
]:
    assert marker in unified, marker
for forbidden in [
    'Button { Task { await connectFastest() } }', 'Test & connect fastest',
    'Button { connectSpecific(profile) } label:', 'private func connectSpecific',
    'private func connectFastest() async',
]:
    assert forbidden not in unified, forbidden
selection=unified.split('private func selectSpecific', 1)[1].split('private func connectOrDisconnect', 1)[0]
assert 'connectOrDisconnect()' not in selection, 'iOS node selection must never implicitly connect'
assert 'deinit { timer?.invalidate() }' not in unified, 'Swift 6 nonisolated deinit must not touch non-Sendable Timer'
runpy.run_path(str(Path(__file__).with_name('test_connection_profiles_contract.py')), run_name='__main__')
print('iOS runtime + helper-chain fail-closed + selection/Connect separation + unified AUTO/SMART/CUSTOM strategy contract OK')
