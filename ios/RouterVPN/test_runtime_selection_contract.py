#!/usr/bin/env python3
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

strategy=app.joinpath('IOSStrategySupport.swift').read_text()
for marker in [
    'runIOSSmartAuto()', 'runIOSCustom(layers requestedRaw: [String])',
    'SMART AUTO is unavailable while iOS Always/strict route lockdown is enabled',
    'selected-node proof passed', 'IOSRuntimeSelector.selectRaw',
    'customLayers = requested', 'applyIOSStartupPolicyIfNeeded()',
    'router-vpn.ios.last-runtime-v1', 'IOSStrategySheet',
]:
    assert marker in strategy, marker
product=app.joinpath('ProductRootView.swift').read_text()
for marker in ['AUTO / SMART / CUSTOM', 'IOSStrategySheet()', 'applyIOSStartupPolicyIfNeeded()', 'recordIOSLastRuntime()']:
    assert marker in product, marker
print('iOS runtime + helper-chain fail-closed + AUTO/SMART/CUSTOM strategy contract OK')
