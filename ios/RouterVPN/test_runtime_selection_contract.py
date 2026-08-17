#!/usr/bin/env python3
from pathlib import Path
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
    'object is [String: Any]',
    'Xray-only, AmneziaWG-only, ALL/MAX and full multihop combinations remain unavailable',
]:
    assert marker in p, marker
assert 'Data(base64Encoded:' in p
assert 'value.contains("..")' in p

strategy=app.joinpath('IOSStrategySupport.swift').read_text()
for marker in [
    'runIOSSmartAuto()', 'runIOSCustom(layers requestedRaw: [String])',
    'SMART AUTO is unavailable while iOS Always/strict route lockdown is enabled',
    'selected-node proof passed', 'IOSRuntimeSelector.selectRaw',
    'customLayers = requested', 'applyIOSStartupPolicyIfNeeded()',
    'router-vpn.ios.last-runtime-v1', 'IOSStrategySheet',
]:
    assert marker in strategy, marker
root=app.joinpath('ProductRootView.swift').read_text()
for marker in ['AUTO / SMART / CUSTOM', 'IOSStrategySheet()', 'applyIOSStartupPolicyIfNeeded()', 'recordIOSLastRuntime()']:
    assert marker in root, marker
print('iOS runtime + AUTO/SMART/CUSTOM strategy contract OK')
