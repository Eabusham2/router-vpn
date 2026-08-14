#!/usr/bin/env python3
from pathlib import Path
p=Path(__file__).with_name('App').joinpath('IOSRuntimeSelection.swift').read_text()
for marker in [
    'case wireGuard = "wireguard"',
    'case libbox = "libbox"',
    'logical.id == "base-raw"',
    'encoded["sing-box.json"] != nil',
    'maxAssetBytes = 4 * 1024 * 1024',
    'maxProfileBytes = 12 * 1024 * 1024',
    'object is [String: Any]',
    'Xray-only, AmneziaWG-only, ALL/MAX and multihop combinations remain unavailable',
]:
    assert marker in p, marker
assert 'Data(base64Encoded:' in p
assert 'value.contains("..")' in p
print('iOS runtime selection contract OK')
