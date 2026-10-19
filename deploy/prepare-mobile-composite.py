#!/usr/bin/env python3
"""Install the fixed, owned TCP/UDP composite in the exact pinned native core."""
from pathlib import Path
import argparse
import hashlib
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'

def inputs():
    return [Path(__file__).resolve(), ROOT/'deploy/test_mobile_composite_pinned.sh', ROOT/'deploy/test_mobile_sip003_pinned.sh', ROOT/'deploy/test_mobile_composite_shipping.py', ROOT/'deploy/testfixtures/composite/main.go'] + sorted((ROOT / 'mobile/composite').glob('*.tmpl'))

def digest():
    value = hashlib.sha256()
    for source in inputs():
        value.update(str(source.relative_to(ROOT)).encode() + b'\0' + source.read_bytes())
    return value.hexdigest()

def insert_once(text, anchor, addition):
    if text.count(anchor) != 1:
        raise ValueError('pinned composite registry boundary changed')
    if addition.strip() in text:
        if text.count(addition) != 1 or anchor + '\n' + addition not in text or [line.strip() for line in text.splitlines()].count(addition.strip()) != 1:
            raise ValueError('existing composite registry differs')
        return text
    return text.replace(anchor, anchor + '\n' + addition, 1)

def prepare(vendor):
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('composite requires the exact pinned native core')
    if not (vendor / 'go.mod').read_text().startswith('module github.com/sagernet/sing-box\n'):
        raise ValueError('unrelated native module')
    target = vendor / 'protocol/routervpncomposite'
    registry = vendor / 'include/registry.go'
    if target.is_symlink() or not target.resolve().is_relative_to(vendor) or registry.is_symlink():
        raise ValueError('linked or escaped native composite destination')
    text = registry.read_text()
    text = insert_once(text, '\t"github.com/sagernet/sing-box/protocol/group"', '\t"github.com/sagernet/sing-box/protocol/routervpncomposite"')
    text = insert_once(text, '\tgroup.RegisterURLTest(registry)', '\troutervpncomposite.RegisterOutbound(registry)')
    sources = sorted((ROOT / 'mobile/composite').glob('*.tmpl'))
    for source in sources:
        output = target/source.stem
        if output.is_symlink() or output.exists() and not output.is_file():
            raise ValueError('unowned composite source destination')
    target.mkdir(parents=True, exist_ok=True)
    for source in sources:
        (target / source.stem).write_bytes(source.read_bytes())
    registry.write_text(text)
    print('Owned composite source:', digest())

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path, nargs='?')
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest: print(digest())
    elif args.vendor: prepare(args.vendor)
    else: parser.error('vendor or --digest required')
