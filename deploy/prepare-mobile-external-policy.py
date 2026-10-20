#!/usr/bin/env python3
"""Bind external DNS/entry/exit proofs to the exact pinned native Box."""
from pathlib import Path
import argparse
import hashlib
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'

def inputs():
    return [Path(__file__).resolve(), ROOT/'deploy/test_mobile_external_pinned.sh'] + sorted((ROOT/'mobile/externalpolicy').glob('*.tmpl'))

def digest():
    value=hashlib.sha256()
    for source in inputs():
        value.update(str(source.relative_to(ROOT)).encode()+b'\0'+source.read_bytes())
    return value.hexdigest()

def prepare(vendor):
    vendor=vendor.resolve()
    if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=PIN:
        raise ValueError('external proof requires the exact pinned native core')
    path=vendor/'box.go'
    if path.is_symlink():raise ValueError('linked native external policy boundary')
    source=path.read_text()
    for before,after in (
        ('type Box struct {\n','type Box struct {\n\trouterVPNExternalOptions string\n'),
        ('func New(options Options) (*Box, error) {\n','func New(options Options) (*Box, error) {\n\texternalOptionsDigest := routerVPNExternalOptionsDigest(options.Context, options.Options)\n'),
        ('\treturn &Box{\n','\treturn &Box{\n\t\trouterVPNExternalOptions: externalOptionsDigest,\n'),
    ):
        if after in source:continue
        if source.count(before)!=1:raise ValueError('native external configuration capture boundary changed')
        source=source.replace(before,after,1)
    path.write_text(source)
    for name in ('box.go','box_test.go'):
        template=ROOT/'mobile/externalpolicy'/(name+'.tmpl')
        (vendor/('routervpn_external_policy'+('_test' if name.endswith('_test.go') else '')+'.go')).write_bytes(template.read_bytes())
    (vendor/'experimental/libbox/routervpn_external_policy_bridge_test.go').write_bytes((ROOT/'mobile/externalpolicy/bridge_test.go.tmpl').read_bytes())

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor',type=Path,nargs='?')
    parser.add_argument('--digest',action='store_true')
    args=parser.parse_args()
    if args.digest:print(digest())
    elif args.vendor:prepare(args.vendor)
    else:parser.error('vendor or --digest required')
