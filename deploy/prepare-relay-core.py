#!/usr/bin/env python3
"""Build the private relay CLI with exactly the mobile AWG transport implementation.

This prepares a disposable, exact-pinned source checkout; it never starts a VPN,
changes routes, or reads user profiles. All application-dependent files enter the
source digest and every import is relocated without substituting another engine.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CORE = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
PACKAGES = ('awgpolicy', 'mobilemultihop', 'applexray', 'multihoprelay', 'routechoice')
spec = importlib.util.spec_from_file_location('relay_amnezia', ROOT/'deploy/prepare-mobile-amnezia.py')
AMNEZIA = importlib.util.module_from_spec(spec)
spec.loader.exec_module(AMNEZIA)

def inputs():
    files = [Path(__file__).resolve()] + AMNEZIA.inputs()
    for package in PACKAGES: files += sorted((ROOT/'internal'/package).glob('*.go'))
    return files

def digest():
    h = hashlib.sha256()
    for path in inputs(): h.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes())
    return h.hexdigest()

def prepare(vendor):
    vendor = vendor.resolve()
    if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=CORE:
        raise ValueError('Private AWG relay requires the exact native core')
    if not (vendor/'go.mod').read_text().startswith('module github.com/sagernet/sing-box\n'):
        raise ValueError('Not a disposable native sing-box checkout')
    for package in PACKAGES:
        output = vendor/'experimental/libbox/routervpn'/package
        if not output.resolve().is_relative_to(vendor): raise ValueError('Relay package target escaped the pinned checkout')
        output.mkdir(parents=True,exist_ok=True)
        if package == 'applexray':
            parent_test = output/'preparation_test.go'
            if parent_test.is_symlink(): raise ValueError('Linked parent-only test in native policy tree')
            if parent_test.exists():
                if not parent_test.is_file() or parent_test.read_bytes() != (ROOT/'internal/applexray/preparation_test.go').read_bytes():
                    raise ValueError('Unexpected parent-only test in native policy tree')
                parent_test.unlink()
        for path in (ROOT/'internal'/package).glob('*.go'):
            if path.name == 'core_config_test.go' or (package == 'applexray' and path.name == 'preparation_test.go'): continue
            text = path.read_text()
            for name in PACKAGES:
                text = text.replace('"router-vpn/internal/'+name+'"','"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+name+'"')
            target=output/path.name
            if target.is_symlink(): raise ValueError('Refusing a linked relay source destination')
            target.write_text(text)
    AMNEZIA.prepare(vendor)
    print('Private relay source digest:', digest())

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor',type=Path,nargs='?')
    parser.add_argument('--digest',action='store_true')
    args=parser.parse_args()
    if args.digest: print(digest())
    elif args.vendor: prepare(args.vendor)
    else: parser.error('vendor or --digest is required')
