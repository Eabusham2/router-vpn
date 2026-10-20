#!/usr/bin/env python3
"""Copy the shared inline OpenVPN compiler and established mobile binding."""
from pathlib import Path
import argparse
import hashlib

ROOT = Path(__file__).resolve().parents[1]
IMPORT = '"router-vpn/internal/nativeopenvpn"'
NATIVE_IMPORT = '"github.com/sagernet/sing-box/experimental/libbox/routervpn/nativeopenvpn"'


def inputs():
    return [Path(__file__).resolve(), ROOT/'deploy/test_mobile_openvpn_source.py', ROOT/'mobile/routervpn_openvpn.go',
            ROOT/'mobile/routervpn_openvpn_test.go', ROOT/'mobile/routervpn_openvpn_parser_test.go',
            *sorted((ROOT/'internal/nativeopenvpn').glob('*.go'))]


def digest():
    value = hashlib.sha256()
    for source in inputs():
        value.update(str(source.relative_to(ROOT)).encode()+b'\0'+source.read_bytes())
    return value.hexdigest()


def prepare(vendor):
    vendor = Path(vendor).resolve()
    if not (vendor/'go.mod').read_text().startswith('module github.com/sagernet/sing-box\n'):
        raise ValueError('Expected the owned disposable native core checkout')
    output = vendor/'experimental/libbox/routervpn/nativeopenvpn'
    if not output.resolve().is_relative_to(vendor):
        raise ValueError('OpenVPN compiler destination escaped the native checkout')
    output.mkdir(parents=True, exist_ok=True)
    files = {output/source.name: source.read_bytes() for source in (ROOT/'internal/nativeopenvpn').glob('*.go')}
    binding = (ROOT/'mobile/routervpn_openvpn.go').read_text()
    if binding.count(IMPORT) != 1:
        raise ValueError('OpenVPN mobile binding lost its shared compiler import')
    files[vendor/'experimental/libbox/routervpn_openvpn.go'] = binding.replace(IMPORT, NATIVE_IMPORT, 1).encode()
    for target in files:
        if target.is_symlink() or not target.resolve().is_relative_to(vendor):
            raise ValueError('Unsafe OpenVPN source destination')
    for target, data in files.items():
        target.write_bytes(data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path, nargs='?')
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest:
        print(digest())
    elif args.vendor:
        prepare(args.vendor)
    else:
        parser.error('vendor or --digest is required')
