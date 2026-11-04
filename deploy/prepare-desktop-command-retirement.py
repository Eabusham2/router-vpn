#!/usr/bin/env python3
"""Project Linux command shutdown through its original retained native owner."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ('command_retirement_linux.go.tmpl', 'command_run_linux.go.tmpl',
             'command_run_other.go.tmpl', 'command_retirement_linux_test.go.tmpl',
             'command_run_linux_test.go.tmpl')
ANCHOR = b'func run() error {\n'
DISPATCH = ANCHOR + b'\tif handled, err := routerVPNRunOwnedCommand(); handled {\n\t\treturn err\n\t}\n'


def inputs():
    return [Path(__file__).resolve(), *(ROOT/'mobile/desktop'/name for name in TEMPLATES)]


def checked_destination(vendor, relative):
    target = vendor / relative
    for parent in (target, *target.parents):
        if parent == vendor:
            break
        if parent.is_symlink():
            raise ValueError('Linked command retirement destination')
    if not target.resolve().is_relative_to(vendor):
        raise ValueError('Command retirement escaped its native checkout')
    return target


def run_dispatch(raw):
    if raw.count(ANCHOR) != 1:
        raise ValueError('Pinned native run entry changed')
    if DISPATCH in raw:
        if raw.count(b'routerVPNRunOwnedCommand()') != 1:
            raise ValueError('Duplicate command retirement dispatch')
        return raw
    if b'routerVPNRunOwnedCommand' in raw:
        raise ValueError('Modified command retirement dispatch')
    return raw.replace(ANCHOR, DISPATCH, 1)


def prepare(vendor):
    vendor = Path(vendor)
    if vendor.is_symlink():
        raise ValueError('Linked native command checkout')
    vendor = vendor.resolve()
    target = checked_destination(vendor, 'cmd/sing-box/cmd_run.go')
    raw = run_dispatch(target.read_bytes())
    # Stage and validate every source/destination before writing the projection.
    staged = [(target, raw)]
    for name in TEMPLATES:
        path = ROOT/'mobile/desktop'/name
        if path.is_symlink():
            raise ValueError('Linked command retirement source')
        raw = path.read_bytes()
        if b'\npackage main\n' not in b'\n'+raw:
            raise ValueError('Command retirement template changed native package')
        staged.append((checked_destination(vendor, 'cmd/sing-box/routervpn_'+name.removesuffix('.tmpl')), raw))
    for target, raw in staged:
        target.write_bytes(raw)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    prepare(parser.parse_args().vendor)
