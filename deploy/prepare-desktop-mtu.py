#!/usr/bin/env python3
"""Prepare exclusive native desktop TUN creation in the pinned dependency."""
from pathlib import Path
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'github.com/sagernet/sing-tun'
VERSION = 'v0.9.3'


def prepare(vendor):
    vendor = vendor.resolve()
    module = json.loads(subprocess.check_output(['go', 'mod', 'download', '-json', MODULE+'@'+VERSION], cwd=vendor, text=True))
    expected = [line.split()[2] for line in (vendor/'go.sum').read_text().splitlines()
                if line.startswith(MODULE+' '+VERSION+' ')]
    if expected != [module.get('Sum')] or module.get('Version') != VERSION:
        raise ValueError('Desktop MTU requires the checksum-pinned native TUN module')
    source = Path(module['Dir']).resolve()
    destination = vendor/'routervpn-desktop-tun'
    if destination.is_symlink():
        raise ValueError('Linked desktop TUN dependency')
    for path in source.rglob('*'):
        if path.is_symlink():
            raise ValueError('Linked native TUN source')
        relative = path.relative_to(source)
        target = destination/relative
        if target.is_symlink() or not target.parent.resolve().is_relative_to(vendor):
            raise ValueError('Prepared native TUN source escaped its checkout')
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_symlink():
                raise ValueError('Linked prepared native TUN source')
            raw = path.read_bytes()
            if relative.as_posix() == 'tun_linux.go':
                patches = [
                    (b'type NativeTun struct {', b'type NativeTun struct {\n\troutervpnOwnedIndex int'),
                    (b'\t\t\t\ttunFd:   tunFd,', b'\t\t\t\troutervpnOwnedIndex: tunLink.Attrs().Index,\n\t\t\t\ttunFd:   tunFd,'),
                    (b'flags := unix.IFF_TUN | unix.IFF_NO_PI', b'flags := unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL'),
                    (b'''\tif t.options.EXP_ExternalConfiguration {
\t\treturn common.Close(common.PtrOrNil(t.tunFile))
\t}
\tif t.options.DNSMode != DNSModeDisabled && t.options.NetNs == "" {''', b'''\tif t.options.EXP_ExternalConfiguration {
\t\treturn common.Close(common.PtrOrNil(t.tunFile))
\t}
\tif t.routervpnOwnedIndex != 0 {
\t\tcurrent, err := net.InterfaceByName(t.options.Name)
\t\tif err != nil || current.Index != t.routervpnOwnedIndex {
\t\t\t// Close only the descriptor we created. Never remove a replacement
\t\t\t// interface's addresses, routes, DNS policy or shared rule priorities.
\t\t\treturn E.Errors(E.New("native TUN identity retired before cleanup"), common.Close(common.PtrOrNil(t.tunFile)))
\t\t}
\t}
\tif t.options.DNSMode != DNSModeDisabled && t.options.NetNs == "" {'''),
                ]
                for before, after in patches:
                    if raw.count(before) != 1:
                        raise ValueError('Pinned Linux TUN ownership boundary changed')
                    raw = raw.replace(before, after)
            if relative.as_posix() == 'tun_darwin.go':
                patches = [
                    (b'type NativeTun struct {', b'type NativeTun struct {\n\troutervpnOwnedIndex int'),
                    (b'\tnativeTun.readPoller = common.Must1(rawfile.NewPoller(nativeTun.stopFd.ReadFD, tunFd))', b'''\tif options.FileDescriptor == 0 {
\t\tcurrent, err := net.InterfaceByName(options.Name)
\t\tif err != nil {
\t\t\tnativeTun.stopFd.Close()
\t\t\t_ = nativeTun.tunFile.Close()
\t\t\treturn nil, err
\t\t}
\t\tnativeTun.routervpnOwnedIndex = current.Index
\t}
\tnativeTun.readPoller = common.Must1(rawfile.NewPoller(nativeTun.stopFd.ReadFD, tunFd))'''),
                    (b'\tdefer flushDNSCache()', b'''\tif t.routervpnOwnedIndex != 0 {
\t\tcurrent, err := net.InterfaceByName(t.options.Name)
\t\tif err != nil || current.Index != t.routervpnOwnedIndex {
\t\t\tt.stopFd.Stop()
\t\t\tcloseErr := t.tunFile.Close()
\t\t\tt.closePollers()
\t\t\tt.stopFd.Close()
\t\t\treturn E.Errors(E.New("native TUN identity retired before cleanup"), closeErr)
\t\t}
\t}
\tdefer flushDNSCache()'''),
                ]
                for before, after in patches:
                    if raw.count(before) != 1:
                        raise ValueError('Pinned Darwin TUN ownership boundary changed')
                    raw = raw.replace(before, after)
            if relative.as_posix() == 'tun_windows.go':
                before = b'''\tif err != nil {
\t\tif !errors.Is(err, os.ErrExist) {
\t\t\treturn nil, err
\t\t}
\t\tcreateErr := err
\t\tadapter, err = wintun.OpenAdapter(options.Name)
\t\tif err != nil {
\t\t\treturn nil, E.Errors(E.Cause(createErr, "create adapter"), E.Cause(err, "open existing adapter"))
\t\t}
\t}'''
                if raw.count(before) != 1:
                    raise ValueError('Pinned Wintun exclusive creation boundary changed')
                raw = raw.replace(before, b'''\tif err != nil {
\t\t// Router VPN owns each adapter it creates. A same-name adapter from
\t\t// another process is not an MTU rollback or startup resource.
\t\treturn nil, err
\t}''')
                # The pinned file uses errors elsewhere; its other ownership
                # and close checks remain byte-for-byte unchanged.
            if target.exists() and not target.stat().st_mode & 0o200:
                target.chmod(0o644)
            target.write_bytes(raw)
    control = ROOT/'mobile/desktop/sing_tun_darwin_control.go.tmpl'
    raw = control.read_bytes()
    if control.is_symlink() or not raw.startswith(b'//go:build darwin\n\npackage tun\n'):
        raise ValueError('Darwin native TUN control source boundary changed')
    target = destination/'routervpn_control_darwin.go'
    if target.is_symlink():
        raise ValueError('Linked Darwin native TUN control destination')
    target.write_bytes(raw)
    subprocess.run(['go', 'mod', 'edit', '-replace='+MODULE+'=./routervpn-desktop-tun'], cwd=vendor, check=True)
    print('Prepared checksum-pinned desktop TUN with exclusive Wintun creation')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    prepare(parser.parse_args().vendor)
