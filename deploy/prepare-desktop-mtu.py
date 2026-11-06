#!/usr/bin/env python3
"""Prepare exclusive native desktop TUN creation in the pinned dependency."""
from pathlib import Path
import json
import hashlib
import subprocess
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'github.com/sagernet/sing-tun'
VERSION = 'v0.9.3'

# Exact v0.9.3 source, before the existing owned-interface and receipt transforms.
# An occupied route belongs to its existing owner; an MTU successor is started
# only after the original TUN has closed, so EEXIST cannot authorize takeover.
LINUX_SOURCE_SHA256 = '6cbe2a62823471888abaaf7a32d0613d96ea3acb22b01d3e8f4b6142767f9c1b'
DARWIN_SOURCE_SHA256 = '0676cdec64934d98461e87b625675f5b0d3d2281f3f4126005df5473f19bde61'
DARWIN_ROUTE_TAKEOVER = b'''				if err != nil {
					if errors.Is(err, unix.EEXIST) {
						err = execRoute(unix.RTM_DELETE, false, 0, destination, gateway)
						if err != nil {
							return E.Cause(err, "remove existing route: ", destination)
						}
						err = execRoute(unix.RTM_ADD, t.options.InterfaceScope, interfaceIndex, destination, gateway)
						if err != nil {
							return E.Cause(err, "re-add route: ", destination)
						}
					} else {
						return E.Cause(err, "add route: ", destination)
					}
				}'''
DARWIN_ROUTE_REFUSAL = b'''				if err != nil {
					return E.Cause(err, "add route: ", destination)
				}'''


def darwin_route_conflict_patch(raw):
    if hashlib.sha256(raw).hexdigest() != DARWIN_SOURCE_SHA256:
        raise ValueError('Pinned Darwin route source changed')
    if raw.count(DARWIN_ROUTE_TAKEOVER) != 1 or raw.count(b'\t"errors"\n') != 1 or raw.count(b'errors.') != 1:
        raise ValueError('Pinned Darwin EEXIST boundary changed')
    return raw.replace(DARWIN_ROUTE_TAKEOVER, DARWIN_ROUTE_REFUSAL, 1).replace(b'\t"errors"\n', b'', 1)


def network_receipt_patch(name, raw):
    if name not in ('tun_linux.go', 'tun_windows.go', 'tun_darwin.go'):
        return raw
    patches = [(b'type NativeTun struct {', b'type NativeTun struct {\n\troutervpnNetwork routerVPNNativeNetworkLedger')]
    if name == 'tun_linux.go':
        raw = linux_retirement_patch(raw)
    elif name == 'tun_windows.go':
        if raw.count(b'addRouteList(luid, routeRanges, gateway4, gateway6, 0)') != 2:
            raise ValueError('Pinned Windows route-list callers changed')
        raw = raw.replace(b'addRouteList(luid, routeRanges, gateway4, gateway6, 0)', b't.routervpnAddRouteList(luid, routeRanges, gateway4, gateway6, 0)')
        patches += [
            (b'func addRouteList(luid winipcfg.LUID,', b'func (t *NativeTun) routervpnAddRouteList(luid winipcfg.LUID,'),
            (b'''\t\terr = row.Create()
\t\tif err != nil {
\t\t\treturn err
\t\t}
\t}''', b'''\t\terr = row.Create()
\t\tif err != nil {
\t\t\treturn err
\t\t}
\t\tt.routervpnWindowsAdded(row)
\t}'''),
        ]
    else:
        # The conflict transform refuses an occupied route before this
        # observational wrapper records successful, uniquely observed adds.
        if raw.count(b'err = execRoute(') != 2:
            raise ValueError('Pinned Darwin route callers changed')
        raw = raw.replace(b'err = execRoute(', b'err = t.routervpnExecRoute(')
    for before, after in patches:
        if raw.count(before) != 1:
            raise ValueError('Pinned desktop routing receipt boundary changed: '+name)
        raw = raw.replace(before, after)
    return raw


def linux_retirement_patch(raw):
    if hashlib.sha256(raw).hexdigest() != LINUX_SOURCE_SHA256:
        raise ValueError('Pinned Linux native lifecycle source changed')
    def replace(before, after):
        nonlocal raw
        if raw.count(before) != 1:
            raise ValueError('Pinned Linux successful-call retirement boundary changed: '+before[:80].decode())
        raw = raw.replace(before, after, 1)

    def function(name, body):
        nonlocal raw
        start = raw.index(b'func (t *NativeTun) '+name+b'(')
        end = raw.find(b'\nfunc ', start+1)
        if end < 0:
            end = len(raw)
        raw = raw[:start]+body+raw[end:]

    replace(b'type NativeTun struct {', b'type NativeTun struct {\n\troutervpnRetirement routerVPNLinuxRetirement\n\troutervpnResolver routerVPNLinuxResolver\n\troutervpnOwnedIndex int')
    replace(b'flags := unix.IFF_TUN | unix.IFF_NO_PI', b'flags := unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL')
    replace(b'unix.Open(controlPath, unix.O_RDWR, 0)', b'unix.Open(controlPath, unix.O_RDWR|unix.O_CLOEXEC, 0)')
    replace(b'\t\tunix.Close(fd)\n\t\treturn 0, E.Cause(err, "set nonblock")', b'\t\treturn fd, E.Cause(err, "set nonblock")')
    raw = raw.replace(b'return 0, E.Cause(err, "create ifreq")', b'return -1, E.Cause(err, "create ifreq")')
    raw = raw.replace(b'return 0, E.Cause(err, "TUNSETIFF")', b'return -1, E.Cause(err, "TUNSETIFF")')
    start = raw.index(b'\t\t\ttunFd, err := open(options.Name, options.GSO)')
    end = raw.index(b'\n\t\t})', start)
    raw = raw[:start]+b'\t\t\treturn routervpnNewLinuxNative(options)'+raw[end:]
    replace(b'\t\terr := netlink.RouteAdd(&route)', b'\t\terr := t.routervpnLinuxAddRoute(route)')
    replace(b'\tfor i, rule := range t.rules() {\n\t\terr := netlink.RuleAdd(rule)', b'\trules := t.rules()\n\tfor i, rule := range rules {\n\t\terr := t.routervpnLinuxAddRule(rule)')
    replace(b'len(t.rules())', b'len(rules)')
    for version in (b'4', b'6'):
        replace(b'err = netlink.AddrAdd(tunLink, addr'+version+b')', b'err = t.routervpnLinuxAddAddress(tunLink, addr'+version+b')')
    address_error = b'if err != nil && !errors.Is(err, unix.EEXIST) {\n\t\t\t\t\treturn E.Cause(err, "add address ", address)'
    if raw.count(address_error) != 2:
        raise ValueError('Pinned Linux address success/refusal boundaries changed')
    raw = raw.replace(address_error, address_error.replace(b' && !errors.Is(err, unix.EEXIST)', b''))
    replace(b'err = netlink.LinkSetUp(tunLink)', b'err = t.routervpnLinuxLinkSetUp(tunLink)')

    replace(b'\t\t_ = t.unsetRoute0(tunLink)\n', b'')
    replace(b'\terr = t.unsetRules()\n\tif err != nil {\n\t\treturn E.Cause(err, "cleanup rules")\n\t}\n', b'')
    replace(b'\t\t_ = t.unsetRules()\n', b'')
    function(b'Close', b'func (t *NativeTun) Close() error {\n\treturn t.routervpnLinuxClose()\n}\n')
    function(b'unsetRoute', b'func (t *NativeTun) unsetRoute() error {\n\treturn t.routervpnLinuxRetireCalls(t.options.RouterVPNNetworkContext, "route")\n}\n')
    function(b'unsetRoute0', b'func (t *NativeTun) unsetRoute0(_ netlink.Link) error {\n\treturn t.unsetRoute()\n}\n')
    function(b'unsetRules', b'func (t *NativeTun) unsetRules() error {\n\treturn t.routervpnLinuxRetireCalls(t.options.RouterVPNNetworkContext, "rule")\n}\n')
    function(b'unsetAddresses', b'')
    replace(b't.setSearchDomainForSystemdResolved()', b't.routervpnLinuxResolverStart(t.options.RouterVPNNetworkContext)')
    function(b'setSearchDomainForSystemdResolved', b'')
    function(b'unsetSearchDomainForSystemdResolved', b'')
    replace(b'\t"os/exec"\n', b'')
    replace(b'\t"github.com/sagernet/sing/common/shell"\n', b'')
    replace(b'\tt.unsetRules()\n\treturn t.setRules()', b'\tif err := t.unsetRules(); err != nil { return err }\n\treturn t.setRules()')
    # Shipping wrappers admit the original caller and descriptor before these
    # unchanged native bodies, then reject late results without discarding the
    # partially mutated reader needed by original Stop.
    for old, new in ((b'Start', b'routervpnLinuxStartOriginal'),
                     (b'UpdateRouteOptions', b'routervpnLinuxUpdateOriginal'),
                     (b'resetRules', b'routervpnLinuxResetRulesOriginal')):
        replace(b'func (t *NativeTun) '+old+b'(', b'func (t *NativeTun) '+new+b'(')
    # No range, regenerated-route, or by-name address deletion remains.
    for forbidden in (b'netlink.RuleDel(', b'netlink.RouteDel(', b'netlink.AddrDel('):
        if forbidden in raw:
            raise ValueError('Unowned Linux native deletion remains: '+forbidden.decode())
    return raw


def dbus_preparer():
    specification = importlib.util.spec_from_file_location('desktop_dbus', ROOT/'deploy/prepare-desktop-dbus.py')
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def verify_linux_retirement_source(vendor, go='go'):
    vendor = Path(vendor).resolve()
    cache = subprocess.check_output([go, 'env', 'GOMODCACHE'], cwd=vendor, text=True, timeout=30).strip()
    pristine = Path(cache) / (MODULE + '@' + VERSION) / 'tun_linux.go'
    if pristine.is_symlink() or not pristine.is_file():
        raise ValueError('Linux retirement gate lost its checksum-pinned native source')
    expected = network_receipt_patch('tun_linux.go', pristine.read_bytes())
    native = vendor / 'routervpn-desktop-tun'
    target = native / 'tun_linux.go'
    if native.is_symlink() or target.is_symlink() or not target.is_file() or target.read_bytes() != expected:
        raise ValueError('Linux retirement differs from the complete prepared native lifecycle')
    # The address history is meaningful only with the exact constructor,
    # notification parser and shared receipt codec that produced it.
    for name in ('sing_tun_retirement_linux.go.tmpl', 'sing_tun_retirement_linux_test.go.tmpl', 'sing_tun_retirement_socket_linux.go.tmpl',
                 'sing_tun_address_retirement_linux.go.tmpl', 'sing_tun_address_retirement_linux_test.go.tmpl'):
        original = ROOT/'mobile/desktop'/name
        projected = native/('routervpn_'+name.removesuffix('.tmpl'))
        if original.is_symlink() or projected.is_symlink() or not projected.is_file() or projected.read_bytes() != original.read_bytes():
            raise ValueError('Linux partial-address retirement lost its exact prepared closure: '+name)
    original = ROOT/'internal/desktopnetwork/desktop_network_retirement.go'
    projected = native/'routervpn_desktop_network_retirement.go'
    if original.is_symlink() or projected.is_symlink() or not projected.is_file() or projected.read_bytes() != original.read_bytes().replace(b'package desktopnetwork\n', b'package tun\n', 1):
        raise ValueError('Linux partial-address retirement lost its shared receipt codec')
    records = dbus_preparer().verify(vendor, go=go)
    for path in sorted(native.rglob('*')):
        if path.is_symlink():
            raise ValueError('Linux retirement contains a linked native module input')
        if path.is_file():
            records[path.relative_to(vendor).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    records['gate/deploy/prepare-desktop-mtu.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return records


def darwin_owned_source(raw):
    raw = darwin_route_conflict_patch(raw)
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
    return raw


# Exact pinned inbound after the declared retained/mobile MTU projection,
# before either desktop lifecycle projection. Only those complete states are
# admitted; a partial/duplicate edit must not become a cached-source repair.
INBOUND_MTU_SHA256 = 'abc973fd68bf66800df527237a664fcece120ed9de6a2cba1aa3a5679405044e'
INBOUND_CONTEXT_EDIT = (
    b'tunOptions: tun.Options{',
    b'tunOptions: tun.Options{\n\t\t\tRouterVPNNetworkContext: ctx,\n\t\t\tRouterVPNNetworkLifetime: ctx,',
)
INBOUND_RETIREMENT_EDITS = (
    (b'type Inbound struct {',
     b'type Inbound struct {\n\troutervpnStandardStartup bool\n\troutervpnRetirementReceipt string'),
    (b'\t\tt.tunOptions.Name = tunOptions.Name\n\t\tif err != nil {',
     b'\t\tt.tunOptions.Name = tunOptions.Name\n'
     b'\t\tt.tunIf = tunInterface // retain the actual partial constructor before its error\n'
     b'\t\tif err != nil {'),
    (b'\t\t\t\tt.tunIf = nil\n',
     b'\t\t\t\tif closeError == nil { t.tunIf = nil }\n'),
    (b'\tt.routervpnReady = false\n\treturn common.Close(',
     b'\tt.routervpnReady = false\n'
     b'\tif runtime.GOOS == "linux" && (t.routervpnStandardStartup || t.routervpnRetirementReceipt != "") {\n'
     b'\t\t_, err := t.routervpnDesktopTunRetireLocked(t.tunOptions.RouterVPNNetworkContext)\n'
     b'\t\treturn err\n\t}\n\treturn common.Close('),
)



def inbound_retirement_patch(raw):
    original = raw
    marked = any(token in raw for token in (b'routervpnStandardStartup', b'routervpnRetirementReceipt',
                 b'routervpnDesktopTunRetireLocked', b'retain the actual partial constructor'))
    if marked:
        for before, after in reversed(INBOUND_RETIREMENT_EDITS):
            if raw.count(after) != 1:
                raise ValueError('Incomplete or duplicated native inbound retirement projection')
            raw = raw.replace(after, before, 1)
    before, after = INBOUND_CONTEXT_EDIT
    previous_context = b"tunOptions: tun.Options{\n\t\t\tRouterVPNNetworkContext: ctx,"
    upgrading_context = after not in raw and previous_context in raw
    if upgrading_context:
        if raw.count(previous_context) != 1:
            raise ValueError("Duplicated prior bounded native context")
        raw = raw.replace(previous_context, before, 1)
    if after in raw:
        if raw.count(after) != 1:
            raise ValueError('Duplicated native inbound startup context')
        raw = raw.replace(after, before, 1)
    if hashlib.sha256(raw).hexdigest() != INBOUND_MTU_SHA256:
        raise ValueError('Native inbound differs from the complete pinned MTU projection')
    for before, after in (INBOUND_CONTEXT_EDIT, *INBOUND_RETIREMENT_EDITS):
        if raw.count(before) != 1:
            raise ValueError('Pinned native inbound retirement boundary changed')
        raw = raw.replace(before, after, 1)
    if marked and original != raw and not upgrading_context:
        raise ValueError('Modified completed native inbound retirement projection')
    return raw


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
            if relative.as_posix() == 'tun.go':
                before = b'return nil, E.New("no IPv4 server configured and no usable next address in ", o.Inet6Address[0], " for DNS")'
                after = b'return nil, E.New("no IPv4 server configured and no usable next address in ", o.Inet4Address[0], " for DNS")'
                if raw.count(before) != 1:
                    raise ValueError('Pinned IPv4 unusable-DNS error boundary changed')
                raw = raw.replace(before, after, 1)
                for before, after in [(b'import (', b'import (\n\t"context"'),
                                      (b'type Options struct {', b'type Options struct {\n\tRouterVPNNetworkContext context.Context\n\tRouterVPNNetworkLifetime context.Context')]:
                    if raw.count(before) != 1:
                        raise ValueError('Pinned native network context boundary changed')
                    raw = raw.replace(before, after, 1)
            if relative.as_posix() == 'tun_darwin.go':
                raw = darwin_owned_source(raw)
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
                before = b'''\tsession, err := adapter.StartSession(0x800000)
\tif err != nil {
\t\treturn nil, err
\t}'''
                if raw.count(before) != 1:
                    raise ValueError('Pinned Wintun failed-session cleanup boundary changed')
                raw = raw.replace(before, b'''\tsession, err := adapter.StartSession(0x800000)
\tif err != nil {
\t\t// A failed session still owns the adapter just created above.
\t\t// Close it synchronously before returning the original failure.
\t\t_ = adapter.Close()
\t\treturn nil, err
\t}''')
                # The pinned file uses errors elsewhere; its other ownership
                # and close checks remain byte-for-byte unchanged.
            if target.exists() and not target.stat().st_mode & 0o200:
                target.chmod(0o644)
            target.write_bytes(network_receipt_patch(relative.as_posix(), raw))
    subprocess.run(['go', 'mod', 'edit', '-require=github.com/godbus/dbus/v5@v5.2.2'], cwd=destination, check=True)
    # The wire decoder is identical in the parent and native TUN module. It
    # imports only the standard library and never introduces a module cycle.
    for name in ('desktop_network_receipt.go', 'desktop_network_wire.go', 'desktop_network_darwin_wire.go', 'desktop_network_dump_linux.go', 'desktop_network_retirement.go', 'desktop_network_retirement_limit_test.go', 'desktop_network_lock.go'):
        path = ROOT/'internal/desktopnetwork'/name
        raw = path.read_bytes()
        if path.is_symlink() or raw.count(b'package desktopnetwork\n') != 1:
            raise ValueError('Native network receipt source boundary changed')
        target = destination/('routervpn_'+name)
        if target.is_symlink():
            raise ValueError('Linked native network receipt destination')
        target.write_bytes(raw.replace(b'package desktopnetwork\n', b'package tun\n', 1))
    for name in ('resolved_policy.go', 'resolved_protocol.go', 'resolved_local.go', 'resolved_anchor.go', 'resolved_route.go', 'resolved_server_state.go'):
        path = ROOT/'internal/standardengine'/name
        raw = path.read_bytes()
        if path.is_symlink() or raw.count(b'package standardengine\n') != 1:
            raise ValueError('Native resolved policy source boundary changed')
        target = destination/('routervpn_'+name)
        if target.is_symlink():
            raise ValueError('Linked native resolved policy destination')
        target.write_bytes(raw.replace(b'package standardengine\n', b'package tun\n', 1))
    inbound = vendor/'protocol/tun/inbound.go'
    raw = inbound.read_bytes()
    prepared = inbound_retirement_patch(raw)
    if prepared != raw:
        inbound.write_bytes(prepared)
    for name in ('sing_tun_monitor_context.go.tmpl', 'sing_tun_monitor_context_test.go.tmpl', 'sing_tun_network.go.tmpl', 'sing_tun_network_linux.go.tmpl', 'sing_tun_network_inventory_linux.go.tmpl', 'sing_tun_retirement_linux.go.tmpl', 'sing_tun_address_retirement_linux.go.tmpl', 'sing_tun_address_retirement_linux_test.go.tmpl', 'sing_tun_retirement_socket_linux.go.tmpl', 'sing_tun_retirement_linux_test.go.tmpl', 'sing_tun_retirement_native_linux_test.go.tmpl', 'sing_tun_resolver_linux.go.tmpl', 'sing_tun_resolver_linux_test.go.tmpl', 'sing_tun_resolved_authority_linux.go.tmpl', 'sing_tun_resolved_authority_linux_test.go.tmpl', 'sing_tun_resolved_anchor_linux.go.tmpl', 'sing_tun_resolved_anchor_linux_test.go.tmpl', 'sing_tun_resolved_server_state_linux.go.tmpl', 'sing_tun_resolved_server_state_linux_test.go.tmpl', 'sing_tun_dns_test.go.tmpl', 'sing_tun_network_linux_test.go.tmpl', 'sing_tun_network_windows.go.tmpl', 'sing_tun_network_darwin.go.tmpl', 'sing_tun_network_darwin_test.go.tmpl', 'sing_tun_route_darwin_test.go.tmpl'):
        path = ROOT/'mobile/desktop'/name
        if path.is_symlink():
            raise ValueError('Linked native network receipt template')
        target = destination/('routervpn_'+name.removesuffix('.tmpl'))
        if target.is_symlink():
            raise ValueError('Linked native network receipt template destination')
        target.write_bytes(path.read_bytes())
    control = ROOT/'mobile/desktop/sing_tun_darwin_control.go.tmpl'
    raw = control.read_bytes()
    if control.is_symlink() or not raw.startswith(b'//go:build darwin\n\npackage tun\n'):
        raise ValueError('Darwin native TUN control source boundary changed')
    target = destination/'routervpn_control_darwin.go'
    if target.is_symlink():
        raise ValueError('Linked Darwin native TUN control destination')
    target.write_bytes(raw)
    subprocess.run(['go', 'mod', 'edit', '-replace='+MODULE+'=./routervpn-desktop-tun'], cwd=vendor, check=True)
    specification = importlib.util.spec_from_file_location('desktop_command_retirement', ROOT/'deploy/prepare-desktop-command-retirement.py')
    command_retirement = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(command_retirement)
    command_retirement.prepare(vendor)
    dbus_preparer().prepare(vendor)
    print('Prepared checksum-pinned desktop TUN with original routing retirement')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    prepare(parser.parse_args().vendor)
