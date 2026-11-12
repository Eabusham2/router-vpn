"""Drain the exact pinned OpenVPN link before gVisor takes its teardown lock."""
from pathlib import Path
import hashlib
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
SOURCE_SHA = '9a0bd5edd56c4ef64f8d8ae335e2a6dfe4d921dc'
OLD = '\t\tclose(d.endpoint.done)\n\t\tif d.udpForwarder != nil {'
NEW = ('\t\tclose(d.endpoint.done)\n'
       '\t\t// Drain captured packet delivery before gVisor Stack.Wait owns its\n'
       '\t\t// stack lock and calls Attach(nil). Delivery can acquire that lock.\n'
       '\t\td.endpoint.Attach(nil)\n'
       '\t\tif d.udpForwarder != nil {')


# These three concrete pointer returns must be unboxed before conversion to the
# public net.Conn/net.PacketConn interface. A nil *gonet.TCPConn is otherwise a
# non-nil interface and its caller's ordinary failure cleanup panics in Close.
DIAL_PATCHES = tuple((old, old.replace('return '+call, 'connection, err := '+call)+
    '\n'+indent+'if connection == nil {\n'+indent+'\treturn nil, err\n'+indent+'}\n'+indent+'return connection, err')
    for indent, call in (
        ('\t\t', 'gonet.DialTCPWithBind(ctx, d.stack, bind, address, networkProtocol)'),
        ('\t\t', 'gonet.DialUDP(d.stack, &bind, &address, networkProtocol)'),
        ('\t', 'gonet.DialUDP(d.stack, &bind, nil, networkProtocol)'),
    ) for old in (indent+'return '+call,))


def inputs():
    return [Path(__file__).resolve(), ROOT/'deploy/test_mobile_openvpn_stack_policy.py',
            ROOT/'mobile/openvpn/stack_close_test.go.tmpl', ROOT/'mobile/openvpn/stack_capacity.go.tmpl']


def blobsha(data):
    return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()


def patch(source):
    original = source.replace(NEW, OLD, 1) if source.count(NEW) == 1 else source
    for old, new in DIAL_PATCHES:
        if original.count(new) == 1:
            original = original.replace(new, old, 1)
    if original.count(OLD) != 1 or any(original.count(old) != 1 for old, _ in DIAL_PATCHES) or blobsha(original.encode()) != SOURCE_SHA:
        raise ValueError('Pinned OpenVPN stack changed; delivery-drain/dial patch refused')
    # Admit the exact original, previous owned drain-only version, and the fully
    # current projection. Any partial dial update remains a source error.
    previous = original.replace(OLD, NEW, 1)
    fixed = previous
    for old, new in DIAL_PATCHES:
        fixed = fixed.replace(old, new, 1)
    if source not in (original, previous, fixed):
        raise ValueError('Partial OpenVPN delivery-drain/dial patch')
    return fixed


def prepare(vendor):
    vendor = Path(vendor).resolve(strict=True)
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('OpenVPN delivery drain requires the exact pinned core')
    source = vendor/'transport/openvpn/device_stack.go'
    fixture = source.with_name('routervpn_stack_close_test.go')
    capacity = source.with_name('routervpn_stack_capacity.go')
    for target in (source, fixture, capacity):
        if target.is_symlink() or not target.resolve().is_relative_to(vendor):
            raise ValueError('Unsafe native OpenVPN delivery-drain target')
    fixed = patch(source.read_text())
    source.write_bytes(fixed.encode('utf-8'))
    fixture.write_bytes((ROOT/'mobile/openvpn/stack_close_test.go.tmpl').read_bytes())
    capacity.write_bytes((ROOT/'mobile/openvpn/stack_capacity.go.tmpl').read_bytes())
    print('Verified native OpenVPN link delivery drains before gVisor teardown')
