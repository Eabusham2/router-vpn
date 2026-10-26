#!/usr/bin/env python3
"""Give each native HY2 packet session bounded QUIC datagram admission.

Only checksum-verified, disposable copies of the two pinned modules are changed.
The shared QUIC connection, normal SendDatagram API, framing, and socket owner
remain unchanged. All clients and the private relay use these same source inputs.
"""
from pathlib import Path, PurePosixPath
import argparse
import base64
import hashlib
import json
import stat
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CORE = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
MAX_BYTES, MAX_FILES = 32 * 1024 * 1024, 5000
QUIC = {
    'module': 'github.com/sagernet/quic-go',
    'version': 'v0.61.0-sing-box-mod.7',
    'sum': 'h1:sW2O+DoNF+my1PGlSZ3zG2N+fdxLR3DC0l4sXCM0lBE=',
    'copy': 'routervpn-patched-quic-deadlines',
    'guards': {'connection.go': '3df2ac2a8c64a9504c5843b49e3138318e734894',
               'datagram_queue.go': '06329ce7137cabf590c7c09b4c012f9a89e06d55'},
    'patches': {},
    'extra': {'routervpn_datagram_deadline.go': 'quic_datagram_deadline.go.tmpl',
              'routervpn_datagram_deadline_test.go': 'quic_datagram_deadline_test.go.tmpl'},
}
HY2 = {
    'module': 'github.com/sagernet/sing-quic', 'version': 'v0.7.0',
    'sum': 'h1:dgbJdRYsa9DXbgjchnuVf2xhAvjY4/jylWdNNVZWmRU=',
    'copy': 'routervpn-patched-hysteria2-deadlines',
    'guards': {'hysteria2/packet.go': '316f475b0c37c0751482124d283d24f3afe71d58'},
    'patches': {'hysteria2/packet.go': (
        ('\tquicConn        *quic.Conn\n', '\tquicConn        routerVPNHysteriaPacketConnection\n'),
        ('\treadDeadline    pipe.Deadline\n', '\treadDeadline    pipe.Deadline\n\twriteDeadline   pipe.Deadline\n\tdeadlineMu      sync.Mutex\n'),
        ('func newUDPPacketConn(ctx context.Context, quicConn *quic.Conn, onDestroy func())',
         'func newUDPPacketConn(ctx context.Context, quicConn routerVPNHysteriaPacketConnection, onDestroy func())'),
        ('\t\treadDeadline: pipe.MakeDeadline(),\n', '\t\treadDeadline: pipe.MakeDeadline(),\n\t\twriteDeadline: pipe.MakeDeadline(),\n'),
        ('return c.quicConn.SendDatagram(buffer.Bytes())',
         'err := c.quicConn.RouterVPNSendDatagram(c.ctx, c.writeDeadline.Wait(), buffer.Bytes())\n'
         '\tif c.ctx.Err() != nil {\n\t\treturn net.ErrClosed\n\t}\n\treturn err'),
        ('func (c *udpPacketConn) closeWithError(err error) {\n\tc.cancel(err)\n}',
         'func (c *udpPacketConn) closeWithError(err error) {\n'
         '\tc.deadlineMu.Lock()\n\tdefer c.deadlineMu.Unlock()\n\tc.cancel(err)\n'
         '\tc.readDeadline.Set(time.Time{})\n\tc.writeDeadline.Set(time.Time{})\n}'),
        ('func (c *udpPacketConn) SetDeadline(t time.Time) error {\n\treturn os.ErrInvalid\n}',
         'func (c *udpPacketConn) SetDeadline(t time.Time) error {\n\treturn c.routerVPNSetPacketDeadlines(t, true, true)\n}'),
        ('func (c *udpPacketConn) SetReadDeadline(t time.Time) error {\n\tc.readDeadline.Set(t)\n\treturn nil\n}',
         'func (c *udpPacketConn) SetReadDeadline(t time.Time) error {\n\treturn c.routerVPNSetPacketDeadlines(t, true, false)\n}'),
        ('func (c *udpPacketConn) SetWriteDeadline(t time.Time) error {\n\treturn os.ErrInvalid\n}',
         'func (c *udpPacketConn) SetWriteDeadline(t time.Time) error {\n\treturn c.routerVPNSetPacketDeadlines(t, false, true)\n}'),
    )},
    'extra': {'hysteria2/routervpn_packet_deadline.go': 'packet_deadline.go.tmpl',
              'hysteria2/routervpn_packet_deadline_test.go': 'packet_deadline_test.go.tmpl'},
}
MODULES = (QUIC, HY2)


def inputs():
    return [Path(__file__).resolve(), ROOT/'deploy/test_hysteria2_deadlines.py',
            ROOT/'deploy/test_hysteria2_deadlines_pinned.py',
            *sorted((ROOT/'mobile/hysteria2').glob('*.tmpl'))]


def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def transform(spec, relative, data, reverse=False):
    guard = spec['guards'].get(relative)
    if not reverse and guard and git_blob(data) != guard:
        raise ValueError('Pinned HY2 deadline source changed: ' + relative)
    edits = spec['patches'].get(relative, ())
    for old, new in reversed(edits) if reverse else edits:
        source, target = (new, old) if reverse else (old, new)
        source, target = source.encode(), target.encode()
        if data.count(source) != 1:
            raise ValueError('Unexpected HY2 deadline patch boundary: ' + relative)
        data = data.replace(source, target, 1)
    if reverse and guard and git_blob(data) != guard:
        raise ValueError('Prepared HY2 deadline source has unrelated changes: ' + relative)
    return data


def h1(rows):
    value = ''.join(digest + '  ' + name + '\n' for name, digest in sorted(rows))
    return 'h1:' + base64.b64encode(hashlib.sha256(value.encode()).digest()).decode()


def safe_relative(name):
    path = PurePosixPath(name)
    if (not name or str(path) != name or path.is_absolute() or '..' in path.parts or
            any(char in name for char in ('\\', '\n', '\r', '\0', ':'))):
        raise ValueError('Unsafe deadline module path')
    return name


def template(name):
    return (ROOT/'mobile/hysteria2'/name).read_bytes()


def verify_tree(spec, directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('HY2 deadline copy must be an owned directory')
    rows, total, extras = [], 0, set()
    prefix = spec['module'] + '@' + spec['version'] + '/'
    for path in sorted(directory.rglob('*')):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ValueError('HY2 deadline copy contains a linked or special entry')
        if path.is_dir():
            continue
        relative = safe_relative(path.relative_to(directory).as_posix())
        if path.stat().st_nlink != 1:
            raise ValueError('HY2 deadline source has a foreign hardlink owner')
        total += path.stat().st_size
        if total > MAX_BYTES or len(rows) + len(extras) >= MAX_FILES:
            raise ValueError('HY2 deadline module exceeds source bounds')
        data = path.read_bytes()
        if relative in spec['extra']:
            if data != template(spec['extra'][relative]):
                raise ValueError('Prepared HY2 deadline helper differs: ' + relative)
            extras.add(relative)
        else:
            rows.append((prefix + relative, hashlib.sha256(transform(spec, relative, data, True)).hexdigest()))
    if extras != set(spec['extra']) or h1(rows) != spec['sum']:
        raise ValueError('Prepared HY2 deadline copy lost its exact module identity')


def extract_verified(spec, archive, target):
    rows, total, seen = [], 0, set()
    prefix = spec['module'] + '@' + spec['version'] + '/'
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if not entries or len(entries) > MAX_FILES:
            raise ValueError('Invalid HY2 deadline archive size')
        for entry in entries:
            name = entry.filename
            if not name.startswith(prefix):
                raise ValueError('HY2 deadline archive has a foreign module prefix')
            relative = safe_relative(name[len(prefix):])
            if (entry.is_dir() or stat.S_ISLNK(entry.external_attr >> 16) or
                    relative in seen or relative in spec['extra']):
                raise ValueError('Unsafe or duplicate HY2 deadline archive member')
            seen.add(relative)
            total += entry.file_size
            if total > MAX_BYTES or entry.file_size > MAX_BYTES:
                raise ValueError('HY2 deadline archive exceeds source bounds')
            data = source.read(entry)
            rows.append((name, hashlib.sha256(data).hexdigest()))
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(transform(spec, relative, data))
        if h1(rows) != spec['sum']:
            raise ValueError('HY2 deadline archive does not match its pinned h1 checksum')
    for relative, name in spec['extra'].items():
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(template(name))
    verify_tree(spec, target)


def module_plan(vendor, go='go', env=None):
    plan = json.loads(subprocess.check_output([go, 'mod', 'edit', '-json'], cwd=vendor, env=env, text=True))
    if plan.get('Module', {}).get('Path') != 'github.com/sagernet/sing-box':
        raise ValueError('Expected the owned native core module')
    for spec in MODULES:
        requirements = [r for r in plan.get('Require', []) if r['Path'] == spec['module']]
        if len(requirements) != 1 or requirements[0]['Version'] != spec['version']:
            raise ValueError('HY2 deadlines require the exact pinned dependency versions')
        replacements = [r for r in plan.get('Replace', []) or [] if r['Old']['Path'] == spec['module']]
        expected = {'Old': {'Path': spec['module'], 'Version': spec['version']},
                    'New': {'Path': './' + spec['copy']}}
        if replacements and replacements != [expected]:
            raise ValueError('Refusing an unrelated HY2 deadline replacement')


def prepare(vendor):
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != CORE:
        raise ValueError('HY2 deadlines require the exact disposable native core')
    module_plan(vendor)
    for spec in MODULES:
        target = vendor / spec['copy']
        if target.exists() or target.is_symlink():
            verify_tree(spec, target)
            continue
        info = json.loads(subprocess.check_output(
            ['go', 'mod', 'download', '-json', spec['module'] + '@' + spec['version']], cwd=vendor, text=True))
        if (info.get('Path') != spec['module'] or info.get('Version') != spec['version'] or
                info.get('Sum') != spec['sum'] or info.get('Error')):
            raise ValueError('HY2 deadline download metadata differs from the pinned module')
        with tempfile.TemporaryDirectory(prefix='.routervpn-hy2-', dir=vendor) as temporary:
            staged = Path(temporary) / 'module'
            staged.mkdir()
            extract_verified(spec, Path(info['Zip']), staged)
            staged.rename(target)
    for spec in MODULES:
        subprocess.run(['go', 'mod', 'edit', '-replace=' + spec['module'] + '@' + spec['version'] + '=./' + spec['copy']], cwd=vendor, check=True)
    verify(vendor)
    print('Prepared exact HY2 session write deadlines and scoped QUIC queue admission')


def verify(vendor, go='go', env=None):
    vendor = vendor.resolve()
    module_plan(vendor, go, env)
    for spec in MODULES:
        info = json.loads(subprocess.check_output([go, 'list', '-m', '-json', spec['module']], cwd=vendor, env=env, text=True))
        replacement = info.get('Replace') or {}
        if (info.get('Version') != spec['version'] or replacement.get('Path') != './' + spec['copy'] or
                Path(replacement.get('Dir', '')).resolve() != vendor / spec['copy']):
            raise ValueError('Native core lost its verified HY2 deadline module copy')
        verify_tree(spec, vendor / spec['copy'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    verify(args.vendor) if args.verify else prepare(args.vendor)
