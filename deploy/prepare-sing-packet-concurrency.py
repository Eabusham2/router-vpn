#!/usr/bin/env python3
"""Compose the pinned UDP fixes in one checksum-verified owned sing copy.

sing 0.9.4 stores a multiword remote address on every packet receive while the
reply goroutine reads it. Guard all three receive APIs and all reply/getter APIs
without holding a lock across network IO. The same copy also preserves complete
65535-byte UDP ciphertext in default and low-memory builds. Both native build
preparations use this owner, so neither can replace the other's dependency.
The SOCKS client association also couples its UDP socket to the lifetime of
its negotiated TCP control connection and synchronizes its own reply endpoint.
Preserve TCP capacities, upstream routing semantics, the whole-module h1
checksum, and the license; never edit the Go module cache.
"""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import json
import stat
import subprocess
import tempfile
import zipfile

CORE = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
MODULE = 'github.com/sagernet/sing'
VERSION = 'v0.9.4'
SUM = 'h1:nIdH+Yvy4NzTezB+c3z/9of1jLRggnrtMtb3uMOIaNM='
COPY = 'routervpn-patched-sing'
PREFIX = MODULE + '@' + VERSION + '/'
MAX_BYTES = 32 * 1024 * 1024
BUFFER_FILES = {
    'common/buf/buffer_standard.go': ('608fbf3f13067a7568c491990dba764b81107e87', '16 * 1024'),
    'common/buf/buffer_low_memory.go': ('81fb10a26460dea3586486118d091a43020284eb', '8 * 1024'),
}
PATCHES = {
    'common/bufio/bind.go': ('dd46fb836525f573a1d4578ad73903dc766516c6', (
        ('\t"net"\n', '\t"net"\n\t"sync"\n'),
        ('\tremoteAddr M.Socksaddr\n', '\tremoteMu   sync.RWMutex\n\tremoteAddr M.Socksaddr\n'),
        ('func (c *serverPacketConn) Read(p []byte)',
         '// Packet receives and replies run concurrently for one SOCKS association.\n'
         '// Copy the complete endpoint under its own lock, never across socket IO.\n'
         'func (c *serverPacketConn) setRemoteAddr(addr M.Socksaddr) {\n'
         '\tc.remoteMu.Lock()\n\tc.remoteAddr = addr\n\tc.remoteMu.Unlock()\n}\n\n'
         'func (c *serverPacketConn) remoteAddress() M.Socksaddr {\n'
         '\tc.remoteMu.RLock()\n\taddr := c.remoteAddr\n\tc.remoteMu.RUnlock()\n\treturn addr\n}\n\n'
         'func (c *serverPacketConn) Read(p []byte)'),
        ('\tc.remoteAddr = M.SocksaddrFromNet(addr)\n', '\tc.setRemoteAddr(M.SocksaddrFromNet(addr))\n'),
        ('\tc.remoteAddr = destination\n', '\tc.setRemoteAddr(destination)\n'),
        ('return c.NetPacketConn.WriteTo(p, c.remoteAddr.UDPAddr())', 'return c.NetPacketConn.WriteTo(p, c.remoteAddress().UDPAddr())'),
        ('return c.NetPacketConn.WritePacket(buffer, c.remoteAddr)', 'return c.NetPacketConn.WritePacket(buffer, c.remoteAddress())'),
        ('\treturn c.remoteAddr\n', '\treturn c.remoteAddress()\n'),
    )),
    'common/bufio/bind_wait.go': ('779474cade3a2e9419ace0ea23eb255ebd555745', (
        ('\tw.remoteAddr = destination\n', '\tw.setRemoteAddr(destination)\n'),
    )),
}
PATCHES.update({name: (digest, (('UDPBufferSize = ' + size, 'UDPBufferSize = 65535'),))
                for name, (digest, size) in BUFFER_FILES.items()})

ASSOCIATION_FILES = {
    'protocol/socks/packet.go': ('583600cacce0cbdf96a63d27c2a95874c3341f55', (
        ('\t"bytes"\n\t"net"\n', '\t"bytes"\n\t"errors"\n\t"net"\n\t"sync"\n'),
        ('\tremoteAddr M.Socksaddr\n\tunderlying net.Conn\n',
         '\tremoteMu   sync.RWMutex\n\tremoteAddr M.Socksaddr\n\tunderlying net.Conn\n\tcontrol    *clientAssociationControl\n'),
        ('func (c *AssociatePacketConn) ReadFrom(', '''// Only a completed client UDP ASSOCIATE owns this control observer. Server
// and lazy-response constructors keep their existing handshake ownership.
// RFC 1928 ends the association when its TCP control connection terminates.
type clientAssociationControl struct {
	udp, tcp net.Conn
	once     sync.Once
	joined   chan struct{}
	err      error
}

func (c *clientAssociationControl) retire() {
	c.once.Do(func() {
		for _, conn := range []net.Conn{c.udp, c.tcp} {
			if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				c.err = errors.Join(c.err, err)
			}
		}
	})
}

func (c *clientAssociationControl) Close() error {
	c.retire()
	<-c.joined
	return c.err
}

func newClientAssociatePacketConn(conn net.Conn, remoteAddr M.Socksaddr, underlying net.Conn) *AssociatePacketConn {
	association := NewAssociatePacketConn(conn, remoteAddr, underlying)
	control := &clientAssociationControl{udp: conn, tcp: underlying, joined: make(chan struct{})}
	association.control = control
	go func() {
		defer close(control.joined)
		var unexpected [1]byte
		_, _ = underlying.Read(unexpected[:])
		control.retire()
	}()
	return association
}

// Copy the complete endpoint without holding its lock across packet I/O.
func (c *AssociatePacketConn) setRemoteAddress(address M.Socksaddr) {
	c.remoteMu.Lock()
	c.remoteAddr = address
	c.remoteMu.Unlock()
}

func (c *AssociatePacketConn) remoteAddress() M.Socksaddr {
	c.remoteMu.RLock()
	address := c.remoteAddr
	c.remoteMu.RUnlock()
	return address
}

func (c *AssociatePacketConn) ReadFrom('''),
        ('\tc.remoteAddr = destination\n\taddr = destination.UDPAddr()',
         '\tc.setRemoteAddress(destination)\n\taddr = destination.UDPAddr()'),
        ('\tc.remoteAddr = destination\n\treturn destination, nil',
         '\tc.setRemoteAddress(destination)\n\treturn destination, nil'),
        ('return c.WriteTo(b, c.remoteAddr)', 'return c.WriteTo(b, c.remoteAddress())'),
        ('return c.remoteAddr.UDPAddr()', 'return c.remoteAddress().UDPAddr()'),
        ('func (c *AssociatePacketConn) Close() error {\n\treturn common.Close(',
         'func (c *AssociatePacketConn) Close() error {\n\tif c.control != nil {\n\t\treturn c.control.Close()\n\t}\n\treturn common.Close('),
    )),
    'protocol/socks/packet_wait.go': ('ecf673acc8ffb99be71f271122d8bdddd6460a5b', (
        ('\tw.conn.remoteAddr = destination\n', '\tw.conn.setRemoteAddress(destination)\n'),
    )),
    'protocol/socks/client.go': ('ccfb6ae89e38771c96d2d3b7d065d26e3d70a545', (
        ('return NewAssociatePacketConn(udpConn, address, tcpConn), nil',
         'return newClientAssociatePacketConn(udpConn, address, tcpConn), nil'),
    )),
}
PATCHES.update(ASSOCIATION_FILES)


def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def transform(relative, data, reverse=False):
    if relative not in PATCHES:
        return data
    blob, edits = PATCHES[relative]
    if not reverse and git_blob(data) != blob:
        raise ValueError('Pinned sing packet boundary changed: ' + relative)
    for old, new in reversed(edits) if reverse else edits:
        source, target = (new, old) if reverse else (old, new)
        source, target = source.encode(), target.encode()
        if data.count(source) != 1:
            raise ValueError('Unexpected sing packet patch boundary: ' + relative)
        data = data.replace(source, target, 1)
    if reverse and git_blob(data) != blob:
        raise ValueError('Prepared sing packet source has unrelated changes: ' + relative)
    return data


def h1(rows):
    summary = ''.join(digest + '  ' + name + '\n' for name, digest in sorted(rows))
    return 'h1:' + base64.b64encode(hashlib.sha256(summary.encode()).digest()).decode()


def verify_tree(directory, allow_packet_only=False):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Prepared sing must be an owned directory')
    rows, total, upgrades = [], 0, {}
    for path in sorted(directory.rglob('*')):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ValueError('Prepared sing contains a linked or special entry')
        if path.is_dir():
            continue
        relative = path.relative_to(directory).as_posix()
        if '\n' in relative or '\r' in relative:
            raise ValueError('Invalid prepared sing path')
        total += path.stat().st_size
        if total > MAX_BYTES or len(rows) >= 5000:
            raise ValueError('Prepared sing exceeds source bounds')
        data = path.read_bytes()
        if allow_packet_only and relative in (BUFFER_FILES | ASSOCIATION_FILES) and git_blob(data) == PATCHES[relative][0]:
            # A prior owned copy may predate either complete fix group. Only
            # exact pristine files may be upgraded, and only after every group
            # and the entire module reverse to the original pinned checksum.
            if path.stat().st_nlink != 1:
                raise ValueError('Cannot upgrade an aliased native buffer file')
            original = data
            upgrades[relative] = transform(relative, data)
        else:
            original = transform(relative, data, reverse=True)
        rows.append((PREFIX + relative, hashlib.sha256(original).hexdigest()))
    if h1(rows) != SUM:
        raise ValueError('Prepared sing differs from its pinned module plus packet synchronization')
    for group in (BUFFER_FILES, ASSOCIATION_FILES):
        changed = set(upgrades).intersection(group)
        if changed and changed != set(group):
            raise ValueError('Prepared sing has a partial UDP capacity or association policy')
    return upgrades


def extract_verified(archive, target):
    rows, total, seen = [], 0, set()
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if not entries or len(entries) > 5000:
            raise ValueError('Invalid sing archive size')
        for entry in entries:
            name = entry.filename
            if not name.startswith(PREFIX):
                raise ValueError('sing archive has a foreign module prefix')
            relative = name[len(PREFIX):]
            parts = PurePosixPath(relative)
            if (not relative or str(parts) != relative or '\\' in relative or
                    '\n' in relative or '\r' in relative or '..' in parts.parts or
                    parts.is_absolute() or entry.is_dir() or
                    stat.S_ISLNK(entry.external_attr >> 16) or relative in seen):
                raise ValueError('Unsafe or duplicate sing archive member')
            seen.add(relative)
            total += entry.file_size
            if total > MAX_BYTES or entry.file_size > MAX_BYTES:
                raise ValueError('sing archive exceeds source bounds')
            data = source.read(entry)
            rows.append((name, hashlib.sha256(data).hexdigest()))
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(transform(relative, data))
        if h1(rows) != SUM:
            raise ValueError('Downloaded sing does not match the pinned h1 checksum')
    verify_tree(target)


def module_plan(vendor):
    plan = json.loads(subprocess.check_output(['go', 'mod', 'edit', '-json'], cwd=vendor, text=True))
    requirements = [r for r in plan.get('Require', []) if r['Path'] == MODULE]
    if len(requirements) != 1 or requirements[0]['Version'] != VERSION:
        raise ValueError('Packet synchronization requires the exact pinned sing version')
    replacements = [r for r in plan.get('Replace', []) or [] if r['Old']['Path'] == MODULE]
    expected = {'Old': {'Path': MODULE, 'Version': VERSION}, 'New': {'Path': './' + COPY}}
    if replacements and replacements != [expected]:
        raise ValueError('Refusing an unrelated sing replacement')


def prepare(vendor):
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != CORE:
        raise ValueError('Packet synchronization requires the exact disposable native core')
    module_plan(vendor)
    target = vendor / COPY
    if target.exists() or target.is_symlink():
        upgrades = verify_tree(target, allow_packet_only=True)
        for relative, data in upgrades.items():
            (target / relative).write_bytes(data)
        verify_tree(target)
    else:
        info = json.loads(subprocess.check_output(
            ['go', 'mod', 'download', '-json', MODULE + '@' + VERSION], cwd=vendor, text=True))
        if info.get('Path') != MODULE or info.get('Version') != VERSION or info.get('Sum') != SUM or info.get('Error'):
            raise ValueError('sing download metadata does not match the pinned module')
        with tempfile.TemporaryDirectory(prefix='.routervpn-sing-', dir=vendor) as temporary:
            staged = Path(temporary) / 'module'
            staged.mkdir()
            extract_verified(Path(info['Zip']), staged)
            staged.rename(target)
    subprocess.run(['go', 'mod', 'edit', '-replace=' + MODULE + '@' + VERSION + '=./' + COPY], cwd=vendor, check=True)
    print('Prepared checksum-verified sing UDP endpoints, joined SOCKS control ownership and complete ciphertext buffers:', VERSION)


def verify(vendor):
    vendor = vendor.resolve()
    module_plan(vendor)
    info = json.loads(subprocess.check_output(['go', 'list', '-m', '-json', MODULE], cwd=vendor, text=True))
    replacement = info.get('Replace') or {}
    if (info.get('Version') != VERSION or replacement.get('Path') != './' + COPY or
            Path(replacement.get('Dir', '')).resolve() != vendor / COPY):
        raise ValueError('Native core lost its verified local sing packet copy')
    verify_tree(vendor / COPY)
