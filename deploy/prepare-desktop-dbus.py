#!/usr/bin/env python3
"""Project exact godbus v5.2.2 native descriptor decoding/ownership fixes."""
from pathlib import Path
import hashlib
import base64
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'github.com/godbus/dbus/v5'
VERSION = 'v5.2.2'
SUM = 'h1:TUR3TgtSVDmjiXOgAAyaZbYmIeP3DPkld3jgKGV8mXQ='
SOURCE = {
    'decoder.go': '685d1a896e5a8e78e7db087f8dfb6c1bcbaa88da102d6d96f808d1fccf5fa9ac',
    'transport_unix.go': '9bb67dbc366358493ee8d4786d0154e99ccd8f9b5c275e4a5c2ef8c6abc45371',
}
TEMPLATES = ('godbus_fd_types.go.tmpl', 'godbus_unix_fd_owner.go.tmpl', 'godbus_unix_fd_owner_test.go.tmpl')

def once(raw, before, after):
    if raw.count(before) != 1:
        raise ValueError('Pinned godbus descriptor boundary changed: '+before[:100].decode())
    return raw.replace(before, after, 1)

def project(name, raw):
    if name not in SOURCE:
        return raw
    if hashlib.sha256(raw).hexdigest() != SOURCE[name]:
        raise ValueError('Pinned godbus source changed: '+name)
    if name == 'decoder.go':
        if raw.count(b'typeFor(') != 5:
            raise ValueError('Pinned godbus container type boundaries changed')
        raw = raw.replace(b'typeFor(', b'dec.routervpnTypeFor(')
        raw = once(raw, b'''\t\tv := recover()
\t\tif err, ok = v.(error); ok {''', b'''\t\tv := recover()
\t\tif v != nil { if _, isError := v.(error); !isError { err = FormatError("invalid decoded D-Bus container"); return } }
\t\tif err, ok = v.(error); ok {''')
        raw = once(raw, b'''\t\tif int(idx) < len(dec.fds) {
\t\t\treturn UnixFD(dec.fds[idx])
\t\t}
\t\treturn UnixFDIndex(idx)''', b'''\t\tif len(dec.fds) != 0 {
\t\t\tif int(idx) >= len(dec.fds) { panic(FormatError("invalid original Unix FD index")) }
\t\t\treturn UnixFD(dec.fds[idx])
\t\t}
\t\treturn UnixFDIndex(idx)''')
    else:
        raw = once(raw, b'\toob  []byte\n', b'\toob  []byte\n\troutervpnRights []int\n')
        raw = once(raw, b'''\tn, oobn, flags, _, err := o.conn.ReadMsgUnix(b, o.buf[:])
\tif err != nil {''', b'''\tn, oobn, flags, _, err := o.conn.ReadMsgUnix(b, o.buf[:])
\tif captureErr := o.routervpnCaptureRights(o.buf[:oobn]); captureErr != nil { return n, captureErr }
\tif err != nil {''')
        raw = once(raw, b'''\tvar (
\t\tr   = t.rdr.r''', b'''\ttransferred := false
\tdefer func() { if !transferred { t.rdr.routervpnCloseRights() }; t.rdr.routervpnRights = nil }()
\tvar (
\t\tr   = t.rdr.r''')
        raw = once(raw, b'''\tif unixfds != 0 {
\t\tif !t.hasUnixFDs {''', b'''\tif int(unixfds) != len(t.rdr.routervpnRights) { return nil, InvalidMessageError("Unix FD count differs from received native descriptors") }
\tif unixfds != 0 {
\t\tif !t.hasUnixFDs {''')
        raw = once(raw, b'''\t\treturn msg, nil
\t}

\tdec.Reset''', b'''\t\tif !routervpnAllRightsUsed(msg.Body, t.rdr.routervpnRights) { return nil, InvalidMessageError("received Unix FD omitted from decoded body") }
\t\ttransferred = true
\t\treturn msg, nil
\t}

\tdec.Reset''')
        raw = once(raw, b'''\treturn msg, nil
}

func decodeMessageBody''', b'''\ttransferred = true
\treturn msg, nil
}

func decodeMessageBody''')
    return raw

def pinned_files(source):
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise ValueError('Pinned godbus source is not an original module directory')
    files = {}
    digest = hashlib.sha256()
    # Go dirhash sorts canonical slash filenames case-sensitively. Native
    # WindowsPath ordering folds case and would hash the same bytes differently.
    for path in sorted(source.rglob('*'), key=lambda item: item.relative_to(source).as_posix()):
        if path.is_symlink():
            raise ValueError('Linked godbus source')
        if path.is_file():
            relative = path.relative_to(source).as_posix()
            if '\n' in relative:
                raise ValueError('Invalid godbus source filename')
            raw = path.read_bytes()
            files[relative] = raw
            digest.update((hashlib.sha256(raw).hexdigest()+'  '+MODULE+'@'+VERSION+'/'+relative+'\n').encode())
    if 'h1:'+base64.b64encode(digest.digest()).decode() != SUM:
        raise ValueError('Complete pinned godbus module checksum changed')
    return files

def expected_files(source):
    expected = {name: project(name, raw) for name,raw in pinned_files(source).items()}
    for name in TEMPLATES:
        path = ROOT/'mobile'/'desktop'/name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Missing original godbus projection template')
        expected['routervpn_'+name.removeprefix('godbus_').removesuffix('.tmpl')] = path.read_bytes()
    return expected

def verify(vendor, go='go'):
    """Read-only complete projection verification; never download or reprepare."""
    vendor = Path(vendor).resolve()
    cache = subprocess.check_output([go,'env','GOMODCACHE'],cwd=vendor,text=True,timeout=30).strip()
    expected = expected_files(Path(cache)/(MODULE+'@'+VERSION))
    dependency = vendor/'routervpn-desktop-dbus'
    if dependency.is_symlink() or not dependency.is_dir():
        raise ValueError('Missing original prepared godbus module')
    observed = {}
    for path in sorted(dependency.rglob('*')):
        if path.is_symlink():
            raise ValueError('Linked prepared godbus source')
        if path.is_file():
            observed[path.relative_to(dependency).as_posix()] = path.read_bytes()
    if observed != expected:
        raise ValueError('Prepared godbus differs from complete pinned descriptor projection')
    metadata = json.loads(subprocess.check_output([go,'mod','edit','-json'],cwd=vendor,text=True,timeout=30))
    replacements = [r for r in metadata.get('Replace',[]) if r['Old']['Path']==MODULE]
    if len(replacements)!=1 or replacements[0]['Old'].get('Version','')!='' or replacements[0]['New'] != {'Path':'./routervpn-desktop-dbus'}:
        raise ValueError('Parent module does not bind the original prepared godbus source')
    records = {'routervpn-desktop-dbus/'+name:hashlib.sha256(raw).hexdigest() for name,raw in expected.items()}
    records['gate/deploy/prepare-desktop-dbus.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    for name in TEMPLATES:
        records['gate/mobile/desktop/'+name] = hashlib.sha256((ROOT/'mobile'/'desktop'/name).read_bytes()).hexdigest()
    return records

def prepare(vendor):
    vendor = Path(vendor).resolve()
    module = json.loads(subprocess.check_output(['go', 'mod', 'download', '-json', MODULE+'@'+VERSION], cwd=vendor, text=True))
    expected = [line.split()[2] for line in (vendor/'go.sum').read_text().splitlines() if line.startswith(MODULE+' '+VERSION+' ')]
    if expected != [SUM] or module.get('Sum') != SUM or module.get('Version') != VERSION:
        raise ValueError('Desktop resolver requires exact checksum-pinned godbus v5.2.2')
    source = Path(module['Dir']).resolve()
    expected_projection = expected_files(source)
    destination = vendor/'routervpn-desktop-dbus'
    if destination.is_symlink():
        raise ValueError('Linked prepared godbus module')
    for name,raw in expected_projection.items():
        target = destination/name
        if target.is_symlink() or not target.parent.resolve().is_relative_to(vendor):
            raise ValueError('Prepared godbus source escaped checkout')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    subprocess.run(['go', 'mod', 'edit', '-replace='+MODULE+'=./routervpn-desktop-dbus'], cwd=vendor, check=True)
    verify(vendor)
    return destination

if __name__ == '__main__':
    import sys
    prepare(Path(sys.argv[1]))
