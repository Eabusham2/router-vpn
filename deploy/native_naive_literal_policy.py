"""Retain captured Naive address/name and stream authority in one verified copy.

The native library and explicit DNS resolver remain unchanged. Derive the
wire hostname without an RFC 6066-forbidden terminal dot, preserving the caller's
original options. Map only its exact hostname to its original IPv6 literal.
Never edit the shared Go cache or accept an unrelated local module replacement.
"""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import json
import stat
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CORE = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
MODULE = 'github.com/sagernet/cronet-go'
VERSION = 'v0.0.0-20260912104727-0d28acc44093'
SUM = 'h1:CsvsLVIli53L6nzgEpyRjjWnRRhTds4D3eh5sEnF5Sw='
COPY = 'routervpn-patched-cronet'
PREFIX = MODULE+'@'+VERSION+'/'
SOURCE = 'naive_client.go'
SOURCE_SHA256 = '367a29cbc783270e07f00d28d77f6b463033805bf4e100b53100f9373bf0f5a5'
OLD = b'\tparamsError := params.SetAsyncDNS(true)\n'
NEW = (b'\trules, paramsError := routerVPNNaiveLiteralRule(c.serverAddress, c.serverName, c.quicEnabled)\n'
       b'\tif paramsError == nil && rules != "" {\n'
       b'\t\tparamsError = params.SetHostResolverRules(rules)\n\t}\n'
       b'\tif paramsError == nil {\n\t\tparamsError = params.SetAsyncDNS(true)\n\t}\n')
NAME_OLD = b'\tserverURL := &url.URL{\n'
NAME_NEW = (b'\tserverName, err = routerVPNNaiveWireName(serverName, config.QUIC)\n'
            b'\tif err != nil {\n\t\treturn nil, err\n\t}\n\n' + NAME_OLD)
DIAL_OLD = b'func (c *NaiveClient) DialEarly(ctx context.Context, destination M.Socksaddr) (NaiveConn, error) {\n'
DIAL_NEW = DIAL_OLD + (b'\tif err := errors.Join(ctx.Err(), c.ctx.Err()); err != nil {\n'
                       b'\t\treturn nil, err\n\t}\n')
OWNER_OLD = b'\tconn.setOnTerminate(trackedConn.release)\n\treturn trackedConn, nil\n'
OWNER_NEW = (b'\ttrackedConn.stopOwner = routerVPNNaiveStreamOwner(c.ctx, conn.Close)\n'
             b'\tconn.setOnTerminate(func() {\n\t\ttrackedConn.stopOwner()\n\t\ttrackedConn.release()\n\t})\n'
             b'\tif err := errors.Join(ctx.Err(), c.ctx.Err()); err != nil {\n'
             b'\t\t_ = trackedConn.Close()\n\t\treturn nil, err\n\t}\n'
             b'\treturn trackedConn, nil\n')
TRACKED_OLD = b'\tclient    *NaiveClient\n\tcloseOnce sync.Once\n'
TRACKED_NEW = TRACKED_OLD + b'\tstopOwner func()\n'
CLOSE_OLD = b'func (c *trackedNaiveConn) Close() error {\n\tc.release()\n'
CLOSE_NEW = b'func (c *trackedNaiveConn) Close() error {\n\tc.stopOwner()\n\tc.release()\n'
PATCHES = ((NAME_OLD, NAME_NEW), (OLD, NEW), (DIAL_OLD, DIAL_NEW),
           (OWNER_OLD, OWNER_NEW), (TRACKED_OLD, TRACKED_NEW), (CLOSE_OLD, CLOSE_NEW))
TEMPLATES = {'cronet_literal.go.tmpl':'routervpn_naive_literal.go',
             'cronet_literal_test.go.tmpl':'routervpn_naive_literal_test.go',
             'cronet_stream_owner.go.tmpl':'routervpn_naive_stream_owner.go',
             'cronet_stream_owner_test.go.tmpl':'routervpn_naive_stream_owner_test.go'}
MAX_BYTES = 32*1024*1024


def inputs():
    return [Path(__file__).resolve(), ROOT/'deploy/test_native_naive_literal_policy.py',
            *(ROOT/'mobile/naive'/name for name in TEMPLATES)]


def transform(relative, raw, *, reverse=False):
    if relative != SOURCE:
        return raw
    original = raw
    if reverse:
        for old, new in PATCHES:
            if original.count(new) != 1:
                raise ValueError('Native Cronet literal policy is absent or partial')
            original = original.replace(new, old, 1)
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256 or any(original.count(old) != 1 for old, _ in PATCHES):
        raise ValueError('Pinned Cronet engine startup differs')
    if reverse:
        return original
    for old, new in PATCHES:
        original = original.replace(old, new, 1)
    return original


def h1(rows):
    raw = ''.join(digest+'  '+name+'\n' for name, digest in sorted(rows)).encode()
    return 'h1:'+base64.b64encode(hashlib.sha256(raw).digest()).decode()


def helpers():
    result = {}
    for name, relative in TEMPLATES.items():
        path = ROOT/'mobile/naive'/name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Native Cronet literal helper lost its source authority')
        result[relative] = path.read_bytes()
    return result


def verify_tree(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Prepared Cronet must be an owned directory')
    generated = helpers()
    rows, records, total = [], {}, 0
    for path in sorted(directory.rglob('*')):
        if path.is_symlink() or not path.is_dir() and not path.is_file():
            raise ValueError('Prepared Cronet contains a linked or special entry')
        if path.is_dir():
            continue
        info = path.stat()
        if info.st_nlink != 1:
            raise ValueError('Prepared Cronet contains a shared source owner')
        name = path.relative_to(directory).as_posix()
        if '\n' in name or '\r' in name:
            raise ValueError('Invalid prepared Cronet path')
        total += info.st_size
        if total > MAX_BYTES or len(records) >= 5000:
            raise ValueError('Prepared Cronet exceeds source bounds')
        raw = path.read_bytes()
        if name in generated:
            if raw != generated[name]:
                raise ValueError('Prepared Cronet literal helper differs from its exact source')
        else:
            original = transform(name, raw, reverse=True)
            rows.append((PREFIX+name, hashlib.sha256(original).hexdigest()))
        records[name] = hashlib.sha256(raw).hexdigest()
    if not set(generated) <= records.keys() or SOURCE not in records or h1(rows) != SUM:
        raise ValueError('Prepared Cronet differs from its pinned whole-module checksum')
    return records


def extract_verified(archive, destination):
    rows, total, seen, files = [], 0, set(), {}
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if not entries or len(entries) > 5000:
            raise ValueError('Invalid Cronet archive size')
        for entry in entries:
            name = entry.filename
            if not name.startswith(PREFIX):
                raise ValueError('Cronet archive has a foreign module prefix')
            relative = name[len(PREFIX):]
            parts = PurePosixPath(relative)
            if (not relative or str(parts) != relative or '\\' in relative or '\n' in relative or '\r' in relative
                    or '..' in parts.parts or parts.is_absolute() or entry.is_dir()
                    or stat.S_ISLNK(entry.external_attr >> 16) or relative in seen or relative in TEMPLATES.values()):
                raise ValueError('Unsafe or duplicate Cronet archive member')
            seen.add(relative)
            total += entry.file_size
            if total > MAX_BYTES or entry.file_size > MAX_BYTES:
                raise ValueError('Cronet archive exceeds source bounds')
            raw = source.read(entry)
            rows.append((name, hashlib.sha256(raw).hexdigest()))
            files[relative] = transform(relative, raw)
    if SOURCE not in files or h1(rows) != SUM:
        raise ValueError('Downloaded Cronet does not match the pinned h1 checksum')
    files.update(helpers())
    # Validate the complete archive and transform before publishing any source.
    for name, raw in files.items():
        path = destination/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    verify_tree(destination)


def module_plan(vendor, *, required=False):
    plan = json.loads(subprocess.check_output(['go', 'mod', 'edit', '-json'], cwd=vendor, text=True))
    dependencies = [row for row in plan.get('Require', []) if row['Path'] == MODULE]
    if len(dependencies) != 1 or dependencies[0]['Version'] != VERSION:
        raise ValueError('Naive IPv6 policy requires the exact pinned Cronet version')
    replacements = [row for row in plan.get('Replace', []) or [] if row['Old']['Path'] == MODULE]
    expected = [{'Old': {'Path': MODULE, 'Version': VERSION}, 'New': {'Path': './'+COPY}}]
    if replacements and replacements != expected or required and replacements != expected:
        raise ValueError('Naive IPv6 policy refuses a missing or unrelated Cronet replacement')


def checked_vendor(vendor):
    vendor = Path(vendor).absolute()
    if vendor.is_symlink() or not vendor.is_dir():
        raise ValueError('Unsafe native Cronet checkout')
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != CORE:
        raise ValueError('Naive IPv6 policy requires the exact pinned native core')
    for name in ('go.mod', 'go.sum'):
        path = vendor/name
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError('Native Cronet dependency record is not owned')
    if not (vendor/'go.mod').read_bytes().startswith(b'module github.com/sagernet/sing-box\n'):
        raise ValueError('Native Cronet policy requires the original core module')
    return vendor


def prepare(vendor):
    vendor = checked_vendor(vendor)
    module_plan(vendor)
    target = vendor/COPY
    if target.exists() or target.is_symlink():
        verify_tree(target)
    else:
        info = json.loads(subprocess.check_output(['go', 'mod', 'download', '-json', MODULE+'@'+VERSION], cwd=vendor, text=True))
        if info.get('Path') != MODULE or info.get('Version') != VERSION or info.get('Sum') != SUM or info.get('Error'):
            raise ValueError('Cronet download metadata differs from the pinned module')
        with tempfile.TemporaryDirectory(prefix='.routervpn-cronet-', dir=vendor) as temporary:
            staged = Path(temporary)/'module'
            staged.mkdir()
            extract_verified(Path(info['Zip']), staged)
            staged.rename(target)
    subprocess.run(['go', 'mod', 'edit', '-replace='+MODULE+'@'+VERSION+'=./'+COPY], cwd=vendor, check=True)
    verify(vendor)


def verify(vendor):
    vendor = checked_vendor(vendor)
    module_plan(vendor, required=True)
    return {COPY+'/'+name:digest for name,digest in verify_tree(vendor/COPY).items()}
