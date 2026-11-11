#!/usr/bin/env python3
"""Backport Go's exact Winsock temporary-socket close fix into an owned copy.

Go 1.26.3's ConnectEx and WSASendMsg extension loaders use CloseHandle on a
socket. This leaves Winsock's provider entry behind when its kernel handle is
reused, so a later IPv6 duplicate can report the old IPv4 protocol. Upstream
fixed both production sites in the commit below. Keep the pinned compiler and
all application ownership checks; change only those two close primitives.

The selected original GOROOT is never changed. Both whole-file preimages must
match the official go1.26.3 tag before a private toolchain copy is published.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = 'go1.26.3'
UPSTREAM = '00be0f2640a11f9964c11836fe3c64be29d32f1a'
UPSTREAM_URL = 'https://go.googlesource.com/go/+/' + UPSTREAM
RECEIPT = 'ROUTERVPN-WINDOWS-SOCKETS.json'
# Independently verified against https://go.googlesource.com/go/+/go1.26.3/.
# This is the complete production portion of the upstream change. Its third
# change is only to an internal/poll test helper, not shipping compiler input.
PATCHES = (
    ('src/syscall/syscall_windows.go',
     'f1b22dde6bb980cf036561cee7ece968daa260cb622f32c96cebd52477b7a346',
     '080dafa81317a12d6b2d23579057195b125edfbf1bd050916e1cd2588b6b3810',
     b'\t\tdefer CloseHandle(s)\n', b'\t\tdefer Closesocket(s)\n'),
    ('src/internal/syscall/windows/syscall_windows.go',
     'bd17d11ec16f619351a85040109b5324a4d7ca1a168cacd398002acfa5fd7611',
     'bd82c4110ae91a34898ec29ca81b307346579cee79f448b710e329c17f18f633',
     b'\t\tdefer syscall.CloseHandle(s)\n', b'\t\tdefer syscall.Closesocket(s)\n'),
)


def receipt():
    return {'schema': 1, 'toolchain': TOOLCHAIN, 'upstream_commit': UPSTREAM,
            'upstream_url': UPSTREAM_URL,
            'files': {name: {'original_sha256': before, 'patched_sha256': after}
                      for name, before, after, _, _ in PATCHES}}


def receipt_bytes():
    return (json.dumps(receipt(), sort_keys=True, indent=2) + '\n').encode()


def identity():
    return hashlib.sha256(receipt_bytes()).hexdigest()


def regular(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Windows Go socket backport requires a regular file: ' + str(path))
    return path.read_bytes()


def version(root):
    lines = regular(root / 'VERSION').splitlines()
    if not lines or lines[0] != TOOLCHAIN.encode():
        raise ValueError('Windows Go socket backport requires the exact Go 1.26.3 source')


def patched_sources(root):
    """Read and validate every input before any destination is created."""
    version(root)
    result = {}
    for name, before, after, old, new in PATCHES:
        raw = regular(root / name)
        if hashlib.sha256(raw).hexdigest() != before or raw.count(old) != 1:
            raise ValueError('Windows Go socket backport preimage differs: ' + name)
        changed = raw.replace(old, new, 1)
        if hashlib.sha256(changed).hexdigest() != after:
            raise ValueError('Windows Go socket backport postimage differs: ' + name)
        result[name] = changed
    return result


def verify(root):
    version(root)
    if regular(root / RECEIPT) != receipt_bytes():
        raise ValueError('Windows Go socket backport identity differs')
    for name, _, after, _, _ in PATCHES:
        if hashlib.sha256(regular(root / name)).hexdigest() != after:
            raise ValueError('Windows Go socket backport source changed: ' + name)
    return root


def prepare_root(original, output):
    original, output = Path(original).resolve(strict=True), Path(output).absolute()
    if (original / RECEIPT).exists():
        return verify(original)
    changed = patched_sources(original)
    if output.is_symlink():
        raise ValueError('Windows Go socket backport output is linked')
    if output.exists():
        return verify(output)
    if output.resolve().is_relative_to(original):
        raise ValueError('Windows Go socket backport cannot modify the original toolchain')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.go-windows-sockets-', dir=output.parent) as temp:
        stage = Path(temp) / 'go'
        shutil.copytree(original, stage)
        for name, raw in changed.items():
            path = stage / name
            # A downloaded toolchain's source may be read-only. Only this
            # build-owned copy is made writable; the original stays intact.
            path.chmod(path.stat().st_mode | 0o200)
            path.write_bytes(raw)
        (stage / RECEIPT).write_bytes(receipt_bytes())
        verify(stage)
        os.replace(stage, output)
    return verify(output)


def environment(go='go', env=None, output=None, require_prepared=False):
    selected = dict(os.environ if env is None else env)
    # Ask the selected compiler, including an already pinned GOTOOLCHAIN,
    # which source it will compile. Never guess a runner's toolcache path.
    info = json.loads(subprocess.check_output(
        [str(go), 'env', '-json', 'GOVERSION', 'GOROOT'], env=selected,
        text=True, timeout=120))
    if info.get('GOVERSION') != TOOLCHAIN or not info.get('GOROOT'):
        raise ValueError('Windows Go socket backport selected another compiler')
    original = Path(info['GOROOT'])
    # The live image's bounded component fallback may only use the compiler
    # already prepared during image creation; it never patches a host SDK.
    root = verify(original) if require_prepared else prepare_root(
        original, output or ROOT / '.deps' / ('go-windows-sockets-' + identity()[:16]))
    compiler = root / 'bin' / ('go.exe' if os.name == 'nt' else 'go')
    if not compiler.is_file() or compiler.is_symlink():
        raise ValueError('Windows Go socket backport lost its selected compiler')
    selected['GOROOT'] = str(root)
    selected['GOTOOLCHAIN'] = 'local'
    path_keys = [key for key in selected if key == 'PATH' or (os.name == 'nt' and key.upper() == 'PATH')]
    if len(path_keys) > 1:
        raise ValueError('Windows Go socket backport has ambiguous executable search paths')
    ambient_path = selected.pop(path_keys[0]) if path_keys else os.defpath
    compiler_path = str(root / 'bin')
    selected['PATH'] = ambient_path if ambient_path.split(os.pathsep)[0] == compiler_path else compiler_path + os.pathsep + ambient_path
    selected['ROUTERVPN_GO_WINDOWS_SOCKETS_SHA256'] = identity()
    actual = json.loads(subprocess.check_output(
        [str(compiler), 'env', '-json', 'GOVERSION', 'GOROOT'], env=selected,
        text=True, timeout=30))
    if actual.get('GOVERSION') != TOOLCHAIN or Path(actual.get('GOROOT', '')).resolve() != root.resolve():
        raise ValueError('Windows Go socket backport compiler changed its owned source')
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--github-env', action='store_true')
    args = parser.parse_args()
    selected = environment(args.go, output=args.output)
    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_bytes(receipt_bytes())
    if args.github_env:
        for name in ('GOROOT', 'GOTOOLCHAIN', 'ROUTERVPN_GO_WINDOWS_SOCKETS_SHA256'):
            value = selected[name]
            if any(c in value for c in '\r\n\0'):
                raise ValueError('Windows Go socket backport export contains a separator')
        with Path(os.environ['GITHUB_ENV']).open('a', encoding='utf-8') as stream:
            for name in ('GOROOT', 'GOTOOLCHAIN', 'ROUTERVPN_GO_WINDOWS_SOCKETS_SHA256'):
                stream.write(name + '=' + selected[name] + '\n')
        with Path(os.environ['GITHUB_PATH']).open('a', encoding='utf-8') as stream:
            stream.write(str(Path(selected['GOROOT']) / 'bin') + '\n')
    print(json.dumps({'toolchain': TOOLCHAIN, 'patch_sha256': identity(),
                      'upstream_commit': UPSTREAM, 'goroot': selected['GOROOT']}, sort_keys=True))


if __name__ == '__main__':
    main()
