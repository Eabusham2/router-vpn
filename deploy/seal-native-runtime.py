#!/usr/bin/env python3
"""Sign a verified macOS native engine and atomically seal the resulting bytes.

Verification precedes signing. This command cannot bless a payload that has
already changed: only its own successful codesign operation may alter it.
"""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_sign_build', ROOT/'deploy/build-native-runtime.py')
BUILD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BUILD)


def seal(directory, target, identity='-'):
    if target not in ('darwin/amd64', 'darwin/arm64'):
        raise ValueError('Only macOS code signing may reseal the native engine')
    if not identity or len(identity) > 1024 or any(ord(c) < 32 for c in identity):
        raise ValueError('Invalid macOS signing identity')
    original = BUILD.reuse(directory, target)
    temporary = Path(tempfile.mkdtemp(prefix='.native-sign-', dir=directory.parent))
    retained = False
    try:
        stage = temporary/'signed'
        shutil.copytree(directory, stage, symlinks=True)
        binary = stage/BUILD.binary_name(target)
        flags = ['--timestamp=none'] if identity == '-' else ['--options', 'runtime', '--timestamp']
        subprocess.run(['codesign', '--force', '--sign', identity, *flags, str(binary)], check=True, timeout=120)
        subprocess.run(['codesign', '--verify', '--strict', str(binary)], check=True, timeout=20)
        tor = stage/BUILD.TOR.VERIFY.binary_name(target)
        subprocess.run(['codesign', '--force', '--sign', identity, *flags, str(tor)], check=True, timeout=120)
        subprocess.run(['codesign', '--verify', '--strict', str(tor)], check=True, timeout=20)
        tor_record = BUILD.TOR.VERIFY.SERVER.json_object((stage/BUILD.TOR.VERIFY.RECEIPT).read_bytes())
        tor_raw = BUILD.regular(tor, BUILD.TOR.VERIFY.MAX_BINARY)
        tor_record['files'][tor.name] = BUILD.payload(tor_raw)
        tor_record['executable_identity'] = BUILD.TOR.VERIFY.executable_identity(tor_raw, target)
        (stage/BUILD.TOR.VERIFY.RECEIPT).write_text(json.dumps(tor_record, sort_keys=True, indent=2)+'\n')
        BUILD.check_target(binary, target, BUILD.environment(target))
        raw = BUILD.regular(binary, BUILD.MAX_BINARY)
        if BUILD.marker(BUILD.digest()).encode() not in raw:
            raise ValueError('Signed native source identity changed')
        sealed = {**original, **BUILD.payload(raw), 'files': dict(original['files'])}
        sealed['files'][binary.name] = BUILD.payload(raw)
        for name in (tor.name, BUILD.TOR.VERIFY.RECEIPT):
            sealed['files'][name] = BUILD.payload(BUILD.regular(stage/name, BUILD.payload_bound(name, target)))
        (stage/'NATIVE-RUNTIME.json').write_text(json.dumps(sealed, sort_keys=True, indent=2)+'\n')
        # Checks every unchanged library/license, all provenance fields, target
        # and tags as well as the newly signed binary's exact size and digest.
        BUILD.reuse(stage, target)
        if BUILD.reuse(directory, target) != original:
            raise ValueError('Original native bundle changed during signing')
        backup = temporary/'original'
        os.replace(directory, backup)
        try:
            os.replace(stage, directory)
        except BaseException:
            try:
                os.replace(backup, directory)
            except BaseException as rollback:
                # Never let temporary-directory cleanup destroy the last
                # verified original when the filesystem refuses restoration.
                retained = True
                raise RuntimeError('Native signing rollback failed; original recovery retained at '+str(backup)) from rollback
            raise
    finally:
        if not retained:
            shutil.rmtree(temporary)
    print('Signed and sealed complete native runtime '+target, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('target', choices=('darwin/amd64', 'darwin/arm64'))
    parser.add_argument('--identity', default='-')
    args = parser.parse_args()
    seal(args.directory, args.target, args.identity)
