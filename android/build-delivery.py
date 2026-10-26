#!/usr/bin/env python3
"""Stage CI-owned key material privately, build/verify, and always retire it."""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import signal
import re
import subprocess
import tempfile

PREFIX = 'ROUTERVPN_ANDROID_'


def archive_version(environment: dict, manifest: Path, expected_sha: str) -> None:
    data = json.loads(manifest.read_text())
    sha = expected_sha
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('Source archive requires its explicitly requested full source SHA')
    if (data.get('schema_version') != 1 or data.get('repository') != 'Eabusham2/router-vpn'
            or data.get('artifact_family') != 'exact-source-snapshot' or data.get('source_sha') != sha):
        raise ValueError('Source archive version receipt does not match the requested exact source')
    code = data.get('android_version_code')
    if type(code) is not int or not 2 <= code <= 2_100_000_000:
        raise ValueError('Source archive has no valid captured Android version code')
    environment[PREFIX + 'VERSION_SHA'] = sha
    environment[PREFIX + 'VERSION_CODE'] = str(code)
    environment['GITHUB_SHA'] = sha
    environment['ROUTER_VPN_SOURCE_SHA'] = sha


def build(root: Path, gradle: str, environment: dict) -> int:
    encoded = environment.pop(PREFIX + 'KEYSTORE_BASE64', '')
    if encoded and environment.get(PREFIX + 'KEYSTORE'):
        raise ValueError('Use exactly one production keystore input')
    with tempfile.TemporaryDirectory(prefix='routervpn-android-signing-', dir=environment.get('RUNNER_TEMP')) as temporary:
        if encoded:
            try:
                if len(encoded) > 2 * 1024 * 1024:
                    raise ValueError('Encoded keystore exceeds its limit')
                raw = base64.b64decode(encoded, validate=True)
                if not raw or len(raw) > 1024 * 1024:
                    raise ValueError('Decoded keystore exceeds its limit')
            except (ValueError, TypeError) as error:
                raise ValueError('Invalid encoded production keystore') from None
            key = Path(temporary) / 'signing.p12'
            with key.open('xb') as stream:
                os.chmod(key, 0o600)
                stream.write(raw)
            environment[PREFIX + 'KEYSTORE'] = str(key)
            del raw, encoded
        child = subprocess.Popen([gradle, '-p', str(root), '--no-daemon', '--no-configuration-cache', ':app:assembleDelivery'], env=environment)
        def stop(signum, frame):
            child.terminate()
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            raise SystemExit(128 + signum)
        handlers = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            return child.wait()
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            for sig, handler in handlers.items():
                signal.signal(sig, handler)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--gradle', default='gradle')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--source-manifest', type=Path)
    parser.add_argument('--source-sha')
    args = parser.parse_args()
    environment = dict(os.environ)
    if args.source_manifest:
        if not args.source_sha:
            parser.error('--source-manifest requires the independently requested --source-sha')
        archive_version(environment, args.source_manifest, args.source_sha)
    elif args.source_sha:
        parser.error('--source-sha is used only with a verified source snapshot manifest')
    return build(args.root, args.gradle, environment)


if __name__ == '__main__':
    raise SystemExit(main())
