#!/usr/bin/env python3
"""Verify the actual APK before publishing its compatibility asset/receipt."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('android_mobile_provenance', ROOT / 'server/scripts/mobile-artifact-provenance.py')
MOBILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOBILE)
MEMBER = 'assets/ROUTER-VPN-ANDROID.json'
COMPATIBILITY_ASSET = 'app-debug.apk'
LABELS = {
    'production-signed': 'Production-signed Android APK',
    'debug-signed': 'Debug-signed Android APK — not a production signing identity',
    'unsigned': 'Unsigned Android APK — signing is required before installation',
}


@contextmanager
def owned_apk(apk: Path, directory: Path | None = None):
    """All tool/provenance reads share one privately owned immutable copy."""
    with tempfile.TemporaryDirectory(prefix='routervpn-apk-verification-', dir=directory) as temporary:
        snapshot = Path(temporary) / 'captured.apk'
        with MOBILE._open_mobile_artifact(apk, 'Android APK') as original, snapshot.open('xb') as output:
            total = 0
            while block := original.read(1024 * 1024):
                total += len(block)
                if total > MOBILE.MAX_MOBILE_ARTIFACT:
                    raise ValueError('APK exceeded its bound during capture')
                output.write(block)
        os.chmod(snapshot, 0o400)
        yield snapshot


def delivery_metadata(apk: Path, sha: str) -> dict:
    with MOBILE._open_mobile_artifact(apk, 'Android APK') as stream, zipfile.ZipFile(stream) as archive:
        source = json.loads(MOBILE._read_member(archive, MOBILE.ANDROID_MEMBER))
        metadata = json.loads(MOBILE._read_member(archive, MEMBER))
        license_info = MOBILE._member(archive, 'assets/LICENSE')
        if not license_info.file_size:
            raise ValueError('APK license is missing')
    if source.get('schema_version') != 1 or source.get('repository') != 'Eabusham2/router-vpn' or source.get('artifact_family') != 'android-apk' or source.get('source_sha') != sha:
        raise ValueError('APK source identity does not match the requested release')
    if metadata.get('schema_version') != 1 or metadata.get('source_sha') != sha or metadata.get('application_id') != 'com.eabusham.routervpn':
        raise ValueError('APK Android delivery identity is invalid')
    code = metadata.get('version_code')
    if type(code) is not int or not 1 <= code <= 2_100_000_000:
        raise ValueError('APK version code is invalid')
    suffix = 'dev' if sha == 'development' else sha[:12]
    if sha != 'development' and not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('APK exact source SHA is invalid')
    if metadata.get('version_name') != f'0.1.{code}-{suffix}':
        raise ValueError('APK version name does not bind its source and version code')
    signing = metadata.get('signing')
    if signing not in LABELS or metadata.get('variant') != ('debug' if signing == 'debug-signed' else 'release'):
        raise ValueError('APK signing state and variant disagree')
    cert = metadata.get('certificate_sha256')
    if signing == 'production-signed':
        if sha == 'development' or not isinstance(cert, str) or not re.fullmatch('[0-9a-f]{64}', cert):
            raise ValueError('Production APK has no exact source or pinned certificate')
    elif cert != '':
        raise ValueError('Nonproduction APK claims a production certificate')
    return metadata


def verified_receipt(metadata: dict, badging: str, signing_output: str, signature_ok: bool,
                     variant: str, code: int, certificate: str, allow_unsigned: bool) -> dict:
    package = re.search(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']*)'", badging, re.M)
    if package is None or package.groups() != ('com.eabusham.routervpn', str(code), metadata['version_name']):
        raise ValueError('Actual APK package/version differs from its captured build identity')
    if metadata['version_code'] != code or metadata['variant'] != variant:
        raise ValueError('APK metadata differs from the requested version/variant')
    debuggable = 'application-debuggable' in badging.splitlines()
    if debuggable != (variant == 'debug'):
        raise ValueError('Actual APK debuggability differs from its declared variant')
    digests = re.findall(r'^Signer #[0-9]+ certificate SHA-256 digest: ([0-9a-fA-F]{64})\s*$', signing_output, re.M)
    signing = metadata['signing']
    if signing == 'unsigned':
        if not allow_unsigned or certificate or signature_ok or digests:
            raise ValueError('Unsigned APK is not authorized for this delivery')
        actual_certificate = ''
    else:
        if not signature_ok or len(digests) != 1:
            raise ValueError('Actual APK signature is invalid or has an unsupported signer set')
        actual_certificate = digests[0].lower()
        if signing == 'production-signed':
            if not re.fullmatch('[0-9a-f]{64}', certificate) or actual_certificate != certificate or metadata['certificate_sha256'] != certificate:
                raise ValueError('Actual APK signer does not match the explicitly pinned production certificate')
        elif certificate:
            raise ValueError('A debug APK cannot satisfy requested production signing')
    return dict(metadata, certificate_sha256=actual_certificate, label=LABELS[signing],
                compatibility_asset=COMPATIBILITY_ASSET, apk_signature_verified=signature_ok)


def verify(apk: Path, sdk: Path, sha: str, variant: str, code: int,
           certificate: str = '', allow_unsigned: bool = False) -> dict:
    with owned_apk(apk) as snapshot:
        return _verify_snapshot(snapshot, sdk, sha, variant, code, certificate, allow_unsigned)


def _verify_snapshot(apk: Path, sdk: Path, sha: str, variant: str, code: int,
                     certificate: str, allow_unsigned: bool) -> dict:
    with apk.open('rb') as stream:
        captured_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    metadata = delivery_metadata(apk, sha)
    tools = sdk / 'build-tools/36.0.0'
    aapt, apksigner = tools / 'aapt', tools / 'apksigner'
    if not aapt.is_file() or not apksigner.is_file():
        raise ValueError('Pinned Android build-tools 36.0.0 are required for APK verification')
    badging = subprocess.run([str(aapt), 'dump', 'badging', str(apk)], check=True,
                             capture_output=True, text=True, timeout=60).stdout
    signatures = subprocess.run([str(apksigner), 'verify', '--verbose', '--print-certs', str(apk)],
                                capture_output=True, text=True, timeout=60)
    result = verified_receipt(metadata, badging, signatures.stdout, signatures.returncode == 0,
                              variant, code, certificate, allow_unsigned)
    with apk.open('rb') as stream:
        result['apk_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    if result['apk_sha256'] != captured_digest:
        raise ValueError('Owned APK snapshot changed during signature verification')
    result['apk_size'] = apk.stat().st_size
    return result


def stage(apk: Path, output: Path, receipt: dict) -> None:
    if receipt['signing'] == 'unsigned' or not receipt['apk_signature_verified']:
        raise ValueError('An unsigned APK cannot enter automatic delivery')
    if output.is_symlink():
        raise ValueError('APK delivery directory is redirected')
    output.mkdir(parents=True, exist_ok=True)
    destination = output / COMPATIBILITY_ASSET
    if destination.is_symlink() or (output / 'android-delivery.json').is_symlink():
        raise ValueError('APK delivery output is redirected')
    # This basename is a published compatibility contract used by existing
    # clients and Setup Center. The actual variant/signing label is explicit.
    with owned_apk(apk, output) as captured:
        with captured.open('rb') as stream:
            copied_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if copied_digest != receipt['apk_sha256'] or captured.stat().st_size != receipt['apk_size']:
            raise ValueError('Delivered APK changed after signature verification')
        owned = captured.stat()
        os.chmod(captured, 0o644)
        os.replace(captured, destination)
        if not os.path.samestat(owned, destination.stat()):
            raise ValueError('Android delivery adoption changed the captured file identity')
    (output / 'android-delivery.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')


def load_receipt(apk: Path, sha: str) -> dict:
    """Bind the verifier's public receipt to the exact bytes being published."""
    with owned_apk(apk) as captured:
        metadata = delivery_metadata(captured, sha)
        with captured.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        size = captured.stat().st_size
    receipt_path = apk.parent / 'android-delivery.json'
    if receipt_path.is_symlink() or not receipt_path.is_file() or not 0 < receipt_path.stat().st_size <= 65536:
        raise ValueError('Android delivery verification receipt is missing or redirected')
    receipt = json.loads(receipt_path.read_text())
    expected_fields = set(metadata) | {'label', 'compatibility_asset', 'apk_signature_verified', 'apk_sha256', 'apk_size'}
    if not isinstance(receipt, dict) or set(receipt) != expected_fields:
        raise ValueError('Android delivery receipt has an unexpected schema')
    for key, value in metadata.items():
        if key != 'certificate_sha256' and receipt.get(key) != value:
            raise ValueError('Android delivery receipt differs from the embedded APK metadata')
    certificate = receipt.get('certificate_sha256', '')
    if (receipt.get('apk_signature_verified') is not True or metadata['signing'] == 'unsigned'
            or not isinstance(certificate, str) or not re.fullmatch('[0-9a-f]{64}', certificate)
            or receipt.get('compatibility_asset') != COMPATIBILITY_ASSET
            or receipt.get('label') != LABELS[metadata['signing']]):
        raise ValueError('Android delivery receipt does not prove a signed labeled package')
    if metadata['signing'] == 'production-signed' and certificate != metadata['certificate_sha256']:
        raise ValueError('Android delivery receipt changed the production signing identity')
    if receipt.get('apk_sha256') != digest or receipt.get('apk_size') != size:
        raise ValueError('Android delivery receipt belongs to different APK bytes')
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--apk', required=True, type=Path)
    parser.add_argument('--sdk', required=True, type=Path)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--variant', required=True, choices=['debug', 'release'])
    parser.add_argument('--version-code', required=True, type=int)
    parser.add_argument('--certificate', default='')
    parser.add_argument('--allow-unsigned', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    receipt = verify(args.apk, args.sdk, args.sha, args.variant, args.version_code, args.certificate, args.allow_unsigned)
    if args.output:
        stage(args.apk, args.output, receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
