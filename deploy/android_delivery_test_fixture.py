"""Synthetic archives for provenance/receipt rejection tests, not signing proof."""
import hashlib
import json
from pathlib import Path
import zipfile


def write_android_fixture(path: Path, sha: str, signing: str = 'debug-signed') -> None:
    certificate = 'c' * 64
    metadata = dict(schema_version=1, source_sha=sha, application_id='com.eabusham.routervpn',
                    version_code=42, version_name='0.1.42-' + sha[:12], variant='debug' if signing == 'debug-signed' else 'release',
                    signing=signing, certificate_sha256=certificate if signing == 'production-signed' else '')
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('classes.dex', b'synthetic provenance fixture')
        archive.writestr('assets/LICENSE', b'MIT synthetic provenance fixture')
        archive.writestr('assets/ROUTER-VPN-SOURCE.json', json.dumps(dict(schema_version=1,
                         repository='Eabusham2/router-vpn', artifact_family='android-apk', source_sha=sha)))
        archive.writestr('assets/ROUTER-VPN-ANDROID.json', json.dumps(metadata))
    receipt = dict(metadata, certificate_sha256=certificate, compatibility_asset='app-debug.apk',
                   label='Production-signed Android APK' if signing == 'production-signed' else 'Debug-signed Android APK — not a production signing identity',
                   apk_signature_verified=True, apk_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), apk_size=path.stat().st_size)
    (path.parent / 'android-delivery.json').write_text(json.dumps(receipt))
