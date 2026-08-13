#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BROKER = ROOT / "server/scripts/download-broker.py"
PUBLISH = ROOT / "server/scripts/publish-downloads.sh"


def patch_broker() -> bool:
    text = BROKER.read_text(encoding="utf-8")
    changed = False

    if 'native_artifact_policy.py' not in text:
        pattern = re.compile(r'DIRECT_ARTIFACTS = \{.*?\n\}\n\nMAX_GITHUB_ARTIFACT', re.S)
        replacement = '''_policy_spec = spec_from_file_location("router_vpn_native_artifact_policy", SCRIPT_DIR / "native_artifact_policy.py")
if _policy_spec is None or _policy_spec.loader is None:
    raise RuntimeError("cannot load native_artifact_policy.py")
_artifact_policy = module_from_spec(_policy_spec)
_policy_spec.loader.exec_module(_artifact_policy)
NATIVE_PACKAGE_ARTIFACTS = _artifact_policy.NATIVE_PACKAGE_ARTIFACTS
DIRECT_ARTIFACTS = _artifact_policy.DIRECT_ARTIFACTS

MAX_GITHUB_ARTIFACT'''
        text2, n = pattern.subn(replacement, text, count=1)
        if n != 1:
            raise RuntimeError("download-broker DIRECT_ARTIFACTS block changed unexpectedly")
        text = text2
        changed = True

    old = '''def fetch_github_package(home_name: str, temp: Path) -> Path:
    generic = _builder.generic_name(home_name)
    if not generic:
        raise RuntimeError("this download has no generic GitHub package")
    artifact_name = os.environ.get("ROUTER_VPN_GITHUB_ARTIFACT", "RouterVPN-client-desktop-unix-ci").strip()
    return fetch_artifact_member(artifact_name, generic, temp, generic)


def fetch_direct_mobile(name: str, temp: Path) -> Path:
    spec = DIRECT_ARTIFACTS[name]
    try:
        return fetch_artifact_member(spec["artifact"], spec["member"], temp, name)
    except Exception as exc:
        raise RuntimeError(
            f"{name} requires its same-SHA GitHub mobile artifact; the Linux home node does not fake a platform-specific mobile build fallback: {exc}"
        ) from exc
'''
    new = '''def _fetch_first_artifact(sources, temp: Path, output_name: str) -> Path:
    failures = []
    for artifact_name, wanted in sources:
        try:
            return fetch_artifact_member(str(artifact_name), str(wanted), temp, output_name)
        except Exception as exc:
            failures.append(f"{artifact_name}: {type(exc).__name__}: {exc}")
    raise RuntimeError("; ".join(failures) if failures else "no GitHub artifact sources configured")


def fetch_github_package(home_name: str, temp: Path) -> Path:
    generic = _builder.generic_name(home_name)
    if not generic:
        raise RuntimeError("this download has no generic GitHub package")
    override = os.environ.get("ROUTER_VPN_GITHUB_ARTIFACT", "").strip()
    if override:
        sources = ((override, generic),)
    else:
        sources = NATIVE_PACKAGE_ARTIFACTS.get(home_name, (("RouterVPN-client-desktop-unix-ci", generic),))
    return _fetch_first_artifact(sources, temp, generic)


def fetch_direct_mobile(name: str, temp: Path) -> Path:
    spec = DIRECT_ARTIFACTS[name]
    try:
        return _fetch_first_artifact(spec["sources"], temp, name)
    except Exception as exc:
        raise RuntimeError(
            f"{name} requires its same-SHA GitHub mobile artifact; the Linux home node does not fake a platform-specific mobile build fallback: {exc}"
        ) from exc
'''
    if old in text:
        text = text.replace(old, new, 1)
        changed = True
    elif '_fetch_first_artifact' not in text or 'NATIVE_PACKAGE_ARTIFACTS.get(home_name' not in text:
        raise RuntimeError("download-broker GitHub fetch functions changed unexpectedly")

    if changed:
        BROKER.write_text(text, encoding="utf-8")
    return changed


def patch_publish() -> bool:
    text = PUBLISH.read_text(encoding="utf-8")
    original = text
    text = text.replace('  "$OUT"/router-vpn-ios-preview.ipa \\\n', '  "$OUT"/router-vpn-ios-preview.ipa \\\n  "$OUT"/router-vpn-ios.ipa \\\n')
    text = text.replace(
        "['iOS/iPadOS preview IPA','router-vpn-ios-preview.ipa','Unsigned re-signable same-SHA generic preview; Packet Tunnel engines are intentionally unavailable'],",
        "['iOS/iPadOS native WireGuard IPA','router-vpn-ios.ipa','Unsigned re-signable same-SHA native WireGuard PacketTunnel build'],",
    )
    text = text.replace("'router-vpn-android.apk','router-vpn-ios-preview.ipa','router-vpn-client-bundle.zip'", "'router-vpn-android.apk','router-vpn-ios.ipa','router-vpn-client-bundle.zip'")
    text = text.replace(
        'Desktop/Portable: matching same-SHA GitHub CI artifact first, then router-side build of only the requested generic Go client package if unavailable. Android/iOS: matching same-SHA GitHub mobile artifact; the Linux home node does not fake platform-specific mobile builds. ',
        'Desktop/Portable: matching same-SHA release/native GitHub artifact first, then router-side build of only the requested generic Go client package if unavailable. Android/iOS: matching same-SHA native GitHub artifact only; the Linux home node does not fake platform-specific mobile builds. ',
    )
    if text != original:
        PUBLISH.write_text(text, encoding="utf-8")
        return True
    return False


def main() -> int:
    changed = []
    if patch_broker(): changed.append("download-broker.py")
    if patch_publish(): changed.append("publish-downloads.sh")
    print("native download wiring changed:", ", ".join(changed) if changed else "nothing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
