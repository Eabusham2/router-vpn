#!/usr/bin/env python3
"""Verify source identity embedded inside Router VPN mobile artifacts."""
from __future__ import annotations

import argparse
import json
import os
import plistlib
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_PROVENANCE = 64 << 10
MAX_MOBILE_ARTIFACT = 768 << 20
MAX_ZIP_MEMBERS = 200_000
MAX_COMPRESSION_RATIO = 200

ANDROID_MEMBER = "assets/ROUTER-VPN-SOURCE.json"
IOS_APP_INFO = "Payload/RouterVPN.app/Info.plist"
IOS_TUNNEL_INFO = "Payload/RouterVPN.app/PlugIns/RouterVPNPacketTunnel.appex/Info.plist"


def _open_mobile_artifact(path: Path, label: str):
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"{label} is missing") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"{label} is redirected or not a regular file")
    if before.st_size <= 0 or before.st_size > MAX_MOBILE_ARTIFACT:
        raise RuntimeError(f"{label} is empty or oversized")
    try:
        stream = path.open("rb")
    except OSError as exc:
        raise RuntimeError(f"{label} could not be safely opened") from exc
    try:
        opened = os.fstat(stream.fileno())
        try:
            current = path.lstat()
        except OSError as exc:
            raise RuntimeError(f"{label} changed identity during verification open") from exc
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(before, opened)
            or not os.path.samestat(opened, current)
        ):
            raise RuntimeError(f"{label} changed identity during verification open")
        if opened.st_size <= 0 or opened.st_size > MAX_MOBILE_ARTIFACT:
            raise RuntimeError(f"{label} is empty or oversized")
        return stream
    except BaseException:
        stream.close()
        raise


def _normalize_sha(value: str) -> str:
    value = str(value or "").strip().lower()
    if not SHA_RE.fullmatch(value):
        raise RuntimeError("mobile artifact provenance requires one full 40-character source SHA")
    return value


def _normalize_repo(value: str) -> str:
    value = str(value or "").strip()
    if not REPO_RE.fullmatch(value):
        raise RuntimeError("mobile artifact provenance repository is invalid")
    return value


def _safe_zip_name(name: str) -> str:
    normalized = str(name or "").replace("\\", "/")
    p = PurePosixPath(normalized)
    if (
        not normalized
        or p.is_absolute()
        or normalized.startswith("//")
        or any(part in ("", ".", "..") for part in p.parts)
        or (p.parts and p.parts[0].endswith(":"))
    ):
        raise RuntimeError(f"mobile artifact contains unsafe ZIP member path: {name!r}")
    return normalized


def _member(zf: zipfile.ZipFile, wanted: str) -> zipfile.ZipInfo:
    matches: list[zipfile.ZipInfo] = []
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_MEMBERS:
        raise RuntimeError("mobile artifact contains too many ZIP members")
    for info in infos:
        clean = _safe_zip_name(info.filename.rstrip("/"))
        mode = (info.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            raise RuntimeError(f"mobile artifact contains a symlink member: {clean}")
        if info.flag_bits & 0x1:
            raise RuntimeError(f"mobile artifact contains an encrypted member: {clean}")
        if info.file_size < 0 or info.file_size > MAX_MOBILE_ARTIFACT:
            raise RuntimeError(f"mobile artifact ZIP member exceeds safety limit: {clean}")
        if info.compress_size > 0 and info.file_size > 8 * 1024 * 1024:
            if info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                raise RuntimeError(f"mobile artifact ZIP member compression ratio is unsafe: {clean}")
        if clean == wanted and not info.is_dir():
            matches.append(info)
    if len(matches) != 1:
        raise RuntimeError(f"mobile artifact contains {len(matches)} copies of required provenance member {wanted}")
    item = matches[0]
    if item.file_size <= 0 or item.file_size > MAX_PROVENANCE:
        raise RuntimeError(f"mobile artifact provenance member size is invalid: {wanted}")
    return item


def _read_member(zf: zipfile.ZipFile, wanted: str) -> bytes:
    item = _member(zf, wanted)
    with zf.open(item, "r") as stream:
        body = stream.read(MAX_PROVENANCE + 1)
    if not body or len(body) > MAX_PROVENANCE:
        raise RuntimeError(f"mobile artifact provenance member size is invalid: {wanted}")
    return body


def _verify_common(data: dict, expected_sha: str, expected_repo: str, expected_family: str) -> None:
    if not isinstance(data, dict):
        raise RuntimeError("mobile artifact provenance is not an object")
    raw_sha = str(data.get("source_sha") or data.get("RouterVPNSourceSHA") or "")
    raw_repo = str(data.get("repository") or data.get("RouterVPNSourceRepository") or "")
    raw_family = str(data.get("artifact_family") or data.get("RouterVPNArtifactFamily") or "")
    if _normalize_sha(raw_sha) != expected_sha:
        raise RuntimeError(f"mobile artifact source SHA mismatch: package={raw_sha!r} expected={expected_sha}")
    if _normalize_repo(raw_repo) != expected_repo:
        raise RuntimeError(f"mobile artifact repository mismatch: package={raw_repo!r} expected={expected_repo}")
    if raw_family != expected_family:
        raise RuntimeError(f"mobile artifact family mismatch: package={raw_family!r} expected={expected_family}")


def verify_android(path: Path, expected_sha: str, expected_repo: str) -> None:
    expected_sha = _normalize_sha(expected_sha)
    expected_repo = _normalize_repo(expected_repo)
    try:
        with _open_mobile_artifact(path, "Android APK") as artifact:
            with zipfile.ZipFile(artifact, "r") as zf:
                raw = _read_member(zf, ANDROID_MEMBER)
    except zipfile.BadZipFile as exc:
        raise RuntimeError("Android APK is not a valid ZIP container") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Android APK source provenance JSON is invalid") from exc
    if data.get("schema_version") != 1:
        raise RuntimeError("Android APK source provenance schema is invalid")
    _verify_common(data, expected_sha, expected_repo, "android-apk")


def _plist_dict(raw: bytes, label: str) -> dict:
    try:
        value = plistlib.loads(raw)
    except Exception as exc:
        raise RuntimeError(f"{label} Info.plist is invalid") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} Info.plist is not a dictionary")
    return {
        "RouterVPNSourceSHA": value.get("RouterVPNSourceSHA"),
        "RouterVPNSourceRepository": value.get("RouterVPNSourceRepository"),
        "RouterVPNArtifactFamily": value.get("RouterVPNArtifactFamily"),
    }


def verify_ios(path: Path, expected_sha: str, expected_repo: str) -> None:
    expected_sha = _normalize_sha(expected_sha)
    expected_repo = _normalize_repo(expected_repo)
    try:
        with _open_mobile_artifact(path, "iOS IPA") as artifact:
            with zipfile.ZipFile(artifact, "r") as zf:
                app = _plist_dict(_read_member(zf, IOS_APP_INFO), "RouterVPN.app")
                tunnel = _plist_dict(_read_member(zf, IOS_TUNNEL_INFO), "RouterVPNPacketTunnel.appex")
    except zipfile.BadZipFile as exc:
        raise RuntimeError("iOS IPA is not a valid ZIP container") from exc
    _verify_common(app, expected_sha, expected_repo, "ios-app")
    _verify_common(tunnel, expected_sha, expected_repo, "ios-packet-tunnel")

def verify(name: str, path: Path, expected_sha: str, expected_repo: str) -> None:
    if name == "router-vpn-android.apk":
        verify_android(path, expected_sha, expected_repo)
        return
    if name in ("router-vpn-ios.ipa", "router-vpn-ios-preview.ipa"):
        verify_ios(path, expected_sha, expected_repo)
        return
    raise RuntimeError(f"unsupported mobile artifact provenance request: {name}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify embedded Router VPN mobile artifact source provenance.")
    ap.add_argument("--name", required=True)
    ap.add_argument("--path", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--repo", default="Eabusham2/router-vpn")
    args = ap.parse_args()
    try:
        verify(args.name, Path(args.path), args.sha, args.repo)
    except RuntimeError as exc:
        raise SystemExit(f"mobile artifact provenance verification failed: {exc}") from exc
    print(f"mobile artifact provenance verified: {args.name} @ {args.sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

