#!/usr/bin/env python3
"""Verify every native release-candidate package is self-identifying as one SHA."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MOBILE_PATH = ROOT / "server" / "scripts" / "mobile-artifact-provenance.py"
_spec = importlib.util.spec_from_file_location("routervpn_release_mobile_provenance", MOBILE_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"cannot load {MOBILE_PATH}")
_mobile = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mobile)

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MANIFEST = "ROUTER-VPN-SOURCE.json"
MAX_MANIFEST = 64 << 10
MAX_ARCHIVE = 768 << 20
MAX_MEMBERS = 200_000
REPO = "Eabusham2/router-vpn"

EXPECTED = {
    "RouterVPN-Windows-amd64.zip": ("zip", "windows-amd64"),
    "RouterVPN-Windows-arm64.zip": ("zip", "windows-arm64"),
    "RouterVPN-Portable-Windows-amd64.zip": ("zip", "windows-portable-amd64"),
    "RouterVPN-Portable-Windows-arm64.zip": ("zip", "windows-portable-arm64"),
    "RouterVPN-darwin-amd64.tar.gz": ("tar", "macos-amd64"),
    "RouterVPN-darwin-arm64.tar.gz": ("tar", "macos-arm64"),
    "RouterVPN-linux-amd64.tar.gz": ("tar", "linux-amd64"),
    "RouterVPN-linux-arm64.tar.gz": ("tar", "linux-arm64"),
    "app-debug.apk": ("android", "android-apk"),
    "RouterVPN-native-unsigned-resignable.ipa": ("ios", "ios-app"),
}


def _sha(value: str) -> str:
    value = str(value or "").strip().lower()
    if not SHA_RE.fullmatch(value):
        raise RuntimeError("release candidate provenance requires a full 40-character SHA")
    return value


def _safe_member(name: str) -> PurePosixPath:
    normalized = str(name or "").replace("\\", "/").rstrip("/")
    p = PurePosixPath(normalized)
    if (
        not normalized
        or p.is_absolute()
        or normalized.startswith("//")
        or any(part in ("", ".", "..") for part in p.parts)
        or (p.parts and p.parts[0].endswith(":"))
    ):
        raise RuntimeError(f"unsafe release archive path: {name!r}")
    return p


def _manifest_data(raw: bytes, expected_sha: str, family: str) -> None:
    if not raw or len(raw) > MAX_MANIFEST:
        raise RuntimeError(f"{family}: source provenance manifest size is invalid")
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError(f"{family}: source provenance JSON is invalid") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise RuntimeError(f"{family}: source provenance schema is invalid")
    if str(data.get("repository") or "") != REPO:
        raise RuntimeError(f"{family}: source provenance repository mismatch")
    if str(data.get("artifact_family") or "") != family:
        raise RuntimeError(f"{family}: source provenance family mismatch")
    if str(data.get("source_sha") or "").strip().lower() != expected_sha:
        raise RuntimeError(f"{family}: source provenance SHA mismatch")


def _zip_manifest(path: Path, expected_sha: str, family: str) -> None:
    with zipfile.ZipFile(path, "r") as zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            raise RuntimeError(f"{path.name}: too many ZIP members")
        matches = []
        for info in infos:
            clean = _safe_member(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise RuntimeError(f"{path.name}: archive contains symlink {clean}")
            if clean.name == MANIFEST and not info.is_dir():
                matches.append(info)
        if len(matches) != 1:
            raise RuntimeError(f"{path.name}: expected one {MANIFEST}, found {len(matches)}")
        item = matches[0]
        if item.file_size <= 0 or item.file_size > MAX_MANIFEST:
            raise RuntimeError(f"{path.name}: provenance manifest size is invalid")
        with zf.open(item) as stream:
            raw = stream.read(MAX_MANIFEST + 1)
    _manifest_data(raw, expected_sha, family)


def _tar_manifest(path: Path, expected_sha: str, family: str) -> None:
    with tarfile.open(path, "r:gz") as tf:
        members = tf.getmembers()
        if len(members) > MAX_MEMBERS:
            raise RuntimeError(f"{path.name}: too many TAR members")
        matches = []
        for item in members:
            clean = _safe_member(item.name)
            if item.issym() or item.islnk() or item.isdev() or item.isfifo():
                raise RuntimeError(f"{path.name}: archive contains unsafe member {clean}")
            if clean.name == MANIFEST and item.isfile():
                matches.append(item)
        if len(matches) != 1:
            raise RuntimeError(f"{path.name}: expected one {MANIFEST}, found {len(matches)}")
        item = matches[0]
        if item.size <= 0 or item.size > MAX_MANIFEST:
            raise RuntimeError(f"{path.name}: provenance manifest size is invalid")
        stream = tf.extractfile(item)
        if stream is None:
            raise RuntimeError(f"{path.name}: cannot read source provenance manifest")
        with stream:
            raw = stream.read(MAX_MANIFEST + 1)
    _manifest_data(raw, expected_sha, family)


def _unique(root: Path, filename: str) -> Path:
    matches = [p for p in root.rglob(filename) if p.is_file() and not p.is_symlink()]
    if len(matches) != 1:
        raise RuntimeError(f"release candidate requires exactly one {filename}, found {len(matches)}")
    path = matches[0]
    size = path.stat().st_size
    if size <= 0 or size > MAX_ARCHIVE:
        raise RuntimeError(f"{filename}: package is empty or oversized")
    return path


def verify_tree(root: Path, expected_sha: str) -> None:
    expected_sha = _sha(expected_sha)
    root = root.resolve()
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError("release candidate artifact root is missing or redirected")

    for filename, (kind, family) in EXPECTED.items():
        path = _unique(root, filename)
        if kind == "zip":
            _zip_manifest(path, expected_sha, family)
        elif kind == "tar":
            _tar_manifest(path, expected_sha, family)
        elif kind == "android":
            _mobile.verify("router-vpn-android.apk", path, expected_sha, REPO)
        elif kind == "ios":
            _mobile.verify("router-vpn-ios.ipa", path, expected_sha, REPO)
        else:
            raise RuntimeError(f"unsupported release provenance kind {kind}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--sha", required=True)
    args = ap.parse_args()
    verify_tree(Path(args.root), args.sha)
    print(f"release candidate embedded provenance: PASS ({len(EXPECTED)} packages at {_sha(args.sha)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
