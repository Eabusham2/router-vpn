#!/usr/bin/env bash
set -euo pipefail
command -v xray >/dev/null 2>&1 && exit 0

VERSION=v26.7.11
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS/$ARCH" in
  linux/x86_64|linux/amd64)
    ASSET='Xray-linux-64.zip'
    EXPECTED_SHA256='aa11c3685c71da0ffc71e511db50404609e7e963bb914b048f59a6a00af8930e'
    ;;
  linux/aarch64|linux/arm64)
    ASSET='Xray-linux-arm64-v8a.zip'
    EXPECTED_SHA256='89cfe01674d7c9f6847b7dd9389537be9acb3b9dc3c6cb9fdeba87a3e4e57fc1'
    ;;
  darwin/x86_64)
    ASSET='Xray-macos-64.zip'
    EXPECTED_SHA256='d8c116756d3a88a38a833a94bdf8bc801f69243ee888befcb56df8b4f1ec4878'
    ;;
  darwin/arm64)
    ASSET='Xray-macos-arm64-v8a.zip'
    EXPECTED_SHA256='61f8f74d099098af710fa43613d9934d97b901dee909801d34f496cd463956d1'
    ;;
  *) echo "No Xray binary mapping for $OS/$ARCH" >&2; exit 1 ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
URL="https://github.com/XTLS/Xray-core/releases/download/$VERSION/$ASSET"
curl --proto '=https' --tlsv1.2 -fL "$URL" -o "$TMP/xray.zip"

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA256=$(sha256sum "$TMP/xray.zip" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA256=$(shasum -a 256 "$TMP/xray.zip" | awk '{print $1}')
else
  echo 'A SHA-256 checksum utility is required' >&2
  exit 1
fi
[[ "$ACTUAL_SHA256" == "$EXPECTED_SHA256" ]] || {
  echo "Xray archive checksum mismatch: expected $EXPECTED_SHA256 got $ACTUAL_SHA256" >&2
  exit 1
}

python3 - "$TMP/xray.zip" "$TMP/xray" <<'PY'
import pathlib
import shutil
import stat
import sys
import zipfile

archive = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
max_archive = 64 * 1024 * 1024
max_members = 128
max_total = 128 * 1024 * 1024
max_binary = 64 * 1024 * 1024

if archive.stat().st_size > max_archive:
    raise SystemExit("Xray archive exceeds maximum allowed size")

with zipfile.ZipFile(archive) as zf:
    infos = zf.infolist()
    if not infos or len(infos) > max_members:
        raise SystemExit("Xray archive member count is invalid")
    total = 0
    binary = None
    for info in infos:
        name = info.filename
        if "\x00" in name:
            raise SystemExit("Xray archive contains NUL in a member name")
        p = pathlib.PurePosixPath(name)
        if p.is_absolute() or ".." in p.parts:
            raise SystemExit(f"Xray archive contains unsafe path: {name}")
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise SystemExit(f"Xray archive contains a symlink: {name}")
        total += info.file_size
        if total > max_total:
            raise SystemExit("Xray archive expands beyond maximum allowed size")
        if p.name == "xray" and not info.is_dir():
            if binary is not None:
                raise SystemExit("Xray archive contains multiple xray binaries")
            if info.file_size <= 0 or info.file_size > max_binary:
                raise SystemExit("Xray binary size is invalid")
            binary = info
    if binary is None:
        raise SystemExit("Xray archive does not contain an xray binary")
    with zf.open(binary, "r") as src, out.open("wb") as dst:
        shutil.copyfileobj(src, dst)
PY

chmod 755 "$TMP/xray"
"$TMP/xray" version >/dev/null
sudo install -m 755 "$TMP/xray" /usr/local/bin/xray
