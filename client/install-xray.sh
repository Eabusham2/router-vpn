#!/usr/bin/env bash
set -euo pipefail
command -v xray >/dev/null 2>&1 && exit 0
OS=$(uname -s | tr '[:upper:]' '[:lower:]'); ARCH=$(uname -m)
case "$OS/$ARCH" in
 linux/x86_64|linux/amd64) pattern='Xray-linux-64.zip' ;;
 linux/aarch64|linux/arm64) pattern='Xray-linux-arm64-v8a.zip' ;;
 darwin/x86_64) pattern='Xray-macos-64.zip' ;;
 darwin/arm64) pattern='Xray-macos-arm64-v8a.zip' ;;
 *) echo "No Xray binary mapping for $OS/$ARCH" >&2; exit 1;;
esac
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
URL=$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest | python3 -c 'import json,sys; p=sys.argv[1]; a=json.load(sys.stdin)["assets"]; print(next(x["browser_download_url"] for x in a if x["name"]==p))' "$pattern")
curl -fL "$URL" -o "$TMP/xray.zip"
python3 - "$TMP/xray.zip" "$TMP" <<'PY'
import zipfile,sys
zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])
PY
sudo install -m 755 "$TMP/xray" /usr/local/bin/xray
