#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT=${1:-"$ROOT/dist/macos-native"}
WORK="$OUT/work"
rm -rf "$OUT"
mkdir -p "$WORK"

write_blank_routers() {
  cat >"$1" <<'JSON'
{"schema_version":2,"selected_id":"","profiles":[]}
JSON
  chmod 600 "$1"
}

copy_runtime() {
  local dir=$1
  mkdir -p "$dir/modes" "$dir/generated" "$dir/client"
  cp "$ROOT/configs/client/client.json.example" "$dir/client.json"
  cp "$ROOT/configs/client/modes.json" "$dir/modes.json"
  cp "$ROOT/configs/client/logical-modes.json" "$dir/logical-modes.json"
  cp -a "$ROOT/modes/." "$dir/modes/"
  cp -a "$ROOT/client/." "$dir/client/"
  write_blank_routers "$dir/routers.json"
  cp "$ROOT/docs/MODES.md" "$dir/MODES.md"
  cp "$ROOT/docs/CLIENT.md" "$dir/CLIENT.md"
  cp "$ROOT/SECURITY.md" "$dir/SECURITY.md"
  cp "$ROOT/LICENSE" "$dir/LICENSE"
}

for arch in amd64 arm64; do
  case "$arch" in
    amd64) goarch=amd64 ;;
    arm64) goarch=arm64 ;;
  esac
  name="RouterVPN-darwin-$arch"
  dir="$WORK/$name"
  mkdir -p "$dir"
  copy_runtime "$dir"

  CGO_ENABLED=0 GOOS=darwin GOARCH="$goarch" go build -trimpath -ldflags='-s -w' -o "$dir/router-vpn-client" ./cmd/client
  CGO_ENABLED=0 GOOS=darwin GOARCH="$goarch" go build -trimpath -ldflags='-s -w' -o "$dir/router-vpn-dns" ./cmd/dnsproxy
  chmod 755 "$dir/router-vpn-client" "$dir/router-vpn-dns" "$dir/modes/"*.sh

  "$ROOT/client/macos/build-native-app.sh" "$dir" "$arch"

  cat >"$dir/start-router-vpn.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
APP="$ROOT/RouterVPN.app"
[[ -d "$APP" ]] || { echo "RouterVPN.app is missing from this package." >&2; exit 1; }
open -W "$APP"
SH
  chmod 755 "$dir/start-router-vpn.sh"

  cat >"$dir/README-MACOS.txt" <<'TXT'
Router VPN for macOS
====================

Open RouterVPN.app for the native AppKit client. The app owns the local controller lifecycle when
it starts it and talks only to http://127.0.0.1:8788. It does not open or embed a website/WebView.
The archive is generic and contains no linked home node. Add/import your router separately.

start-router-vpn.sh is a convenience launcher for the same native app. Keep RouterVPN.app beside
router-vpn-client, client.json, routers.json, modes/, generated/, and the rest of this folder.

If Gatekeeper blocks a locally-built unsigned artifact, verify its SHA-256 and use System Settings
→ Privacy & Security → Open Anyway for that specific trusted build. Do not disable Gatekeeper or
other macOS platform security globally. Long-term distribution is expected to be signed/notarized.

Router VPN is MIT-licensed; see LICENSE.
TXT

  tar -C "$WORK" -czf "$OUT/$name.tar.gz" "$name"
  tar -tzf "$OUT/$name.tar.gz" >/dev/null
  tar -tzf "$OUT/$name.tar.gz" | grep -q "^$name/RouterVPN.app/Contents/MacOS/RouterVPN$"
done

python3 "$ROOT/deploy/check-generic-package-secrets.py" "$OUT"
(
  cd "$OUT"
  shasum -a 256 RouterVPN-darwin-amd64.tar.gz RouterVPN-darwin-arm64.tar.gz > SHA256SUMS
  shasum -a 256 -c SHA256SUMS
)
rm -rf "$WORK"
echo "Packaged native macOS Router VPN applications in $OUT"
