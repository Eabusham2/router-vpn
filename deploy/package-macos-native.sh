#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT=${1:-"$ROOT/dist/macos-native"}
WORK="$OUT/work"
MACOS_SIGN_IDENTITY=${ROUTER_VPN_MACOS_SIGN_IDENTITY:--}
rm -rf "$OUT"
mkdir -p "$WORK"

write_blank_routers() {
  cat >"$1" <<'JSON'
{"schema_version":4,"selected_id":"","profiles":[]}
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

sign_macho() {
  local target=$1
  if [[ "$MACOS_SIGN_IDENTITY" == "-" ]]; then
    codesign --force --sign - --timestamp=none "$target"
  else
    codesign --force --options runtime --timestamp --sign "$MACOS_SIGN_IDENTITY" "$target"
  fi
  codesign --verify --strict --verbose=2 "$target"
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

  # Seal every distributed Mach-O before packaging. CI/release candidates use
  # an ad-hoc identity so quarantine cannot mistake an unsealed bundle for a
  # modified/corrupt app. Production can supply a Developer ID Application
  # identity via ROUTER_VPN_MACOS_SIGN_IDENTITY; that path also enables the
  # hardened runtime and secure timestamp required by Apple's notarization flow.
  sign_macho "$dir/router-vpn-client"
  sign_macho "$dir/router-vpn-dns"
  sign_macho "$dir/RouterVPN.app"

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

Open RouterVPN.app for the native AppKit client. The app includes the Router VPN application icon,
owns the local controller lifecycle when it starts it, and talks only to http://127.0.0.1:8788. It
does not open or embed a website/WebView. The archive is generic and contains no linked home node.
Add/import your router separately.

start-router-vpn.sh is a convenience launcher for the same native app. Keep RouterVPN.app beside
router-vpn-client, client.json, routers.json, modes/, generated/, and the rest of this folder.

Release-candidate packages are cryptographically sealed with an ad-hoc code signature so macOS can
verify bundle integrity after download. A public production build must additionally be signed with a
Developer ID Application certificate and notarized by Apple before distribution. Do not disable
Gatekeeper or other macOS platform security globally.

Router VPN is MIT-licensed; see LICENSE.
TXT

  codesign --verify --deep --strict --verbose=2 "$dir/RouterVPN.app"
  signature_info="$WORK/$name-codesign.txt"
  codesign -dv --verbose=2 "$dir/RouterVPN.app" >"$signature_info" 2>&1
  grep -Eq 'Signature=adhoc|Authority=Developer ID Application' "$signature_info"
  python3 "$ROOT/server/scripts/source_provenance.py" "$dir" --family "macos-$arch"

  tar -C "$WORK" -czf "$OUT/$name.tar.gz" "$name"
  archive_list="$WORK/$name-members.txt"
  tar -tzf "$OUT/$name.tar.gz" > "$archive_list"
  grep -Fxq "$name/RouterVPN.app/Contents/MacOS/RouterVPN" "$archive_list"
  grep -Fxq "$name/RouterVPN.app/Contents/Resources/RouterVPN.icns" "$archive_list"
  grep -Fxq "$name/ROUTER-VPN-SOURCE.json" "$archive_list"
  [[ "$(plutil -extract CFBundleIconFile raw -o - "$dir/RouterVPN.app/Contents/Info.plist")" == "RouterVPN" ]]
done

python3 "$ROOT/deploy/check-generic-package-secrets.py" "$OUT"
(
  cd "$OUT"
  shasum -a 256 RouterVPN-darwin-amd64.tar.gz RouterVPN-darwin-arm64.tar.gz > SHA256SUMS
  shasum -a 256 -c SHA256SUMS
)
rm -rf "$WORK"
echo "Packaged code-signed native macOS Router VPN applications in $OUT"
