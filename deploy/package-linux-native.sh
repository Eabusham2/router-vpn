#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ARCH=${1:?usage: package-linux-native.sh amd64|arm64 [OUT_DIR]}
OUT=${2:-"$ROOT/dist/linux-native"}
case "$ARCH" in
  amd64) goarch=amd64 ;;
  arm64) goarch=arm64 ;;
  *) echo "Unsupported Linux architecture: $ARCH" >&2; exit 2 ;;
esac

name="RouterVPN-linux-$ARCH"
work="$OUT/work-$ARCH"
dir="$work/$name"
rm -rf "$work"
rm -f "$OUT/$name.tar.gz" "$OUT/$name.sha256"
mkdir -p "$dir/modes" "$dir/generated" "$dir/client" "$OUT"

cp "$ROOT/configs/client/client.json.example" "$dir/client.json"
cp "$ROOT/configs/client/modes.json" "$dir/modes.json"
cp "$ROOT/configs/client/logical-modes.json" "$dir/logical-modes.json"
cp -a "$ROOT/modes/." "$dir/modes/"
cp -a "$ROOT/client/." "$dir/client/"
cat > "$dir/routers.json" <<'JSON'
{"schema_version":4,"selected_id":"","profiles":[]}
JSON
chmod 600 "$dir/routers.json"
cp "$ROOT/docs/MODES.md" "$dir/MODES.md"
cp "$ROOT/docs/CLIENT.md" "$dir/CLIENT.md"
cp "$ROOT/SECURITY.md" "$dir/SECURITY.md"
cp "$ROOT/LICENSE" "$dir/LICENSE"

CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -ldflags='-s -w' -o "$dir/router-vpn-client" ./cmd/client
CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -ldflags='-s -w' -o "$dir/router-vpn-dns" ./cmd/dnsproxy
chmod 755 "$dir/router-vpn-client" "$dir/router-vpn-dns" "$dir/modes/"*.sh

# The GTK builder intentionally uses strict -Werror and many fail-closed contract
# checks. If one of those post-link checks fails, print enough native evidence to
# identify the exact missing dependency/symbol instead of leaving CI with only the
# preceding `file` line. Never turn a failed native build into a package success.
set +e
"$ROOT/client/linux/build-native-app.sh" "$dir/router-vpn-app"
native_rc=$?
set -e
if (( native_rc != 0 )); then
  echo "Linux native app builder failed rc=$native_rc" >&2
  if [[ -f "$dir/router-vpn-app" ]]; then
    echo '=== router-vpn-app file ===' >&2
    file "$dir/router-vpn-app" >&2 || true
    echo '=== router-vpn-app ldd ===' >&2
    ldd "$dir/router-vpn-app" >&2 || true
    echo '=== required direct symbols ===' >&2
    nm -D "$dir/router-vpn-app" 2>/dev/null | grep -E 'gtk_|json_|curl_easy_' | head -n 80 >&2 || true
  fi
  exit "$native_rc"
fi
python3 "$ROOT/deploy/materialize-desktop-icons.py" --png "$dir/router-vpn.png" --ico "$dir/RouterVPN.ico"

cat > "$dir/start-router-vpn.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
exec "$ROOT/router-vpn-app"
SH
chmod 755 "$dir/start-router-vpn.sh"

cat > "$dir/router-vpn.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Router VPN
Comment=Native Router VPN client
TryExec=/opt/router-vpn-client/router-vpn-app
Exec=/opt/router-vpn-client/router-vpn-app
Icon=router-vpn
Terminal=false
Categories=Network;Security;
StartupNotify=true
StartupWMClass=router-vpn-app
DESKTOP

cat > "$dir/install-router-vpn.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=/opt/router-vpn-client
mkdir -p "$ROOT" /usr/local/bin /usr/share/applications /usr/share/icons/hicolor/256x256/apps

# Refresh immutable application/runtime material without replacing private
# install-once node state on an upgrade.
for path in modes client; do
  rm -rf "$ROOT/$path"
  cp -a "$SRC/$path" "$ROOT/$path"
done
for file in client.json modes.json logical-modes.json router-vpn-client router-vpn-dns router-vpn-app RouterVPN.ico router-vpn.png MODES.md CLIENT.md SECURITY.md LICENSE; do
  [[ -e "$SRC/$file" ]] && cp -a "$SRC/$file" "$ROOT/$file"
done
chmod 755 "$ROOT/router-vpn-client" "$ROOT/router-vpn-dns" "$ROOT/router-vpn-app" "$ROOT/modes/"*.sh
if [[ ! -f "$ROOT/routers.json" ]]; then
  install -m 600 "$SRC/routers.json" "$ROOT/routers.json"
fi
if [[ ! -d "$ROOT/generated" ]]; then
  cp -a "$SRC/generated" "$ROOT/generated"
fi

install -m 644 "$SRC/router-vpn.png" /usr/share/icons/hicolor/256x256/apps/router-vpn.png
install -m 644 "$SRC/router-vpn.desktop" /usr/share/applications/router-vpn.desktop
cat >/usr/local/bin/router-vpn <<'LAUNCH'
#!/usr/bin/env sh
exec /opt/router-vpn-client/router-vpn-app "$@"
LAUNCH
chmod 755 /usr/local/bin/router-vpn
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database /usr/share/applications || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -f -t /usr/share/icons/hicolor || true
printf '%s\n' 'Router VPN installed. Open Router VPN from the desktop application menu or run: router-vpn'
printf '%s\n' 'Existing linked Router VPN nodes were preserved if already present.'
SH
chmod 755 "$dir/install-router-vpn.sh"

cat > "$dir/README-LINUX.txt" <<'TXT'
Router VPN for Linux
====================
Run sudo ./install-router-vpn.sh for normal desktop application integration, then open Router VPN
from your application menu. The installer adds the Router VPN icon/desktop entry and preserves any
existing /opt/router-vpn-client/routers.json + generated node state on upgrades.

You can also run ./router-vpn-app or ./start-router-vpn.sh directly from the extracted folder. This
is a native GTK3 application that talks only to the loopback Router VPN controller API. It does not
open or embed a website/WebView.

The app starts the sibling router-vpn-client only when no controller is already listening on
127.0.0.1:8788. If it starts that controller, closing the app issues an emergency stop and stops
only that owned process. The generic archive contains no linked home node; link/import node data
separately. Router VPN is MIT-licensed; see LICENSE.

Runtime desktop dependencies: GTK3, libcurl and json-glib. Tunnel engines/tools are installed by
the normal Router VPN Linux runtime setup; unsupported mode checks remain unavailable/grey rather
than being substituted with a fake compatibility path.
TXT

tar -C "$work" -czf "$OUT/$name.tar.gz" "$name"
archive_list="$work/archive-members.txt"
tar -tzf "$OUT/$name.tar.gz" > "$archive_list"
grep -Fxq "$name/router-vpn-app" "$archive_list"
grep -Fxq "$name/router-vpn.png" "$archive_list"
grep -Fxq "$name/router-vpn.desktop" "$archive_list"
grep -Fxq "$name/install-router-vpn.sh" "$archive_list"
grep -Fxq "$name/LICENSE" "$archive_list"
if grep -Fq 'router-vpn-bundle.json' "$archive_list"; then
  echo 'Native Linux package unexpectedly contains a private router bundle.' >&2
  exit 1
fi
grep -Fq 'Exec=/opt/router-vpn-client/router-vpn-app' "$dir/router-vpn.desktop"
grep -Fq 'Icon=router-vpn' "$dir/router-vpn.desktop"
grep -Fq 'StartupWMClass=router-vpn-app' "$dir/router-vpn.desktop"
grep -Fq '[[ ! -f "$ROOT/routers.json" ]]' "$dir/install-router-vpn.sh"

python3 "$ROOT/deploy/check-generic-package-secrets.py" "$OUT"
(
  cd "$OUT"
  sha256sum "$name.tar.gz" > "$name.sha256"
  sha256sum -c "$name.sha256"
)
rm -rf "$work"
echo "Packaged native Linux Router VPN app: $OUT/$name.tar.gz"
