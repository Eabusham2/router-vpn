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
{"schema_version":2,"selected_id":"","profiles":[]}
JSON
chmod 600 "$dir/routers.json"
cp "$ROOT/docs/MODES.md" "$dir/MODES.md"
cp "$ROOT/docs/CLIENT.md" "$dir/CLIENT.md"
cp "$ROOT/SECURITY.md" "$dir/SECURITY.md"
cp "$ROOT/LICENSE" "$dir/LICENSE"

CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -ldflags='-s -w' -o "$dir/router-vpn-client" ./cmd/client
CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -ldflags='-s -w' -o "$dir/router-vpn-dns" ./cmd/dnsproxy
chmod 755 "$dir/router-vpn-client" "$dir/router-vpn-dns" "$dir/modes/"*.sh

"$ROOT/client/linux/build-native-app.sh" "$dir/router-vpn-app"

cat > "$dir/start-router-vpn.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
exec "$ROOT/router-vpn-app"
SH
chmod 755 "$dir/start-router-vpn.sh"

cat > "$dir/routervpn.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Router VPN
Comment=Native Router VPN client
Exec=router-vpn-app
Terminal=false
Categories=Network;Security;
DESKTOP

cat > "$dir/README-LINUX.txt" <<'TXT'
Router VPN for Linux
====================
Run ./router-vpn-app or ./start-router-vpn.sh. This is a native GTK3 application that talks only
to the loopback Router VPN controller API. It does not open or embed a website/WebView.

The app starts the sibling router-vpn-client only when no controller is already listening on
127.0.0.1:8788. If it starts that controller, closing the app issues an emergency stop and stops
only that owned process. The generic archive contains no linked home node; link/import node data
separately. Router VPN is MIT-licensed; see LICENSE.

Runtime desktop dependencies: GTK3, libcurl and json-glib. Tunnel engines/tools are installed by
the normal Router VPN Linux runtime setup; unsupported mode checks remain unavailable/grey rather
than being substituted with a fake compatibility path.
TXT

tar -C "$work" -czf "$OUT/$name.tar.gz" "$name"
# Materialize the archive listing once. With pipefail, `tar -t | grep -q` can
# make tar receive SIGPIPE after grep finds an early match, falsely failing a
# valid package with "tar: stdout: write error".
archive_list="$work/archive-members.txt"
tar -tzf "$OUT/$name.tar.gz" > "$archive_list"
grep -Fxq "$name/router-vpn-app" "$archive_list"
grep -Fxq "$name/LICENSE" "$archive_list"
if grep -Fq 'router-vpn-bundle.json' "$archive_list"; then
  echo 'Native Linux package unexpectedly contains a private router bundle.' >&2
  exit 1
fi

# Scan the finished public archive. The scanner intentionally requires an archive;
# scanning the work directory before tar creation would always fail with "no packages found".
python3 "$ROOT/deploy/check-generic-package-secrets.py" "$OUT"
(
  cd "$OUT"
  sha256sum "$name.tar.gz" > "$name.sha256"
  sha256sum -c "$name.sha256"
)
rm -rf "$work"
echo "Packaged native Linux Router VPN app: $OUT/$name.tar.gz"
