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

# A matching host must execute the actual privilege boundary before its native
# controller is built. A cross-compile cannot certify that host's authority.
host_arch=$(uname -m)
case "$host_arch" in x86_64|amd64) host_arch=amd64 ;; aarch64|arm64) host_arch=arm64 ;; esac
[[ $(uname -s) == Linux && "$host_arch" == "$goarch" ]] || { echo 'Native Linux packaging requires a matching execution host.' >&2; exit 1; }
python3 "$ROOT/deploy/test_linux_controller_privilege.py" --go "$(command -v go)"

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
python3 "$ROOT/deploy/build-dnsproxy.py" build "linux/$goarch" "$dir/router-vpn-dns"
CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -ldflags='-s -w' -o "$dir/router-vpn-start-layer-relay" ./cmd/start-layer-relay
CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -ldflags='-s -w' -o "$dir/router-vpn-update" ./cmd/app-update
chmod 755 "$dir/router-vpn-client" "$dir/router-vpn-dns" "$dir/router-vpn-start-layer-relay" "$dir/router-vpn-update" "$dir/modes/"*.sh

# The current wrapper surgically composes the mature native builder with the
# schema-v4 AUTO/SMART requirement controls. It executes a temporary copy in
# client/linux so the base builder keeps its normal ROOT semantics.
set +e
"$ROOT/client/linux/build-native-app-current.sh" "$dir/router-vpn-app"
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
[[ -x "$ROOT/router-vpn-update" ]] && "$ROOT/router-vpn-update" --download --json >/dev/null 2>&1 &
exec "$ROOT/router-vpn-app"
SH
chmod 755 "$dir/start-router-vpn.sh"

cat > "$dir/router-vpn.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Router VPN
Comment=Native Router VPN client
TryExec=/usr/local/bin/router-vpn
Exec=/usr/local/bin/router-vpn
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
bash "$SRC/client/install-linux-system-tools.sh" --install "$SRC/router-vpn-app"
python3 "$SRC/client/install-linux-native.py" "$SRC"
SH
chmod 755 "$dir/install-router-vpn.sh"

cat > "$dir/README-LINUX.txt" <<'TXT'
Router VPN for Linux
====================
Run sudo ./install-router-vpn.sh for normal desktop application integration, then open Router VPN
from your application menu. The installer adds the Router VPN icon/desktop entry and preserves any
existing /opt/router-vpn-client/routers.json + generated node state on upgrades.

The package includes router-vpn-start-layer-relay for the optional authenticated AES-256-GCM start
layer's XOR whitening mode. XOR is obfuscation only; authenticated encryption remains Shadowsocks
2022 AES-256-GCM. Unsupported graphs fail closed instead of silently weakening the selected path.

The installed launcher starts a short-lived router-vpn-update helper before the native GTK app. It
accepts only immutable exact-SHA releases whose RouterVPN-RELEASE.json package digest matches, stages
a newer archive, and never overwrites the currently running installation. Distribution package
managers remain authoritative when Router VPN is installed through one.

The installed GUI stays under your desktop user. Its administrator request starts only the fixed,
root-owned controller; credentials travel through an anonymous pipe, and every privileged API call
is authenticated. Closing the GUI requests owned tunnel cleanup before its controller exits.

Always protection is reasserted before network managers start. The installer supplies a dedicated
early systemd service and dependency drop-ins; it does not start an unauthenticated boot controller.
For local emergency recovery, run sudo router-vpn-killswitch-recovery and review the saved policy.

This is a native GTK3 application that talks only to the loopback Router VPN controller API. It does not
open or embed a website/WebView.

The app verifies its own controller identity before sending API credentials to 127.0.0.1:8788.
An unrelated listener is rejected. The generic archive contains no linked home node; link/import
node data separately. Installation/upgrade stages verified files before promotion, preserves private
node state, and refuses an upgrade while the application is still running. Router VPN is MIT-licensed; see LICENSE.

The installer checks the actual native GUI's linked libraries and the system tools required for
networking and strict protection before replacing application files. On Debian/Ubuntu it installs
missing dependencies using the configured package repositories: GTK3, libcurl, json-glib, Python 3,
nftables, iproute2, passwd, util-linux, libc-bin, pkexec/polkit and systemd. Other distributions can provide the same tools
with their package manager before installation. No VPN engine is compiled during this setup.

To check an extracted package's system dependencies before installation, run
bash client/install-linux-system-tools.sh --check ./router-vpn-app. The normal desktop-user tunnel
launch uses the installed, protected controller and its administrator authorization.
TXT

"$ROOT/deploy/package-xray-runtime.sh" "linux/$ARCH" "$dir"
"$ROOT/deploy/package-amnezia-runtime.sh" "linux/$ARCH" "$dir"
"$ROOT/deploy/package-native-runtime.sh" "linux/$ARCH" "$dir"
python3 "$ROOT/server/scripts/source_provenance.py" "$dir" --family "linux-$ARCH"
python3 "$ROOT/deploy/test_linux_runtime_install.py" --package "$dir"
python3 "$ROOT/deploy/test_linux_native_install.py" --package "$dir"
bash "$dir/client/install-linux-system-tools.sh" --check "$dir/router-vpn-app"
tar -C "$work" -czf "$OUT/$name.tar.gz" "$name"
python3 "$ROOT/deploy/native-runtime-bundle.py" verify-package "linux/$ARCH" "$OUT/$name.tar.gz"
archive_list="$work/archive-members.txt"
tar -tzf "$OUT/$name.tar.gz" > "$archive_list"
grep -Fxq "$name/router-vpn-app" "$archive_list"
grep -Fxq "$name/router-vpn-start-layer-relay" "$archive_list"
grep -Fxq "$name/router-vpn-update" "$archive_list"
grep -Fxq "$name/router-vpn.png" "$archive_list"
grep -Fxq "$name/router-vpn.desktop" "$archive_list"
grep -Fxq "$name/install-router-vpn.sh" "$archive_list"
grep -Fxq "$name/LICENSE" "$archive_list"
grep -Fxq "$name/ROUTER-VPN-SOURCE.json" "$archive_list"
grep -Fxq "$name/runtime/amnezia/sing-box-amnezia" "$archive_list"
grep -Fxq "$name/runtime/amnezia/AMNEZIA-RUNTIME.json" "$archive_list"
if grep -Fq 'router-vpn-bundle.json' "$archive_list"; then
  echo 'Native Linux package unexpectedly contains a private router bundle.' >&2
  exit 1
fi
grep -Fq 'Exec=/usr/local/bin/router-vpn' "$dir/router-vpn.desktop"
grep -Fq 'Icon=router-vpn' "$dir/router-vpn.desktop"
grep -Fq 'StartupWMClass=router-vpn-app' "$dir/router-vpn.desktop"
grep -Fq 'python3 "$SRC/client/install-linux-native.py" "$SRC"' "$dir/install-router-vpn.sh"

python3 "$ROOT/deploy/check-generic-package-secrets.py" "$OUT"
(
  cd "$OUT"
  sha256sum "$name.tar.gz" > "$name.sha256"
  sha256sum -c "$name.sha256"
)
bash "$ROOT/deploy/test-linux-rendered-layout.sh" "$OUT/$name.tar.gz"
rm -rf "$work"
echo "Packaged native Linux Router VPN app: $OUT/$name.tar.gz"
