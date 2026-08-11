#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -ne 0 ]] || { echo 'Run this as your normal Mac user, not with sudo.'; exit 1; }
BUNDLE=${1:-$(pwd)}
bash "$BUNDLE/client/install-macos-complete.sh" "$BUNDLE"

# If the complete installer placed a verified official sing-box in /usr/local/bin,
# prefer it over a Homebrew build with reduced build tags.
if [[ -x /usr/local/bin/sing-box ]] && /usr/local/bin/sing-box version 2>&1 | grep -q 'with_naive_outbound'; then
  PLIST=/Library/LaunchDaemons/com.routervpn.client.plist
  sudo /usr/libexec/PlistBuddy -c 'Delete :EnvironmentVariables:PATH' "$PLIST" >/dev/null 2>&1 || true
  sudo /usr/libexec/PlistBuddy -c 'Add :EnvironmentVariables:PATH string /usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin' "$PLIST"
  sudo launchctl bootout system/com.routervpn.client >/dev/null 2>&1 || true
  sudo launchctl bootstrap system "$PLIST"
  sudo launchctl enable system/com.routervpn.client
fi

# Install a normal Applications entry so everyday use does not require typing or
# bookmarking http://127.0.0.1:8788. The controller remains local-only; the app
# launcher opens it in browser standalone/app-window mode when supported.
APP_DIR="$HOME/Applications/Router VPN.app"
mkdir -p "$APP_DIR/Contents/MacOS"
cat >"$APP_DIR/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Router VPN</string>
  <key>CFBundleDisplayName</key><string>Router VPN</string>
  <key>CFBundleIdentifier</key><string>com.eabusham.routervpn.desktop</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleShortVersionString</key><string>0.7</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>RouterVPN</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
</dict></plist>
PLIST
cat >"$APP_DIR/Contents/MacOS/RouterVPN" <<'SH'
#!/usr/bin/env bash
set -u
URL='http://127.0.0.1:8788/'
for _ in {1..40}; do
  /usr/bin/curl -fsS --max-time 1 "$URL" >/dev/null 2>&1 && break
  /bin/sleep 0.25
done
if [[ -d '/Applications/Google Chrome.app' ]]; then
  exec /usr/bin/open -na 'Google Chrome' --args --app="$URL"
elif [[ -d '/Applications/Microsoft Edge.app' ]]; then
  exec /usr/bin/open -na 'Microsoft Edge' --args --app="$URL"
elif [[ -d '/Applications/Brave Browser.app' ]]; then
  exec /usr/bin/open -na 'Brave Browser' --args --app="$URL"
elif [[ -d '/Applications/Chromium.app' ]]; then
  exec /usr/bin/open -na 'Chromium' --args --app="$URL"
else
  exec /usr/bin/open "$URL"
fi
SH
chmod 0755 "$APP_DIR/Contents/MacOS/RouterVPN"
/usr/bin/touch "$APP_DIR"

printf 'macOS Router VPN is ready. Open "Router VPN" from ~/Applications (or http://127.0.0.1:8788 for recovery).\n'
