#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -ne 0 ]] || { echo 'Run this as your normal Mac user, not with sudo.'; exit 1; }
BUNDLE=${1:-$(pwd)}
[[ -f "$BUNDLE/client/install-macos.sh" ]] || { echo 'Run from the extracted router-vpn-client-bundle folder.'; exit 1; }

bash "$BUNDLE/client/install-macos.sh" "$BUNDLE"

PLIST=/Library/LaunchDaemons/com.routervpn.client.plist
TMP=$(mktemp)
cat >"$TMP" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.routervpn.client</string>
  <key>ProgramArguments</key><array><string>/usr/local/bin/router-vpn-client</string></array>
  <key>WorkingDirectory</key><string>/opt/router-vpn-client</string>
  <key>EnvironmentVariables</key><dict>
    <key>HOMEVPN_ROOT</key><string>/opt/router-vpn-client</string>
    <key>HOMEVPN_CLIENT_CONFIG</key><string>/opt/router-vpn-client/client.json</string>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/router-vpn-client.log</string>
  <key>StandardErrorPath</key><string>/var/log/router-vpn-client-error.log</string>
</dict></plist>
PLIST
sudo cp "$TMP" "$PLIST"
rm -f "$TMP"
sudo chown root:wheel "$PLIST"
sudo chmod 644 "$PLIST"
sudo launchctl bootout system/com.routervpn.client >/dev/null 2>&1 || true
sudo launchctl bootstrap system "$PLIST"
sudo launchctl enable system/com.routervpn.client
printf 'Installed and started. Open http://127.0.0.1:8788\n'
