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

printf 'macOS Router VPN is ready. Open http://127.0.0.1:8788\n'
