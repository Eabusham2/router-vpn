#!/usr/bin/env bash
set -euo pipefail

SHA="${ROUTER_VPN_SOURCE_SHA:-}"
REPO="${ROUTER_VPN_SOURCE_REPOSITORY:-Eabusham2/router-vpn}"
FAMILY="${ROUTER_VPN_ARTIFACT_FAMILY:-}"

[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "Router VPN source provenance requires an exact 40-character SHA" >&2; exit 1; }
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "Router VPN source repository is invalid" >&2; exit 1; }
[[ "$FAMILY" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || { echo "Router VPN artifact family is invalid" >&2; exit 1; }

PLIST="$TARGET_BUILD_DIR/$INFOPLIST_PATH"
[[ -f "$PLIST" ]] || { echo "Generated target Info.plist is missing: $PLIST" >&2; exit 1; }

set_key() {
  local key="$1" value="$2"
  if /usr/libexec/PlistBuddy -c "Print :$key" "$PLIST" >/dev/null 2>&1; then
    /usr/libexec/PlistBuddy -c "Set :$key $value" "$PLIST"
  else
    /usr/libexec/PlistBuddy -c "Add :$key string $value" "$PLIST"
  fi
}

set_key RouterVPNSourceSHA "$SHA"
set_key RouterVPNSourceRepository "$REPO"
set_key RouterVPNArtifactFamily "$FAMILY"

/usr/libexec/PlistBuddy -c "Print :RouterVPNSourceSHA" "$PLIST" | grep -Fx "$SHA" >/dev/null
/usr/libexec/PlistBuddy -c "Print :RouterVPNSourceRepository" "$PLIST" | grep -Fx "$REPO" >/dev/null
/usr/libexec/PlistBuddy -c "Print :RouterVPNArtifactFamily" "$PLIST" | grep -Fx "$FAMILY" >/dev/null
