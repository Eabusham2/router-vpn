#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -ne 0 ]] || { echo 'Run this as your normal Mac user, not with sudo.' >&2; exit 1; }

BUNDLE=${1:-$(pwd)}
BUNDLE=$(cd "$BUNDLE" && pwd -P)
APP_SRC="$BUNDLE/RouterVPN.app"
[[ -x "$APP_SRC/Contents/MacOS/RouterVPN" ]] || { echo 'This package does not contain the native RouterVPN.app.' >&2; exit 1; }
[[ -x "$BUNDLE/router-vpn-client" && -f "$BUNDLE/client.json" ]] || { echo 'Native Router VPN runtime files are missing from this package.' >&2; exit 1; }
[[ -f "$BUNDLE/LICENSE" ]] || { echo 'Router VPN LICENSE is missing from this package.' >&2; exit 1; }

# Install/refresh the macOS engine prerequisites and private local controller
# service. That service remains an implementation detail; everyday use is the
# native AppKit application below, never a browser/PWA launcher.
bash "$BUNDLE/client/install-macos-complete.sh" "$BUNDLE"

INSTALL_PARENT="$HOME/Applications"
INSTALL_ROOT="$INSTALL_PARENT/Router VPN"
STAGE="$INSTALL_PARENT/.router-vpn-install-$$"
BACKUP="$INSTALL_PARENT/.router-vpn-backup-$$"
mkdir -p "$INSTALL_PARENT"
rm -rf "$STAGE" "$BACKUP"
mkdir -m 700 "$STAGE"
cleanup() { rm -rf "$STAGE" "$BACKUP"; }
trap cleanup EXIT INT TERM HUP

# Copy the generic package, but never replace already-linked private node or
# custom-exit state with a blank package file during an upgrade.
/usr/bin/ditto --noqtn "$BUNDLE" "$STAGE"
for state in routers.json standard-exits.json; do
  if [[ -f "$INSTALL_ROOT/$state" ]]; then
    cp -p "$INSTALL_ROOT/$state" "$STAGE/$state"
    chmod 600 "$STAGE/$state" 2>/dev/null || true
  fi
done
if [[ -d "$INSTALL_ROOT/generated" ]]; then
  rm -rf "$STAGE/generated"
  cp -a "$INSTALL_ROOT/generated" "$STAGE/generated"
fi

# Prevent accidental secrets from becoming group/world readable when package
# extraction umasks differ.
chmod 700 "$STAGE"
[[ ! -e "$STAGE/routers.json" ]] || chmod 600 "$STAGE/routers.json"
[[ ! -e "$STAGE/standard-exits.json" ]] || chmod 600 "$STAGE/standard-exits.json"

"$STAGE/RouterVPN.app/Contents/MacOS/RouterVPN" --self-test
! grep -RIlE --include='*' 'chrome.*--app=|Microsoft Edge.*--app=|Brave Browser.*--app=|open[[:space:]].*127\.0\.0\.1:8788' "$STAGE/RouterVPN.app/Contents" >/dev/null

if [[ -e "$INSTALL_ROOT" ]]; then mv "$INSTALL_ROOT" "$BACKUP"; fi
if ! mv "$STAGE" "$INSTALL_ROOT"; then
  [[ ! -e "$BACKUP" ]] || mv "$BACKUP" "$INSTALL_ROOT"
  echo 'Native Router VPN install failed; previous installation was restored.' >&2
  exit 1
fi
rm -rf "$BACKUP"
trap - EXIT INT TERM HUP

/usr/bin/xattr -dr com.apple.quarantine "$INSTALL_ROOT/RouterVPN.app" 2>/dev/null || true
/usr/bin/open "$INSTALL_ROOT/RouterVPN.app"
printf 'Router VPN native macOS app installed at:\n  %s\n' "$INSTALL_ROOT/RouterVPN.app"
printf 'The local 127.0.0.1:8788 controller remains private recovery/API plumbing; it is not the daily app UI.\n'
