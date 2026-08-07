#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -ne 0 ]] || { echo 'Run this as your normal Mac user, not with sudo.'; exit 1; }
BUNDLE=${1:-$(pwd)}
[[ -f "$BUNDLE/client/install-macos-current.sh" ]] || { echo 'Run from the extracted router-vpn-client-bundle folder.'; exit 1; }

bash "$BUNDLE/client/install-macos-current.sh" "$BUNDLE"

if ! /usr/local/bin/sing-box version 2>&1 | grep -q 'with_naive_outbound'; then
  echo 'Installing the official Naive-capable sing-box macOS release...'
  VERSION=1.13.12
  case "$(uname -m)" in
    arm64) ARCH=arm64 ;;
    x86_64) ARCH=amd64 ;;
    *) echo 'Unsupported Mac architecture for official sing-box release.' >&2; exit 1 ;;
  esac
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-darwin-${ARCH}.tar.gz" | tar -xz -C "$TMP"
  BIN="$TMP/sing-box-${VERSION}-darwin-${ARCH}/sing-box"
  [[ -x "$BIN" ]] || { echo 'Official sing-box binary was not found in the release archive.' >&2; exit 1; }
  "$BIN" version 2>&1 | grep -q 'with_naive_outbound' || { echo 'Official sing-box release does not report Naive support; leaving the mode disabled rather than mislabeling it.' >&2; exit 1; }
  sudo install -m 755 "$BIN" /usr/local/bin/sing-box
  sudo launchctl kickstart -k system/com.routervpn.client >/dev/null 2>&1 || true
fi

echo 'macOS client engines are installed. Open http://127.0.0.1:8788'
