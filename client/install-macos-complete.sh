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
    arm64) ARCH=arm64; EXPECTED_SHA256='43eef86f0ea4a79c3696974f397a963c46a457ee46d1ffac9aa913944a5fc986' ;;
    x86_64) ARCH=amd64; EXPECTED_SHA256='f3275316451bf1983bc059599c69c8ed0232d53a619d15cfd535f95cc9a4477a' ;;
    *) echo 'Unsupported Mac architecture for official sing-box release.' >&2; exit 1 ;;
  esac
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  ASSET="sing-box-${VERSION}-darwin-${ARCH}.tar.gz"
  MEMBER="sing-box-${VERSION}-darwin-${ARCH}/sing-box"
  ARCHIVE="$TMP/$ASSET"
  curl --proto '=https' --tlsv1.2 -fL --retry 5 --retry-all-errors --retry-delay 2 \
    "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/${ASSET}" -o "$ARCHIVE"
  ACTUAL_SHA256=$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')
  [[ "$ACTUAL_SHA256" == "$EXPECTED_SHA256" ]] || { echo 'Official sing-box archive checksum mismatch.' >&2; exit 1; }
  [[ $(tar -tzf "$ARCHIVE" | grep -Fx "$MEMBER" | wc -l | tr -d ' ') == 1 ]] || { echo 'Official sing-box archive member check failed.' >&2; exit 1; }
  tar -xzf "$ARCHIVE" -C "$TMP" "$MEMBER"
  BIN="$TMP/$MEMBER"
  [[ -x "$BIN" ]] || { echo 'Official sing-box binary was not found in the release archive.' >&2; exit 1; }
  "$BIN" version 2>&1 | grep -q 'with_naive_outbound' || { echo 'Official sing-box release does not report Naive support; leaving the mode disabled rather than mislabeling it.' >&2; exit 1; }
  sudo install -m 755 "$BIN" /usr/local/bin/sing-box
  sudo launchctl kickstart -k system/com.routervpn.client >/dev/null 2>&1 || true
fi

echo 'macOS client engines are installed. Open http://127.0.0.1:8788'
