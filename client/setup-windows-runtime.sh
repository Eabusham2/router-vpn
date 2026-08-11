#!/usr/bin/env bash
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo 'Run this inside WSL with sudo.' >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl git make gcc libc6-dev golang-go python3 tar xz-utils \
  cmake clang pkg-config libsodium-dev cargo rustc wireguard-tools resolvconf

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! command -v xray >/dev/null 2>&1; then
  bash "$SCRIPT_DIR/install-xray.sh"
fi

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) SB_ARCH=amd64 ;;
  aarch64|arm64) SB_ARCH=arm64 ;;
  *) echo "Unsupported WSL architecture: $ARCH" >&2; exit 1 ;;
esac

# Use the official sing-box build so Naive H2/H3 has the same build tags and
# libcronet support as the normal Linux/macOS Router VPN setup.
if ! command -v sing-box >/dev/null 2>&1 || ! sing-box version 2>&1 | grep -q 'with_naive_outbound' || [[ ! -s /usr/local/lib/libcronet.so && ! -s /usr/local/bin/libcronet.so ]]; then
  SB_VER=1.13.12
  TMP_SB=$(mktemp -d)
  trap 'rm -rf "$TMP_SB"' EXIT
  curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-${SB_ARCH}.tar.gz" | tar -xz -C "$TMP_SB"
  SB_DIR="$TMP_SB/sing-box-${SB_VER}-linux-${SB_ARCH}"
  install -m 755 "$SB_DIR/sing-box" /usr/local/bin/sing-box
  CRONET=$(find "$SB_DIR" -type f -name libcronet.so -print -quit)
  [[ -n "$CRONET" && -s "$CRONET" ]] || { echo 'Official sing-box archive did not contain libcronet.so.' >&2; exit 1; }
  install -m 755 "$CRONET" /usr/local/lib/libcronet.so
  command -v ldconfig >/dev/null 2>&1 && ldconfig || true
  rm -rf "$TMP_SB"
  trap - EXIT
fi

if ! command -v rosenpass >/dev/null 2>&1; then
  TMP_RP=$(mktemp -d)
  git clone https://github.com/rosenpass/rosenpass "$TMP_RP/rosenpass"
  (cd "$TMP_RP/rosenpass" && git checkout 00569eb && cargo build --release --bin rosenpass)
  install -m 755 "$TMP_RP/rosenpass/target/release/rosenpass" /usr/local/bin/rosenpass
  rm -rf "$TMP_RP"
fi

if ! command -v sslocal >/dev/null 2>&1; then
  cargo install --locked --version 1.24.0 shadowsocks-rust
  install -m 755 "${CARGO_HOME:-/root/.cargo}/bin/sslocal" /usr/local/bin/sslocal
fi

if ! command -v v2ray-plugin >/dev/null 2>&1; then
  TMP_V2=$(mktemp -d)
  git clone https://github.com/shadowsocks/v2ray-plugin "$TMP_V2/v2ray-plugin"
  (cd "$TMP_V2/v2ray-plugin" && git checkout e9af1cdd2549d528deb20a4ab8d61c5fbe51f306 && GOTOOLCHAIN=auto go build -trimpath -ldflags='-s -w' -o v2ray-plugin .)
  install -m 755 "$TMP_V2/v2ray-plugin/v2ray-plugin" /usr/local/bin/v2ray-plugin
  rm -rf "$TMP_V2"
fi

if ! command -v amneziawg-go >/dev/null 2>&1 || ! command -v awg >/dev/null 2>&1 || ! command -v awg-quick >/dev/null 2>&1; then
  TMP_AWG=$(mktemp -d)
  git clone --branch v3.0.2 --depth 1 https://github.com/amnezia-vpn/amneziawg-go "$TMP_AWG/amneziawg-go"
  (cd "$TMP_AWG/amneziawg-go" && GOTOOLCHAIN=auto go mod download && GOTOOLCHAIN=auto go mod verify && GOTOOLCHAIN=auto go build -trimpath -o amneziawg-go .)
  install -m 755 "$TMP_AWG/amneziawg-go/amneziawg-go" /usr/local/bin/amneziawg-go

  # Fetch only the pinned tools commit. A shallow branch clone followed by a
  # detached checkout can fail when the pinned commit is outside the shallow tip.
  git init "$TMP_AWG/amneziawg-tools"
  git -C "$TMP_AWG/amneziawg-tools" remote add origin https://github.com/amnezia-vpn/amneziawg-tools.git
  git -C "$TMP_AWG/amneziawg-tools" fetch --depth=1 origin 05434cab7d91bbbc607d18ec5fade91f4b83774c
  git -C "$TMP_AWG/amneziawg-tools" checkout --detach FETCH_HEAD
  make -C "$TMP_AWG/amneziawg-tools/src" WITH_WGQUICK=yes
  make -C "$TMP_AWG/amneziawg-tools/src" install WITH_WGQUICK=yes PREFIX=/usr/local
  rm -rf "$TMP_AWG"
fi

missing=0
for cmd in wg wg-quick sing-box xray rosenpass sslocal v2ray-plugin amneziawg-go awg awg-quick python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "MISSING after setup: $cmd" >&2
    missing=1
  else
    printf 'OK: %-16s %s\n' "$cmd" "$(command -v "$cmd")"
  fi
done
[[ $missing -eq 0 ]] || exit 1

sing-box version 2>&1 | grep -q 'with_naive_outbound' || { echo 'sing-box still lacks Naive outbound support.' >&2; exit 1; }
[[ -s /usr/local/lib/libcronet.so || -s /usr/local/bin/libcronet.so ]] || { echo 'libcronet.so is still missing.' >&2; exit 1; }

echo 'Windows WSL Router VPN runtime is ready.'
