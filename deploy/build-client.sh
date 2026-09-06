#!/usr/bin/env bash
set -euo pipefail

rm -rf dist
mkdir -p dist/client dist/dnsproxy dist/start-layer dist/router-agent dist/app-update

client_targets=(
  windows/amd64 windows/arm64
  darwin/amd64 darwin/arm64
  linux/amd64 linux/arm64 linux/arm
  freebsd/amd64 freebsd/arm64
  openbsd/amd64 openbsd/arm64
  netbsd/amd64 netbsd/arm64
  dragonfly/amd64
  illumos/amd64
)

for target in "${client_targets[@]}"; do
  GOOS=${target%/*}
  GOARCH=${target#*/}
  ext=''
  [[ $GOOS == windows ]] && ext='.exe'
  suffix="${GOOS}-${GOARCH}"
  [[ $GOARCH == arm ]] && suffix="${suffix}-v7"
  echo "building client $GOOS/$GOARCH"
  output="dist/client/router-vpn-client-${suffix}${ext}"
  env GOOS="$GOOS" GOARCH="$GOARCH" GOARM=7 CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w' -o "$output" ./cmd/client
  cp "$output" "dist/$(basename "$output")"

  echo "building DNS helper $GOOS/$GOARCH"
  dns_output="dist/dnsproxy/router-vpn-dns-${suffix}${ext}"
  env GOOS="$GOOS" GOARCH="$GOARCH" GOARM=7 CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w' -o "$dns_output" ./cmd/dnsproxy
  cp "$dns_output" "dist/$(basename "$dns_output")"

  echo "building start-layer relay $GOOS/$GOARCH"
  relay_output="dist/start-layer/router-vpn-start-layer-relay-${suffix}${ext}"
  env GOOS="$GOOS" GOARCH="$GOARCH" GOARM=7 CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w' -o "$relay_output" ./cmd/start-layer-relay
  cp "$relay_output" "dist/$(basename "$relay_output")"
done

# The self-update helper is intentionally limited to mainstream desktop
# platforms whose exact-SHA release assets have a real install/staging path.
for target in windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do
  GOOS=${target%/*}
  GOARCH=${target#*/}
  ext=''
  [[ $GOOS == windows ]] && ext='.exe'
  echo "building exact-SHA app updater $GOOS/$GOARCH"
  output="dist/app-update/router-vpn-update-${GOOS}-${GOARCH}${ext}"
  env GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w' -o "$output" ./cmd/app-update
  cp "$output" "dist/$(basename "$output")"
done

for target in windows/amd64 windows/arm64; do
  GOOS=${target%/*}
  GOARCH=${target#*/}
  echo "building normal and portable Windows launchers $GOOS/$GOARCH"
  env GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w -H=windowsgui' \
    -o "dist/client/RouterVPN-${GOARCH}.exe" ./cmd/windows-app-launcher
  # Keep the mature Portable runtime owner as an internal core and put the
  # update-aware supervisor at the public RouterVPNPortable.exe boundary.
  env GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w -H=windowsgui' \
    -o "dist/client/RouterVPNPortableCore-${GOARCH}.exe" ./cmd/portable-launcher
  env GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w -H=windowsgui' \
    -o "dist/client/RouterVPNPortable-${GOARCH}.exe" ./cmd/portable-bootstrap
  env GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w -H=windowsgui' \
    -o "dist/client/RouterVPNSetupRuntime-${GOARCH}.exe" ./cmd/portable-runtime-setup
done

for target in linux/amd64 linux/arm64; do
  GOOS=${target%/*}
  GOARCH=${target#*/}
  echo "building router agent $GOOS/$GOARCH"
  output="dist/router-agent/router-vpn-agent-${GOOS}-${GOARCH}"
  env GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w' -o "$output" ./cmd/router-agent
  cp "$output" "dist/$(basename "$output")"
done

(
  cd dist
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)