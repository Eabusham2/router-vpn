#!/usr/bin/env bash
set -euo pipefail

rm -rf dist
mkdir -p dist/client dist/router-agent

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
done

for target in windows/amd64 windows/arm64; do
  GOOS=${target%/*}
  GOARCH=${target#*/}
  echo "building portable launcher $GOOS/$GOARCH"
  env GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w -H=windowsgui' \
    -o "dist/client/RouterVPNPortable-${GOARCH}.exe" ./cmd/portable-launcher
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
  find . -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
