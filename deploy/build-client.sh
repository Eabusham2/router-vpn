#!/usr/bin/env bash
set -euo pipefail
mkdir -p dist
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
  GOOS=${target%/*}; GOARCH=${target#*/}; ext=''; [[ $GOOS == windows ]] && ext='.exe'
  echo "building client $GOOS/$GOARCH"
  GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "dist/router-vpn-client-${GOOS}-${GOARCH}${ext}" ./cmd/client
done
for target in linux/amd64 linux/arm64; do
  GOOS=${target%/*}; GOARCH=${target#*/}
  echo "building router agent $GOOS/$GOARCH"
  GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "dist/router-vpn-agent-${GOOS}-${GOARCH}" ./cmd/router-agent
done
