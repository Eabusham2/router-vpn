FROM golang:1.24-alpine AS binaries
WORKDIR /src
COPY . .
RUN mkdir -p dist \
 && for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
      GOOS=${target%/*}; GOARCH=${target#*/}; ext=''; [ "$GOOS" = windows ] && ext='.exe'; \
      CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -trimpath -ldflags='-s -w' -o "dist/router-vpn-client-${GOOS}-${GOARCH}${ext}" ./cmd/client; \
      CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -trimpath -ldflags='-s -w' -o "dist/router-vpn-dns-${GOOS}-${GOARCH}${ext}" ./cmd/dnsproxy; \
    done \
 && for target in linux/amd64 linux/arm64; do \
      GOOS=${target%/*}; GOARCH=${target#*/}; \
      CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -trimpath -ldflags='-s -w' -o "dist/router-vpn-agent-${GOOS}-${GOARCH}" ./cmd/router-agent; \
    done

FROM ghcr.io/sagernet/sing-box:v1.13.12 AS singbox
FROM ghcr.io/xtls/xray-core:26.7.11 AS xray
FROM ghcr.io/rosenpass/rosenpass:sha-00569eb AS rosenpass

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates curl iproute2 nftables openssl python3 wireguard-tools zip \
 && rm -rf /var/lib/apt/lists/*
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
COPY --from=rosenpass /usr/local/bin/rosenpass /usr/local/bin/rosenpass
WORKDIR /src
COPY . /src
COPY --from=binaries /src/dist /src/dist
COPY server/init/noninteractive.sh /usr/local/bin/router-vpn-init
RUN find /src -type f \( -name '*.sh' -o -name '*.py' \) -exec sed -i 's/\r$//' {} + \
 && find /src -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod 0755 {} + \
 && sed -i 's/\r$//' /usr/local/bin/router-vpn-init \
 && chmod 0755 /usr/local/bin/router-vpn-init \
 && /bin/bash -n /usr/local/bin/router-vpn-init \
 && /usr/local/bin/rosenpass --version >/dev/null \
 && test -x /src/server/scripts/generate-transports.sh \
 && test -x /src/server/scripts/generate-xray-pq.sh \
 && test -x /src/server/scripts/create-bundle-json.py \
 && test -x /src/server/scripts/apply-runtime.sh
ENTRYPOINT ["/bin/bash", "/usr/local/bin/router-vpn-init"]
