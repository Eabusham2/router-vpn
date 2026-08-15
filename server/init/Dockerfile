FROM golang:1.24.13-alpine AS binaries
WORKDIR /src
COPY . .
RUN mkdir -p dist \
 && for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do \
      GOOS=${target%/*}; GOARCH=${target#*/}; ext=''; [ "$GOOS" = windows ] && ext='.exe'; \
      CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -trimpath -ldflags='-s -w' -o "dist/router-vpn-client-${GOOS}-${GOARCH}${ext}" ./cmd/client; \
      CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -trimpath -ldflags='-s -w' -o "dist/router-vpn-dns-${GOOS}-${GOARCH}${ext}" ./cmd/dnsproxy; \
    done \
 && for arch in amd64 arm64; do \
      CGO_ENABLED=0 GOOS=windows GOARCH=$arch go build -trimpath -ldflags='-s -w -H=windowsgui' -o "dist/RouterVPN-${arch}.exe" ./cmd/windows-app-launcher; \
      CGO_ENABLED=0 GOOS=windows GOARCH=$arch go build -trimpath -ldflags='-s -w -H=windowsgui' -o "dist/RouterVPNPortable-${arch}.exe" ./cmd/portable-launcher; \
      CGO_ENABLED=0 GOOS=windows GOARCH=$arch go build -trimpath -ldflags='-s -w -H=windowsgui' -o "dist/RouterVPNSetupRuntime-${arch}.exe" ./cmd/portable-runtime-setup; \
    done \
 && for target in linux/amd64 linux/arm64; do \
      GOOS=${target%/*}; GOARCH=${target#*/}; \
      CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -trimpath -ldflags='-s -w' -o "dist/router-vpn-agent-${GOOS}-${GOARCH}" ./cmd/router-agent; \
    done

# Runtime Go exists only for the bounded requested-package fallback. The normal
# path assembles from the exact-image prebuilt components above. Go is used only
# if a supported Windows/Portable component is unexpectedly absent. The
# native AppKit/GTK SDK environments are intentionally not installed here;
# macOS/Linux desktop fallback requires the exact-SHA native GitHub artifact.
FROM golang:1.24.13-bookworm AS go-toolchain

FROM ghcr.io/sagernet/sing-box:v1.13.12 AS singbox
FROM ghcr.io/xtls/xray-core:26.7.11 AS xray
FROM ghcr.io/rosenpass/rosenpass:sha-00569eb AS rosenpass

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates curl iproute2 iptables nftables openssl procps python3 qrencode wireguard-tools zip \
 && rm -rf /var/lib/apt/lists/*
COPY --from=go-toolchain /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
COPY --from=rosenpass /usr/local/bin/rosenpass /usr/local/bin/rosenpass
WORKDIR /src
COPY . /src
COPY --from=binaries /src/dist /src/dist
COPY server/init/noninteractive.sh /usr/local/bin/router-vpn-init
COPY server/init/entrypoint-v2.sh /usr/local/bin/router-vpn-init-entrypoint
RUN find /src -type f \( -name '*.sh' -o -name '*.py' \) -exec sed -i 's/\r$//' {} + \
 && find /src -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod 0755 {} + \
 && sed -i 's/\r$//' /usr/local/bin/router-vpn-init /usr/local/bin/router-vpn-init-entrypoint \
 && chmod 0755 /usr/local/bin/router-vpn-init /usr/local/bin/router-vpn-init-entrypoint \
 && /bin/bash -n /usr/local/bin/router-vpn-init \
 && /bin/bash -n /usr/local/bin/router-vpn-init-entrypoint \
 && /bin/bash -n /src/server/scripts/apply-runtime.sh \
 && go version \
 && /usr/local/bin/rosenpass --version >/dev/null \
 && command -v qrencode >/dev/null \
 && command -v sysctl >/dev/null \
 && command -v iptables-legacy >/dev/null \
 && command -v ip6tables-legacy >/dev/null \
 && test -x /src/server/scripts/generate-transports.sh \
 && test -x /src/server/scripts/generate-xray-pq.sh \
 && test -x /src/server/scripts/generate-setup-assets.py \
 && test -x /src/server/scripts/generate-aux-proxies.py \
 && test -x /src/server/scripts/create-bundle-json.py \
 && test -x /src/server/scripts/apply-runtime.sh \
 && test -x /src/server/scripts/build-download-on-demand.py \
 && test -x /src/server/scripts/download-broker.py \
 && test -f /src/dist/RouterVPN-amd64.exe \
 && test -f /src/dist/RouterVPN-arm64.exe \
 && test -f /src/dist/RouterVPNPortable-amd64.exe \
 && test -f /src/dist/RouterVPNPortable-arm64.exe \
 && test -f /src/dist/RouterVPNSetupRuntime-amd64.exe \
 && test -f /src/dist/RouterVPNSetupRuntime-arm64.exe
ENTRYPOINT ["/bin/bash", "/usr/local/bin/router-vpn-init-entrypoint"]
