FROM golang:1.24.13-alpine AS start-layer-build
WORKDIR /src
COPY go.mod ./
COPY cmd/start-layer-relay ./cmd/start-layer-relay
COPY internal/startwhitening ./internal/startwhitening
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/router-vpn-start-layer-relay ./cmd/start-layer-relay

FROM rust:1.88.0-bookworm AS overtls-build
ARG OVERTLS_VERSION=0.3.12
RUN cargo install overtls --version "${OVERTLS_VERSION}" --locked --root /out \
 && /out/bin/overtls-bin --version >/dev/null

FROM debian:bookworm AS ssr-build
ARG SSR_COMMIT=227127c4bc5a6555e0556693d084c96860e75b5e
COPY server/aux-proxies/patches/ssr-stable-obfs-layout.patch /patches/ssr-stable-obfs-layout.patch
COPY server/aux-proxies/test-ssr-obfs-abi.sh /tests/test-ssr-obfs-abi.sh
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential autoconf automake cmake git libtool pkg-config ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && git init /src/ssr \
 && git -C /src/ssr remote add origin https://github.com/ShadowsocksR-Live/shadowsocksr-native.git \
 && git -C /src/ssr fetch --depth 1 origin "${SSR_COMMIT}" \
 && git -C /src/ssr checkout --detach FETCH_HEAD \
 && test "$(git -C /src/ssr rev-parse HEAD)" = "${SSR_COMMIT}" \
 && git -C /src/ssr submodule update --init --recursive --depth 1 \
 && echo "245edf8e21b2dd9d3dda4a5270b2f74a19081212fe1f92162760903bf84b6820  /patches/ssr-stable-obfs-layout.patch" | sha256sum --check - \
 && git -C /src/ssr apply --check /patches/ssr-stable-obfs-layout.patch \
 && git -C /src/ssr apply /patches/ssr-stable-obfs-layout.patch \
 && cmake -S /src/ssr -B /src/ssr/build -DCMAKE_BUILD_TYPE=Release \
 && sh /tests/test-ssr-obfs-abi.sh /src/ssr /src/ssr/build \
 && cmake --build /src/ssr/build --parallel 2 \
 && test -x /src/ssr/build/src/ssr-server \
 && /src/ssr/build/src/ssr-server -h >/dev/null 2>&1

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=start-layer-build /out/router-vpn-start-layer-relay /usr/local/bin/router-vpn-start-layer-relay
COPY --from=overtls-build /out/bin/overtls-bin /usr/local/bin/overtls-bin
COPY --from=ssr-build /src/ssr/build/src/ssr-server /usr/local/bin/ssr-server
COPY --chmod=0755 server/aux-proxies/entrypoint.sh /usr/local/bin/router-vpn-aux-proxies
RUN /usr/local/bin/router-vpn-start-layer-relay -h >/dev/null \
 && /usr/local/bin/overtls-bin --version >/dev/null \
 && /usr/local/bin/ssr-server -h >/dev/null 2>&1
ENTRYPOINT ["/usr/local/bin/router-vpn-aux-proxies"]