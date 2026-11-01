FROM golang:1.24.13-alpine AS start-layer-build
WORKDIR /src
COPY go.mod ./
COPY cmd/start-layer-relay ./cmd/start-layer-relay
COPY internal/startwhitening ./internal/startwhitening
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/router-vpn-start-layer-relay ./cmd/start-layer-relay

FROM rust:1.88.0-bookworm AS overtls-upstream-build
ARG OVERTLS_VERSION=0.3.12
ENV CARGO_TARGET_DIR=/build-target
RUN cargo install overtls --version "${OVERTLS_VERSION}" --locked --root /out \
 && /out/bin/overtls-bin --version >/dev/null

FROM overtls-upstream-build AS overtls-build
COPY server/aux-proxies/patches/overtls-preserve-selected-dns.patch /patches/overtls-preserve-selected-dns.patch
RUN echo "a419065664a0abbf1bb13e2711c19aca4c0efea5b3df077ff33128d077a8a88e  /patches/overtls-preserve-selected-dns.patch" | sha256sum --check - \
 && printf '65ddf4401a40f832aaf0d368886c882c2acacfab787ee3bc5786f4b095a528f4  %s\n' "${CARGO_HOME}/registry/cache/"*/"overtls-${OVERTLS_VERSION}.crate" | sha256sum --check - \
 && mkdir -p /src \
 && cp -a "${CARGO_HOME}/registry/src/"*/"overtls-${OVERTLS_VERSION}" /src/overtls-production \
 && git -C /src/overtls-production apply --check /patches/overtls-preserve-selected-dns.patch \
 && git -C /src/overtls-production apply /patches/overtls-preserve-selected-dns.patch \
 && cargo install --path /src/overtls-production --locked --offline --force --root /out

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

# The two reference clients preserve their upstream wire protocols. Their
# SOCKS UDP envelope corrections are explicit and confined to test-only stages.
FROM ssr-build AS ssr-reference-client
COPY server/aux-proxies/patches/ssr-client-udp-returned-address.patch /patches/ssr-client-udp-returned-address.patch
RUN echo "99be69c6474a504f74f1894dcb5e97773b4ba9ad3121b48dea709beb7855259c  /patches/ssr-client-udp-returned-address.patch" | sha256sum --check - \
 && git -C /src/ssr apply --check /patches/ssr-client-udp-returned-address.patch \
 && git -C /src/ssr apply /patches/ssr-client-udp-returned-address.patch \
 && cmake --build /src/ssr/build --target ssr-client --parallel 2

FROM overtls-upstream-build AS overtls-reference-client
COPY server/aux-proxies/patches/overtls-client-udp-returned-address.patch /patches/overtls-client-udp-returned-address.patch
RUN echo "952d071aea5e60b06e349cc754a8b663309aff259d019a36d082f05c8bf2e9cb  /patches/overtls-client-udp-returned-address.patch" | sha256sum --check - \
 && printf '65ddf4401a40f832aaf0d368886c882c2acacfab787ee3bc5786f4b095a528f4  %s\n' "${CARGO_HOME}/registry/cache/"*/"overtls-${OVERTLS_VERSION}.crate" | sha256sum --check - \
 && mkdir -p /src \
 && cp -a "${CARGO_HOME}/registry/src/"*/"overtls-${OVERTLS_VERSION}" /src/overtls \
 && git -C /src/overtls apply --check /patches/overtls-client-udp-returned-address.patch \
 && git -C /src/overtls apply /patches/overtls-client-udp-returned-address.patch \
 && cargo install --path /src/overtls --locked --offline --root /reference-client

FROM pocat/naiveproxy:v2.11.4-uot AS interop-caddy

# Test-only clients and local TLS tooling. The final production image below
# still contains only the existing server programs and start-layer relay.
FROM debian:bookworm-slim AS aux-interoperability
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates python3 openssl iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=overtls-build /out/bin/overtls-bin /usr/local/bin/overtls-bin
COPY --from=overtls-upstream-build /out/bin/overtls-bin /usr/local/bin/overtls-stock
COPY --from=overtls-reference-client /reference-client/bin/overtls-bin /usr/local/bin/overtls-reference-client
COPY --from=ssr-build /src/ssr/build/src/ssr-server /usr/local/bin/ssr-server
COPY --from=ssr-build /src/ssr/build/src/ssr-client /usr/local/bin/ssr-stock-client
COPY --from=ssr-reference-client /src/ssr/build/src/ssr-client /usr/local/bin/ssr-reference-client
COPY --from=interop-caddy /usr/bin/caddy /usr/local/bin/caddy
COPY deploy/test_aux_interoperability.py deploy/run_aux_interoperability.py /src/deploy/
COPY server/scripts/generate-aux-proxies.py server/scripts/atomic-private-batch.py /src/server/scripts/
COPY server/naive/entrypoint.sh server/naive/Dockerfile /src/server/naive/
ENTRYPOINT ["python3", "/src/deploy/run_aux_interoperability.py", "--overtls-server", "/usr/local/bin/overtls-bin", "--overtls-client", "/usr/local/bin/overtls-reference-client", "--overtls-stock-client", "/usr/local/bin/overtls-stock", "--ssr-server", "/usr/local/bin/ssr-server", "--ssr-client", "/usr/local/bin/ssr-reference-client", "--ssr-stock-client", "/usr/local/bin/ssr-stock-client", "--caddy", "/usr/local/bin/caddy", "--openssl", "/usr/bin/openssl"]

FROM aux-interoperability AS aux-dns-interoperability
COPY deploy/test_aux_dns_interoperability.py /src/deploy/test_aux_dns_interoperability.py
ENTRYPOINT ["python3", "/src/deploy/test_aux_dns_interoperability.py", "--overtls-server", "/usr/local/bin/overtls-bin", "--overtls-client", "/usr/local/bin/overtls-reference-client", "--overtls-stock-server", "/usr/local/bin/overtls-stock", "--caddy", "/usr/local/bin/caddy", "--openssl", "/usr/bin/openssl"]

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
