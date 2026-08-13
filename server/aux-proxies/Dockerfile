FROM rust:1.88-bookworm AS overtls-build
ARG OVERTLS_VERSION=0.3.12
RUN cargo install overtls --version "${OVERTLS_VERSION}" --locked --root /out \
 && /out/bin/overtls-bin --version >/dev/null

FROM debian:bookworm AS ssr-build
ARG SSR_COMMIT=227127c4bc5a6555e0556693d084c96860e75b5e
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential autoconf automake cmake git libtool pkg-config ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && git init /src/ssr \
 && git -C /src/ssr remote add origin https://github.com/ShadowsocksR-Live/shadowsocksr-native.git \
 && git -C /src/ssr fetch --depth 1 origin "${SSR_COMMIT}" \
 && git -C /src/ssr checkout --detach FETCH_HEAD \
 && test "$(git -C /src/ssr rev-parse HEAD)" = "${SSR_COMMIT}" \
 && git -C /src/ssr submodule update --init --recursive --depth 1 \
 && cmake -S /src/ssr -B /src/ssr/build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /src/ssr/build --parallel 2 \
 && test -x /src/ssr/build/src/ssr-server \
 && /src/ssr/build/src/ssr-server -h >/dev/null 2>&1

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=overtls-build /out/bin/overtls-bin /usr/local/bin/overtls-bin
COPY --from=ssr-build /src/ssr/build/src/ssr-server /usr/local/bin/ssr-server
COPY --chmod=0755 server/aux-proxies/entrypoint.sh /usr/local/bin/router-vpn-aux-proxies
RUN /usr/local/bin/overtls-bin --version >/dev/null \
 && /usr/local/bin/ssr-server -h >/dev/null 2>&1
ENTRYPOINT ["/usr/local/bin/router-vpn-aux-proxies"]
