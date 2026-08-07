FROM ghcr.io/rosenpass/rosenpass:sha-00569eb AS rosenpass

FROM debian:bookworm AS tools-build
RUN apt-get update && apt-get install -y --no-install-recommends git make gcc libc6-dev pkg-config ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools /src/amneziawg-tools \
 && make -C /src/amneziawg-tools/src WITH_WGQUICK=no

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends bash ca-certificates diffutils iproute2 procps wireguard-tools \
 && rm -rf /var/lib/apt/lists/*
COPY --from=rosenpass /usr/local/bin/rosenpass /usr/local/bin/rosenpass
COPY --from=tools-build /src/amneziawg-tools/src/awg /usr/local/bin/awg
COPY modes/rosenpass-key-watch.sh /usr/local/lib/router-vpn/rosenpass-key-watch.sh
COPY server/rosenpass/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
