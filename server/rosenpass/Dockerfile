FROM ghcr.io/rosenpass/rosenpass:sha-00569eb AS rosenpass

FROM debian:bookworm AS tools-build
ARG AWGTOOLS_COMMIT=05434cab7d91bbbc607d18ec5fade91f4b83774c
RUN apt-get update && apt-get install -y --no-install-recommends git make gcc libc6-dev pkg-config ca-certificates linux-libc-dev \
 && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/amnezia-vpn/amneziawg-tools /src/amneziawg-tools \
 && cd /src/amneziawg-tools \
 && git checkout "$AWGTOOLS_COMMIT" \
 && make -C src

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends bash ca-certificates diffutils iproute2 procps wireguard-tools \
 && rm -rf /var/lib/apt/lists/*
COPY --from=rosenpass /usr/local/bin/rosenpass /usr/local/bin/rosenpass
COPY --from=tools-build /src/amneziawg-tools/src/wg /usr/local/bin/awg
COPY modes/rosenpass-key-watch.sh /usr/local/lib/router-vpn/rosenpass-key-watch.sh
COPY server/rosenpass/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/awg
ENTRYPOINT ["/entrypoint.sh"]
