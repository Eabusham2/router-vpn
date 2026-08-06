FROM golang:1.24-bookworm AS go-build
RUN apt-get update && apt-get install -y --no-install-recommends git make ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go /src/amneziawg-go && make -C /src/amneziawg-go
FROM debian:bookworm AS tools-build
RUN apt-get update && apt-get install -y --no-install-recommends git make gcc libc6-dev pkg-config && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools /src/amneziawg-tools && make -C /src/amneziawg-tools/src WITH_WGQUICK=yes && make -C /src/amneziawg-tools/src install WITH_WGQUICK=yes
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends bash iproute2 nftables openresolv procps ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=go-build /src/amneziawg-go/amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=tools-build /usr/bin/awg /usr/bin/awg
COPY --from=tools-build /usr/bin/awg-quick /usr/bin/awg-quick
COPY server/awg2/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
