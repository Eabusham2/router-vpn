FROM golang:1.25.12 AS go-build
WORKDIR /src/amneziawg-go
RUN mkdir -p /out \
 && git clone --branch v3.0.2 --depth 1 https://github.com/amnezia-vpn/amneziawg-go . \
 && go mod download \
 && go mod verify \
 && go build -ldflags '-linkmode external -extldflags "-fno-PIC -static"' -v -o /out/amneziawg-go .

FROM debian:bookworm AS tools-build
ARG AWGTOOLS_COMMIT=05434cab7d91bbbc607d18ec5fade91f4b83774c
RUN apt-get update && apt-get install -y --no-install-recommends git make gcc libc6-dev pkg-config linux-libc-dev && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/amnezia-vpn/amneziawg-tools /src/amneziawg-tools \
 && cd /src/amneziawg-tools \
 && git checkout "$AWGTOOLS_COMMIT" \
 && make -C src

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends bash iproute2 nftables openresolv procps ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=go-build /out/amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=tools-build /src/amneziawg-tools/src/wg /usr/bin/awg
COPY --from=tools-build /src/amneziawg-tools/src/wg-quick/linux.bash /usr/bin/awg-quick
COPY server/awg2/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/bin/awg /usr/bin/awg-quick
ENTRYPOINT ["/entrypoint.sh"]
