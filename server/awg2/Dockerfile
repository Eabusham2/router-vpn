FROM golang:1.25.12-bookworm AS go-build
ARG AWG_GO_TAG=v3.0.2
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gzip tar \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src/amneziawg-go
RUN mkdir -p /out \
 && curl -fL --retry 5 --retry-delay 2 \
      "https://github.com/amnezia-vpn/amneziawg-go/archive/refs/tags/${AWG_GO_TAG}.tar.gz" \
      -o /tmp/amneziawg-go.tar.gz \
 && tar -xzf /tmp/amneziawg-go.tar.gz -C /src/amneziawg-go --strip-components=1 \
 && rm -f /tmp/amneziawg-go.tar.gz \
 && go mod download \
 && go mod verify \
 && go build -ldflags '-linkmode external -extldflags "-fno-PIC -static"' -v -o /out/amneziawg-go .

FROM debian:bookworm AS tools-build
ARG AWGTOOLS_COMMIT=05434cab7d91bbbc607d18ec5fade91f4b83774c
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gzip tar make gcc libc6-dev pkg-config linux-libc-dev \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /src/amneziawg-tools \
 && curl -fL --retry 5 --retry-delay 2 \
      "https://github.com/amnezia-vpn/amneziawg-tools/archive/${AWGTOOLS_COMMIT}.tar.gz" \
      -o /tmp/amneziawg-tools.tar.gz \
 && tar -xzf /tmp/amneziawg-tools.tar.gz -C /src/amneziawg-tools --strip-components=1 \
 && rm -f /tmp/amneziawg-tools.tar.gz \
 && make -C /src/amneziawg-tools/src

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash iproute2 nftables openresolv procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=go-build /out/amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=tools-build /src/amneziawg-tools/src/wg /usr/bin/awg
COPY --from=tools-build /src/amneziawg-tools/src/wg-quick/linux.bash /usr/bin/awg-quick
COPY server/awg2/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/bin/awg /usr/bin/awg-quick
ENTRYPOINT ["/entrypoint.sh"]
