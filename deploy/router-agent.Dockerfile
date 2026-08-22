FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /router-vpn-agent ./cmd/router-agent

FROM alpine:3.22 AS awg-tools-build
ARG AWGTOOLS_COMMIT=5e882890fbca2316f8ca40e992789d24f67f0118
RUN apk add --no-cache build-base linux-headers curl tar \
 && mkdir -p /src/amneziawg-tools \
 && curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
      "https://codeload.github.com/amnezia-vpn/amneziawg-tools/tar.gz/${AWGTOOLS_COMMIT}" \
      -o /tmp/amneziawg-tools.tar.gz \
 && tar -xzf /tmp/amneziawg-tools.tar.gz -C /src/amneziawg-tools --strip-components=1 \
 && rm -f /tmp/amneziawg-tools.tar.gz \
 && make -C /src/amneziawg-tools/src \
 && test -x /src/amneziawg-tools/src/wg

FROM alpine:3.22
RUN apk add --no-cache nftables ca-certificates wireguard-tools iproute2
COPY --from=build /router-vpn-agent /usr/local/bin/router-vpn-agent
COPY --from=awg-tools-build /src/amneziawg-tools/src/wg /usr/local/bin/awg
RUN chmod 0755 /usr/local/bin/awg \
 && command -v wg >/dev/null \
 && command -v awg >/dev/null
ENTRYPOINT ["/usr/local/bin/router-vpn-agent"]
