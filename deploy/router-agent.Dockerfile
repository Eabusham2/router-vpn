FROM golang:1.24.13-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /router-vpn-agent ./cmd/router-agent
RUN ROUTER_VPN_RELAY_FIXTURES_DIR=/relay-fixtures CGO_ENABLED=0 go test -count=1 -run TestExportPinnedCoreRelayConfigurations ./internal/multihoprelay

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

# The relay runs the same pinned AWG endpoint implementation as the phone apps.
# Stock sing-box cannot interpret routervpn-amneziawg and is not a substitute.
FROM golang:1.26.3-alpine AS relay-core
ARG RELAY_CORE_COMMIT=1ac1a339cb1223e9c70eae14c44411c75033c02d
RUN apk add --no-cache git python3 build-base linux-headers ca-certificates
WORKDIR /core
RUN git init -q . \
 && git fetch --depth=1 https://github.com/SagerNet/sing-box.git "${RELAY_CORE_COMMIT}" \
 && git checkout --detach FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "${RELAY_CORE_COMMIT}"
COPY --from=build /src /routervpn-source
RUN python3 /routervpn-source/deploy/prepare-relay-core.py /core \
 && go mod download github.com/amnezia-vpn/amneziawg-go/v3@v3.1.20260814 \
 && CGO_ENABLED=0 go build -mod=mod -trimpath -tags with_quic,with_wireguard,with_gvisor \
      -ldflags='-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.1-routervpn' \
      -o /usr/local/bin/sing-box ./cmd/sing-box \
 && python3 /routervpn-source/deploy/prepare-mobile-amnezia.py --verify-dependency /core \
 && python3 /routervpn-source/deploy/prepare-relay-core.py --digest > /routervpn-relay-source.sha256

FROM alpine:3.22
RUN apk add --no-cache nftables ca-certificates wireguard-tools iproute2 python3
COPY --from=build /router-vpn-agent /usr/local/bin/router-vpn-agent
COPY --from=relay-core /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY --from=build /relay-fixtures /tmp/relay-fixtures
COPY --from=relay-core /core/routervpn-amnezia-LICENSE.txt /usr/local/share/router-vpn/amneziawg-LICENSE.txt
COPY --from=relay-core /routervpn-relay-source.sha256 /usr/local/share/router-vpn/relay-source.sha256
RUN sing-box version | grep -F "sing-box version 1.14.1-routervpn" \
 && for config in /tmp/relay-fixtures/*.json; do sing-box check -c "$config" || exit 1; done \
 && rm -rf /tmp/relay-fixtures
COPY --from=awg-tools-build /src/amneziawg-tools/src/wg /usr/local/bin/awg
RUN chmod 0755 /usr/local/bin/awg \
 && command -v wg >/dev/null \
 && command -v awg >/dev/null
COPY server/scripts/provision-multihop-relays.py server/scripts/verified-regular-read.py server/scripts/atomic-private-write.py /usr/local/lib/router-vpn-relay/
RUN chmod 0755 /usr/local/lib/router-vpn-relay/provision-multihop-relays.py \
 && ln -s /usr/local/lib/router-vpn-relay/provision-multihop-relays.py /usr/local/bin/router-vpn-relay-pair
ENTRYPOINT ["/usr/local/bin/router-vpn-agent"]
