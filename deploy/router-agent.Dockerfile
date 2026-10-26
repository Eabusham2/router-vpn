FROM golang:1.24.13-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /router-vpn-agent ./cmd/router-agent
RUN ROUTER_VPN_RELAY_FIXTURES_DIR=/relay-fixtures CGO_ENABLED=0 go test -count=1 -run 'TestExportPinnedCore(Relay|XrayRelay|PQRelay|NaiveRelay|CompositeRelay|MAXRelay)Configurations' ./internal/multihoprelay ./internal/mobilemultihop

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

# The static protocol library owns no networking. Runtime sockets and peer keys
# remain scoped to each native relay endpoint; test keys never enter the image.
FROM rust:1.99.0-alpine3.22 AS relay-pq-protocol
RUN apk add --no-cache build-base clang clang-dev cmake ninja linux-headers git python3
WORKDIR /pq
COPY mobile/rosenpass/ ./
# Cargo build scripts must load libclang on musl. Only these build-time tools
# link a dynamic CRT; the delivered Go executable is explicitly static below.
ENV CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CMAKE_GENERATOR=Ninja RUSTFLAGS="-C target-feature=-crt-static"
RUN rustc --version | grep -F 'rustc 1.99.0 ' \
 && cargo build --release --locked --lib \
 && cargo run --release --locked --example native_keys -- /pq-test-keys \
 && sha256sum Cargo.lock > /pq-Cargo.lock.sha256

# The relay runs the same pinned AWG and Xray implementations as the phone apps.
# Stock sing-box cannot interpret these owned native outbounds/endpoints.
FROM golang:1.26.3-alpine AS relay-core
ARG RELAY_CORE_COMMIT=1ac1a339cb1223e9c70eae14c44411c75033c02d
ARG RELAY_XRAY_COMMIT=50231eaff98ccc31b5cbd247a721c16e97fe5ec1
# The pinned Cronet musl archive uses LLVM CREL relocations. GNU ld rejects
# those ARM64 objects as "incompatible"; use native Clang/LLD for this link.
RUN apk add --no-cache git python3 build-base linux-headers ca-certificates clang21 lld21
WORKDIR /core
RUN git init -q . \
 && git fetch --depth=1 https://github.com/SagerNet/sing-box.git "${RELAY_CORE_COMMIT}" \
 && git checkout --detach FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "${RELAY_CORE_COMMIT}"
RUN git init -q /xray-core \
 && git -C /xray-core fetch --depth=1 https://github.com/XTLS/Xray-core.git "${RELAY_XRAY_COMMIT}" \
 && git -C /xray-core checkout --detach FETCH_HEAD \
 && test "$(git -C /xray-core rev-parse HEAD)" = "${RELAY_XRAY_COMMIT}"
COPY --from=build /src /routervpn-source
COPY --from=relay-pq-protocol /pq/target/release/libroutervpn_rosenpass.a /pq-native/libroutervpn_rosenpass.a
COPY --from=relay-pq-protocol /pq-test-keys /pq-native/keys
COPY --from=relay-pq-protocol /pq-Cargo.lock.sha256 /routervpn-pq-Cargo.lock.sha256
RUN python3 /routervpn-source/deploy/prepare-relay-core.py /core /xray-core \
 && go mod download github.com/amnezia-vpn/amneziawg-go/v3@v3.1.20260814 \
 && python3 /routervpn-source/deploy/test_server_pq_real.py --library /pq-native/libroutervpn_rosenpass.a --keys /pq-native/keys \
 && python3 /routervpn-source/deploy/test_server_pq_traffic.py --core /core --library /pq-native/libroutervpn_rosenpass.a --keys /pq-native/keys \
 && CGO_ENABLED=1 CC=clang CXX=clang++ python3 /routervpn-source/deploy/test_hysteria2_deadlines_pinned.py /core \
 && CGO_ENABLED=1 CGO_LDFLAGS='-fuse-ld=lld -L/pq-native' CC=clang CXX=clang++ go build -mod=mod -trimpath -tags with_quic,with_wireguard,with_gvisor,with_openvpn,routervpn_native_pq,with_naive_outbound,with_musl \
      -ldflags='-checklinkname=0 -linkmode external -extldflags "-static" -s -w -X github.com/sagernet/sing-box/constant.Version=1.14.1-routervpn' \
      -o /usr/local/bin/sing-box ./cmd/sing-box \
 && ! readelf -l /usr/local/bin/sing-box | grep -q INTERP \
 && python3 /routervpn-source/deploy/prepare-mobile-amnezia.py --verify-dependency /core \
 && python3 /routervpn-source/deploy/prepare-relay-core.py --digest > /routervpn-relay-source.sha256

FROM alpine:3.22
RUN apk add --no-cache nftables ca-certificates wireguard-tools iproute2 python3
COPY --from=build /router-vpn-agent /usr/local/bin/router-vpn-agent
COPY --from=relay-core /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY --from=build /relay-fixtures /tmp/relay-fixtures
COPY --from=relay-core /core/routervpn-amnezia-LICENSE.txt /usr/local/share/router-vpn/amneziawg-LICENSE.txt
COPY --from=relay-core /core/routervpn-xray-LICENSE.txt /usr/local/share/router-vpn/xray-LICENSE.txt
COPY --from=relay-core /routervpn-relay-source.sha256 /usr/local/share/router-vpn/relay-source.sha256
COPY --from=relay-core /routervpn-pq-Cargo.lock.sha256 /usr/local/share/router-vpn/pq-Cargo.lock.sha256
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
