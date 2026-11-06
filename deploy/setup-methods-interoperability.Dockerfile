FROM rust:1.88.0-bookworm AS independent-client
ENV CARGO_BUILD_JOBS=2
RUN cargo install shadowsocks-rust --version 1.24.0 --locked --no-default-features \
      --features local,server,utility,aead-cipher,aead-cipher-2022,multi-threaded,logging \
      --bin sslocal --bin ssurl --root /out \
 && printf 'ffb45881cb155d64015a93b36278f4ee1e06d0c444857c3591715ba2bb87b355  %s\n' "${CARGO_HOME}/registry/cache/"*/shadowsocks-rust-1.24.0.crate | sha256sum --check -

FROM ghcr.io/sagernet/sing-box:v1.13.12 AS production-transport

FROM debian:bookworm-slim AS official-hysteria-client
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY deploy/fetch_hysteria_test_client.py /fetch_hysteria_test_client.py
RUN python3 /fetch_hysteria_test_client.py --arch "$TARGETARCH" --output /out/hysteria

FROM debian:bookworm-slim AS method-base
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 bash openssl ca-certificates qrencode \
 && rm -rf /var/lib/apt/lists/*
COPY --from=production-transport /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY deploy/test_aux_interoperability.py /src/deploy/
COPY server/scripts/ss_service_capability.py server/scripts/generate-transports.sh server/scripts/generate-setup-assets.py server/scripts/normalize-setup-imports.py server/scripts/import_payloads.py /src/server/scripts/
COPY server/scripts/atomic-private-write.py server/scripts/atomic-private-batch.py server/scripts/verified-regular-read.py server/scripts/preserve-generated-state.py /src/server/scripts/

COPY server/portainer-current.yaml /src/server/portainer-current.yaml

FROM method-base AS socks-method-import
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl nodejs iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY deploy/test_setup_socks_interoperability.py deploy/test_setup_overtls_interoperability.py deploy/run_aux_interoperability.py /src/deploy/
COPY configs/router/socks5.json.example /src/configs/router/socks5.json.example
COPY server/finalize/finalize.sh server/finalize/upgrade-safe.sh /src/server/finalize/
ENTRYPOINT ["python3", "/src/deploy/test_setup_socks_interoperability.py", "--sing-box", "/usr/local/bin/sing-box", "--curl", "/usr/bin/curl", "--node", "/usr/bin/node"]

FROM method-base AS hysteria-method-import
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl nodejs iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=official-hysteria-client /out/hysteria /usr/local/bin/hysteria
COPY --from=official-hysteria-client /out/hysteria.json /usr/local/share/router-vpn/hysteria-client.json
COPY deploy/test_setup_hysteria_interoperability.py deploy/fetch_hysteria_test_client.py deploy/test_setup_socks_interoperability.py deploy/test_setup_overtls_interoperability.py deploy/run_aux_interoperability.py /src/deploy/
ENTRYPOINT ["python3", "/src/deploy/test_setup_hysteria_interoperability.py", "--sing-box", "/usr/local/bin/sing-box", "--hysteria", "/usr/local/bin/hysteria", "--curl", "/usr/bin/curl", "--node", "/usr/bin/node"]

# Keep the existing unqualified build target as the Shadowsocks import gate.
FROM method-base AS shadowsocks-method-import
COPY --from=independent-client /out/bin/sslocal /out/bin/ssurl /usr/local/bin/
COPY deploy/test_setup_shadowsocks_interoperability.py /src/deploy/
ENTRYPOINT ["python3", "/src/deploy/test_setup_shadowsocks_interoperability.py", "--sing-box", "/usr/local/bin/sing-box", "--sslocal", "/usr/local/bin/sslocal", "--ssurl", "/usr/local/bin/ssurl"]
