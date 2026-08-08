FROM ghcr.io/rosenpass/rosenpass:sha-00569eb AS rosenpass

FROM debian:bookworm AS tools-build
ARG AWGTOOLS_COMMIT=05434cab7d91bbbc607d18ec5fade91f4b83774c
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl make gcc libc6-dev pkg-config linux-libc-dev \
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
 && apt-get install -y --no-install-recommends bash ca-certificates diffutils iproute2 procps wireguard-tools \
 && rm -rf /var/lib/apt/lists/*
COPY --from=rosenpass /usr/local/bin/rosenpass /usr/local/bin/rosenpass
COPY --from=tools-build /src/amneziawg-tools/src/wg /usr/local/bin/awg
COPY modes/rosenpass-key-watch.sh /usr/local/lib/router-vpn/rosenpass-key-watch.sh
COPY server/rosenpass/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/awg
ENTRYPOINT ["/entrypoint.sh"]
