FROM ghcr.io/rosenpass/rosenpass:sha-00569eb AS rosenpass

FROM debian:bookworm AS tools-build
ARG AWGTOOLS_COMMIT=5e882890fbca2316f8ca40e992789d24f67f0118
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gzip tar make gcc libc6-dev pkg-config linux-libc-dev \
 && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    mkdir -p /src/amneziawg-tools; \
    fetch_tar() { \
      out="$1"; shift; \
      for url in "$@"; do \
        if curl -fL --retry 5 --retry-all-errors --retry-delay 2 "$url" -o "$out"; then return 0; fi; \
      done; \
      return 1; \
    }; \
    fetch_tar /tmp/amneziawg-tools.tar.gz \
      "https://codeload.github.com/amnezia-vpn/amneziawg-tools/tar.gz/${AWGTOOLS_COMMIT}" \
      "https://github.com/amnezia-vpn/amneziawg-tools/archive/${AWGTOOLS_COMMIT}.tar.gz"; \
    tar -xzf /tmp/amneziawg-tools.tar.gz -C /src/amneziawg-tools --strip-components=1; \
    rm -f /tmp/amneziawg-tools.tar.gz; \
    make -C /src/amneziawg-tools/src

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
