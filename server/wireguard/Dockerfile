FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash iproute2 iptables nftables wireguard-tools ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY server/wireguard/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
 && /bin/bash -n /entrypoint.sh \
 && command -v iptables-legacy >/dev/null \
 && command -v ip6tables-legacy >/dev/null
ENTRYPOINT ["/entrypoint.sh"]
