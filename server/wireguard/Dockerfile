FROM alpine:3.22
RUN apk add --no-cache bash iproute2 nftables wireguard-tools
COPY server/wireguard/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
