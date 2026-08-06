FROM ghcr.io/sagernet/sing-box:1.13.12 AS singbox
FROM alpine:3.22
RUN apk add --no-cache bash curl iproute2 nftables openssl python3 wireguard-tools zip
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
WORKDIR /src
COPY . /src
COPY server/init/noninteractive.sh /usr/local/bin/router-vpn-init
RUN chmod +x /usr/local/bin/router-vpn-init
ENTRYPOINT ["/usr/local/bin/router-vpn-init"]
