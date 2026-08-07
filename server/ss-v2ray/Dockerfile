FROM golang:1.24-alpine AS plugin
RUN apk add --no-cache git
RUN git clone --depth 1 https://github.com/shadowsocks/v2ray-plugin /src/v2ray-plugin \
 && cd /src/v2ray-plugin \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/v2ray-plugin .

FROM ghcr.io/shadowsocks/ssserver-rust:latest
COPY --from=plugin /out/v2ray-plugin /usr/bin/v2ray-plugin
COPY server/ss-v2ray/entrypoint.sh /usr/bin/router-vpn-ss-v2ray
RUN chmod +x /usr/bin/router-vpn-ss-v2ray /usr/bin/v2ray-plugin
ENTRYPOINT ["/usr/bin/router-vpn-ss-v2ray"]
