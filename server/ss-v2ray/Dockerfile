FROM golang:1.24-alpine AS plugin
ARG V2RAY_PLUGIN_COMMIT=e9af1cdd2549d528deb20a4ab8d61c5fbe51f306
RUN apk add --no-cache git
RUN mkdir -p /out \
 && git clone https://github.com/shadowsocks/v2ray-plugin /src/v2ray-plugin \
 && cd /src/v2ray-plugin \
 && git checkout "$V2RAY_PLUGIN_COMMIT" \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/v2ray-plugin .

FROM ghcr.io/shadowsocks/ssserver-rust:v1.24.0
COPY --from=plugin /out/v2ray-plugin /usr/bin/v2ray-plugin
COPY server/ss-v2ray/entrypoint.sh /usr/bin/router-vpn-ss-v2ray
RUN chmod +x /usr/bin/router-vpn-ss-v2ray /usr/bin/v2ray-plugin
ENTRYPOINT ["/usr/bin/router-vpn-ss-v2ray"]
