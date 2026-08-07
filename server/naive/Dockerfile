FROM caddy:2-builder AS builder
RUN xcaddy build --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@naive

FROM caddy:2-alpine
RUN apk add --no-cache bash
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY server/naive/entrypoint.sh /usr/local/bin/router-vpn-naive
RUN chmod +x /usr/local/bin/router-vpn-naive \
 && mkdir -p /srv \
 && printf '%s\n' '<!doctype html><html><head><title>Welcome</title></head><body><h1>Welcome</h1><p>This site is online.</p></body></html>' >/srv/index.html
ENTRYPOINT ["/usr/local/bin/router-vpn-naive"]
