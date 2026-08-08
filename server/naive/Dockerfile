FROM golang:1.25.12-alpine AS builder
ARG XCADDY_VERSION=v0.4.5
ARG CADDY_VERSION=v2.8.4
ARG FORWARDPROXY_COMMIT=d62c80d3dd2c706b6b87579844d2397bddd18317
RUN apk add --no-cache ca-certificates curl tar
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}
RUN mkdir -p /src/forwardproxy /out \
 && curl -fL --retry 5 --retry-delay 2 \
      "https://github.com/klzgrad/forwardproxy/archive/${FORWARDPROXY_COMMIT}.tar.gz" \
      -o /tmp/forwardproxy.tar.gz \
 && tar -xzf /tmp/forwardproxy.tar.gz -C /src/forwardproxy --strip-components=1 \
 && rm -f /tmp/forwardproxy.tar.gz \
 && cd /src/forwardproxy \
 && /go/bin/xcaddy build "${CADDY_VERSION}" \
      --with github.com/caddyserver/forwardproxy@master=/src/forwardproxy \
      --output /out/caddy \
 && /out/caddy version

FROM caddy:2.8.4-alpine
RUN apk add --no-cache bash
COPY --from=builder /out/caddy /usr/bin/caddy
COPY server/naive/entrypoint.sh /usr/local/bin/router-vpn-naive
RUN chmod +x /usr/local/bin/router-vpn-naive \
 && mkdir -p /srv \
 && printf '%s\n' '<!doctype html><html><head><title>Welcome</title></head><body><h1>Welcome</h1><p>This site is online.</p></body></html>' >/srv/index.html
ENTRYPOINT ["/usr/local/bin/router-vpn-naive"]
