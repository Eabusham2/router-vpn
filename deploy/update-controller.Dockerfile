FROM golang:1.24.13-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd/update-controller ./cmd/update-controller
COPY cmd/update-auto ./cmd/update-auto
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /router-vpn-update-controller ./cmd/update-controller \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /router-vpn-update-auto ./cmd/update-auto

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /router-vpn-update-controller /usr/local/bin/router-vpn-update-controller
COPY --from=build /router-vpn-update-auto /usr/local/bin/router-vpn-update-auto
COPY deploy/update-controller-entrypoint.sh /usr/local/bin/router-vpn-update-entrypoint
RUN chmod 0755 /usr/local/bin/router-vpn-update-controller /usr/local/bin/router-vpn-update-auto /usr/local/bin/router-vpn-update-entrypoint \
 && test -x /usr/local/bin/router-vpn-update-controller \
 && test -x /usr/local/bin/router-vpn-update-auto \
 && test -x /usr/local/bin/router-vpn-update-entrypoint
ENTRYPOINT ["/usr/local/bin/router-vpn-update-entrypoint"]
