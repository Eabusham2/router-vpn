FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd/update-controller ./cmd/update-controller
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /router-vpn-update-controller ./cmd/update-controller

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /router-vpn-update-controller /usr/local/bin/router-vpn-update-controller
RUN test -x /usr/local/bin/router-vpn-update-controller
ENTRYPOINT ["/usr/local/bin/router-vpn-update-controller"]
