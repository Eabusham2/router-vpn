FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /router-vpn-agent ./cmd/router-agent
FROM alpine:3.22
RUN apk add --no-cache nftables ca-certificates wireguard-tools iproute2
COPY --from=build /router-vpn-agent /usr/local/bin/router-vpn-agent
ENTRYPOINT ["/usr/local/bin/router-vpn-agent"]
