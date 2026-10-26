package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

type upstream struct {
	Protocol   string
	Server     string
	Port       int
	ServerName string
	Path       string
}

//go:embed THIRD-PARTY-NOTICES.json
var dnsProxyNotices []byte

func getenv(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func main() {
	listen := flag.String("listen", getenv("HOMEVPN_DNS_LISTEN", "127.0.0.1:53"), "local DNS listen address")
	protocol := flag.String("protocol", getenv("HOMEVPN_DNS_PROTOCOL", "udp"), "udp, tcp, tls, https, h3, or explicit rescue")
	server := flag.String("server", getenv("HOMEVPN_DNS_HOST", "1.1.1.1"), "literal upstream DNS IP address")
	port := flag.String("port", getenv("HOMEVPN_DNS_PORT", "0"), "upstream DNS port; zero uses the selected transport default")
	serverName := flag.String("server-name", getenv("HOMEVPN_DNS_SERVER_NAME", ""), "TLS certificate name; the selected literal IP remains the dial destination")
	path := flag.String("path", getenv("HOMEVPN_DNS_PATH", "/dns-query"), "exact DoH or DoH3 request path")
	licenses := flag.Bool("licenses", false, "print the bundled pinned dependency license notices and exit")
	flag.Parse()
	if *licenses {
		_, _ = os.Stdout.Write(dnsProxyNotices)
		return
	}
	if flag.NArg() != 0 {
		log.Fatal("DNS proxy does not accept positional arguments")
	}
	selectedPort, err := strconv.Atoi(*port)
	if err != nil {
		log.Fatal("DNS upstream port must be an integer; refusing to replace the selected port")
	}
	// Validate the real CLI selection before either local listener is opened.
	// H3 has one QUIC transport; only the explicitly selected Rescue mode has
	// a fallback chain. Resolver names are TLS identities, never OS bootstrap.
	primary, err := normalizeDNSUpstream(upstream{Protocol: *protocol, Server: *server, Port: selectedPort, ServerName: *serverName, Path: *path})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := runDNSProxy(ctx, *listen, primary); err != nil {
		log.Fatal(err)
	}
}

func describe(u upstream) string {
	return fmt.Sprintf("%s://%s", u.Protocol, netJoinDNSAddress(u))
}
