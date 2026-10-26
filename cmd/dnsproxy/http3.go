package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// One raw-tunnel DNS service owns one HTTP/3 transport and UDP socket. Its
// literal destination, TLS identity and request authority are fixed together;
// the HTTP stack never resolves a hostname or chooses another transport.
type dnsHTTP3Client struct {
	upstream upstream
	socket   net.PacketConn
	quic     *quic.Transport
	http     *http3.Transport
	closed   atomic.Bool
	once     sync.Once
	closeErr error
}

func newDNSHTTP3Client(u upstream, roots *x509.CertPool) (*dnsHTTP3Client, error) {
	var err error
	u, err = normalizeDNSUpstream(u)
	if err != nil || u.Protocol != "h3" {
		return nil, errors.New("HTTP/3 DNS requires a captured H3 upstream")
	}
	ip := net.ParseIP(u.Server)
	family, local := "udp4", net.IPv4zero
	if ip.To4() == nil {
		family, local = "udp6", net.IPv6unspecified
	}
	socket, err := net.ListenUDP(family, &net.UDPAddr{IP: local})
	if err != nil {
		return nil, err
	}
	client := &dnsHTTP3Client{upstream: u, socket: socket, quic: &quic.Transport{Conn: socket}}
	name := dnsTLSName(u)
	authority := net.JoinHostPort(name, strconv.Itoa(u.Port))
	remote := &net.UDPAddr{IP: ip, Port: u.Port}
	client.http = &http3.Transport{
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS13, ServerName: name, RootCAs: roots, NextProtos: []string{http3.NextProtoH3}},
		QUICConfig:             &quic.Config{Versions: []quic.Version{quic.Version1}, HandshakeIdleTimeout: 4 * time.Second, MaxIdleTimeout: 30 * time.Second, MaxIncomingStreams: -1, MaxIncomingUniStreams: 8},
		MaxResponseHeaderBytes: 8192,
		DisableCompression:     true,
		Dial: func(ctx context.Context, requested string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
			if client.closed.Load() || ctx.Err() != nil || requested != authority || tlsConfig == nil || tlsConfig.ServerName != name || tlsConfig.InsecureSkipVerify {
				return nil, errors.New("HTTP/3 DNS dial lost its captured endpoint or TLS identity")
			}
			// Dial waits for the TLS handshake. DNS queries are never sent as
			// replayable 0-RTT data, and the remote address is never bootstrapped.
			return client.quic.Dial(ctx, remote, tlsConfig, config)
		},
	}
	return client, nil
}

func (c *dnsHTTP3Client) resolve(ctx context.Context, query []byte) ([]byte, error) {
	if c == nil || c.closed.Load() {
		return nil, errors.New("HTTP/3 DNS owner is closed")
	}
	request, err := dnsHTTPRequest(ctx, query, c.upstream)
	if err != nil {
		return nil, err
	}
	response, err := readDNSHTTPResponse(ctx, request, c.http, true)
	if err != nil {
		return nil, err
	}
	if c.closed.Load() {
		return nil, errors.New("HTTP/3 DNS response belongs to a closed owner")
	}
	return validateDNSForwarded(query, response)
}

func (c *dnsHTTP3Client) Close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		c.closed.Store(true)
		// HTTP Close cancels and joins any pending dial and closes its QUIC
		// connections. The separately owned transport then joins the packet
		// reader before the exact UDP socket is released. No pathname or PID
		// rediscovery, idle-only cleanup or timeout can stand in for this join.
		c.closeErr = errors.Join(c.http.Close(), c.quic.Close())
		if err := c.socket.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			c.closeErr = errors.Join(c.closeErr, err)
		}
	})
	return c.closeErr
}

var _ http.RoundTripper = (*http3.Transport)(nil)
