package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"router-vpn/internal/common"
)

// A resolver belongs to one captured DNS proxy. HTTP/3 reuses only that
// owner's literal-IP connection; shutting down the proxy closes the transport
// after its request workers have been cancelled and joined.
type dnsResolver struct {
	upstream upstream
	h3       *dnsHTTP3Client
}

func newDNSResolver(u upstream, roots *x509.CertPool) (*dnsResolver, error) {
	u, err := normalizeDNSUpstream(u)
	if err != nil {
		return nil, err
	}
	r := &dnsResolver{upstream: u}
	if u.Protocol == "h3" {
		r.h3, err = newDNSHTTP3Client(u, roots)
	}
	return r, err
}

func (r *dnsResolver) Close() error { return r.h3.Close() }

func (r *dnsResolver) resolve(ctx context.Context, query []byte) ([]byte, error) {
	if err := common.ValidateDNSForwardQuery(query); err != nil {
		return nil, err
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	if r.h3 != nil {
		request, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		response, err := r.h3.resolve(request, query)
		if err != nil {
			return nil, dnsTransportError(request, err)
		}
		return validateDNSForwarded(query, response)
	}
	return resolveContext(ctx, query, r.upstream)
}

func netJoinDNSAddress(u upstream) string { return net.JoinHostPort(u.Server, strconv.Itoa(u.Port)) }

func resolve(query []byte, u upstream) ([]byte, error) {
	return resolveContext(context.Background(), query, u)
}

func resolveContext(ctx context.Context, query []byte, u upstream) ([]byte, error) {
	if err := common.ValidateDNSForwardQuery(query); err != nil {
		return nil, err
	}
	var err error
	u, err = normalizeDNSUpstream(u)
	if err != nil {
		return nil, err
	}
	if u.Protocol != "rescue" {
		return resolveOneContext(ctx, query, u)
	}
	chain := []upstream{u}
	chain[0].Protocol = "https"
	if chain[0].Port == 53 || chain[0].Port == 0 {
		chain[0].Port = 443
	}
	if chain[0].ServerName == "" && chain[0].Server == "1.1.1.1" {
		chain[0].ServerName = "cloudflare-dns.com"
	}
	chain = append(chain,
		upstream{Protocol: "https", Server: "1.1.1.1", Port: 443, ServerName: "cloudflare-dns.com", Path: "/dns-query"},
		upstream{Protocol: "tls", Server: "1.1.1.1", Port: 853, ServerName: "cloudflare-dns.com"},
		upstream{Protocol: "tcp", Server: "1.1.1.1", Port: 53},
		upstream{Protocol: "udp", Server: "1.1.1.1", Port: 53},
	)
	for _, candidate := range chain {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		var response []byte
		response, err = resolveOneContext(ctx, query, candidate)
		if err == nil {
			return response, nil
		}
	}
	return nil, err
}

func resolveOne(query []byte, u upstream) ([]byte, error) {
	return resolveOneContext(context.Background(), query, u)
}

func resolveOneContext(parent context.Context, query []byte, u upstream) ([]byte, error) {
	if err := common.ValidateDNSForwardQuery(query); err != nil {
		return nil, err
	}
	var err error
	u, err = normalizeDNSUpstream(u)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	var response []byte
	switch u.Protocol {
	case "udp":
		response, err = dnsUDP(ctx, query, u)
	case "tcp":
		response, err = dnsTCP(ctx, query, u, false)
	case "tls":
		response, err = dnsTCP(ctx, query, u, true)
	case "https":
		response, err = dnsHTTPS(ctx, query, u)
	case "h3":
		var client *dnsHTTP3Client
		client, err = newDNSHTTP3Client(u, nil)
		if err == nil {
			response, err = client.resolve(ctx, query)
			err = errors.Join(err, client.Close())
		}
	default:
		err = fmt.Errorf("unsupported DNS protocol %q", u.Protocol)
	}
	if err != nil || ctx.Err() != nil {
		return nil, dnsTransportError(ctx, err)
	}
	return validateDNSForwarded(query, response)
}

func validateDNSForwarded(query, response []byte) ([]byte, error) {
	if err := common.ValidateDNSForwardResponse(query, response); err != nil {
		return nil, err
	}
	return response, nil
}

func dnsUDP(ctx context.Context, query []byte, u upstream) ([]byte, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", netJoinDNSAddress(u))
	if err != nil {
		return nil, dnsTransportError(ctx, err)
	}
	closeOwned, err := ownDNSConnection(ctx, conn)
	if err != nil {
		return nil, err
	}
	defer closeOwned()
	if _, err = conn.Write(query); err != nil {
		return nil, dnsTransportError(ctx, err)
	}
	response := make([]byte, 65536)
	n, err := conn.Read(response)
	if err != nil || ctx.Err() != nil {
		return nil, dnsTransportError(ctx, err)
	}
	return response[:n], nil
}

func dnsTCP(ctx context.Context, query []byte, u upstream, useTLS bool) ([]byte, error) {
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	var conn net.Conn
	var err error
	if useTLS {
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: dnsTLSName(u)}}
		conn, err = tlsDialer.DialContext(ctx, "tcp", netJoinDNSAddress(u))
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", netJoinDNSAddress(u))
	}
	if err != nil {
		return nil, dnsTransportError(ctx, err)
	}
	closeOwned, err := ownDNSConnection(ctx, conn)
	if err != nil {
		return nil, err
	}
	defer closeOwned()
	if err := writeDNSFrame(conn, query); err != nil {
		return nil, dnsTransportError(ctx, err)
	}
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, dnsTransportError(ctx, err)
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size < 12 {
		return nil, errors.New("short DNS response")
	}
	response := make([]byte, size)
	_, err = io.ReadFull(conn, response)
	if err != nil || ctx.Err() != nil {
		return nil, dnsTransportError(ctx, err)
	}
	return response, nil
}

func dnsTLSName(u upstream) string {
	if u.ServerName != "" {
		return u.ServerName
	}
	return u.Server
}

func dnsHTTPRequest(ctx context.Context, query []byte, u upstream) (*http.Request, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	if err := common.ValidateDNSForwardQuery(query); err != nil {
		return nil, err
	}
	address := "https://" + net.JoinHostPort(dnsTLSName(u), strconv.Itoa(u.Port)) + u.Path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	request.Header.Set("content-type", "application/dns-message")
	request.Header.Set("accept", "application/dns-message")
	return request, nil
}

func readDNSHTTPResponse(ctx context.Context, request *http.Request, transport http.RoundTripper, h3 bool) ([]byte, error) {
	// RoundTrip deliberately has no redirect handler, Alt-Svc discovery or
	// fallback client. A redirect is a failed selected-policy exchange.
	response, err := transport.RoundTrip(request)
	if err != nil {
		return nil, dnsTransportError(ctx, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || h3 && response.ProtoMajor != 3 {
		return nil, errors.New("selected DNS HTTP transport returned an invalid protocol or status")
	}
	kind, parameters, err := mime.ParseMediaType(response.Header.Get("content-type"))
	if err != nil || kind != "application/dns-message" || len(parameters) != 0 || response.Header.Get("content-encoding") != "" && !strings.EqualFold(response.Header.Get("content-encoding"), "identity") {
		return nil, errors.New("selected DNS HTTP transport returned a non-DNS representation")
	}
	if response.ContentLength > 65535 {
		return nil, errors.New("DNS HTTP response exceeds its message bound")
	}
	message, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil || ctx.Err() != nil {
		return nil, dnsTransportError(ctx, err)
	}
	if len(message) < 12 || len(message) > 65535 || response.ContentLength >= 0 && int64(len(message)) != response.ContentLength {
		return nil, errors.New("DNS HTTP response is incomplete or exceeds its message bound")
	}
	if h3 && message[2]&2 != 0 {
		return nil, errors.New("HTTP/3 DNS response was truncated; transport fallback is not allowed")
	}
	return message, nil
}

func dnsHTTPS(ctx context.Context, query []byte, u upstream) ([]byte, error) {
	request, err := dnsHTTPRequest(ctx, query, u)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, ServerName: dnsTLSName(u)},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, netJoinDNSAddress(u))
		},
		MaxResponseHeaderBytes: 8192,
		DisableCompression:     true,
		DisableKeepAlives:      true,
	}
	defer transport.CloseIdleConnections()
	return readDNSHTTPResponse(ctx, request, transport, false)
}
