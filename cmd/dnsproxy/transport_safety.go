package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

func normalizeDNSUpstream(u upstream) (upstream, error) {
	u.Protocol = strings.ToLower(strings.TrimSpace(u.Protocol))
	switch u.Protocol {
	case "doh":
		u.Protocol = "https"
	case "dot":
		u.Protocol = "tls"
	case "doh3":
		u.Protocol = "h3"
	case "udp", "tcp", "tls", "https", "h3", "rescue":
	default:
		return upstream{}, fmt.Errorf("unsupported DNS protocol %q", u.Protocol)
	}
	u.Server = strings.Trim(strings.TrimSpace(u.Server), "[]")
	if net.ParseIP(u.Server) == nil {
		return upstream{}, errors.New("raw-tunnel DNS requires a literal upstream IP; recursive OS bootstrap is not allowed")
	}
	u.Server = net.ParseIP(u.Server).String()
	if u.Port == 0 {
		u.Port = 53
		if u.Protocol == "tls" {
			u.Port = 853
		}
		if u.Protocol == "https" || u.Protocol == "h3" || u.Protocol == "rescue" {
			u.Port = 443
		}
	}
	if u.Port < 1 || u.Port > 65535 {
		return upstream{}, errors.New("invalid DNS upstream port")
	}
	u.ServerName = strings.TrimSpace(u.ServerName)
	if strings.ContainsAny(u.ServerName, " /\\\t\r\n?#@") || strings.IndexFunc(u.ServerName, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return upstream{}, errors.New("invalid DNS TLS server name")
	}
	if u.Path == "" {
		u.Path = "/dns-query"
	}
	path, err := url.ParseRequestURI(u.Path)
	if err != nil || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") || path.IsAbs() || path.Host != "" || path.Fragment != "" || strings.ContainsAny(u.Path, "\\#") || strings.IndexFunc(u.Path, func(r rune) bool { return r <= 0x20 || r == 0x7f }) >= 0 {
		return upstream{}, errors.New("DNS HTTPS path must be a local absolute path, not another URL")
	}
	return u, nil
}

// The dial's context does not cancel reads after connection establishment.
// Attach cancellation to this socket only, and join its callback before return.
func ownDNSConnection(ctx context.Context, conn net.Conn) (func(), error) {
	deadline := time.Now().Add(4 * time.Second)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); conn.Close() })
	return func() {
		if !stop() {
			<-done
		}
		conn.Close()
	}, nil
}

func dnsTransportError(ctx context.Context, err error) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return err
}

func writeDNSFrame(w io.Writer, message []byte) error {
	if len(message) < 12 || len(message) > 65535 {
		return errors.New("invalid DNS frame size")
	}
	frame := make([]byte, len(message)+2)
	frame[0], frame[1] = byte(len(message)>>8), byte(len(message))
	copy(frame[2:], message)
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(frame) {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}
