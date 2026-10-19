package httpupgrade

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
)

type Config struct {
	Path string
	Host string

	TrustedReverseProxyHops int
}

func NewHTTPUpgradeTransport(config *Config) (Transport, error) {
	return Transport{path: config.Path, host: config.Host, trustedReverseProxyHops: config.TrustedReverseProxyHops}, nil
}

type Transport struct {
	path string
	host string

	trustedReverseProxyHops int
}

func (t Transport) Client(conn net.Conn) (net.Conn, error) {
	req, err := http.NewRequest("GET", "/"+t.path, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Host = t.host

	err = req.Write(conn)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, err
	}

	if resp.Status == "101 Switching Protocols" &&
		strings.ToLower(resp.Header.Get("Upgrade")) == "websocket" &&
		strings.ToLower(resp.Header.Get("Connection")) == "upgrade" {
		return &bufferedConn{Conn: conn, reader: reader}, nil
	}
	return nil, errors.New("unrecognized reply")
}

func (t Transport) Server(conn net.Conn) (net.Conn, error) {
	connReader := bufio.NewReader(conn)
	req, err := http.ReadRequest(connReader)
	if err != nil {
		return nil, err
	}
	connection := strings.ToLower(req.Header.Get("Connection"))
	upgrade := strings.ToLower(req.Header.Get("Upgrade"))
	if connection != "upgrade" || upgrade != "websocket" {
		return nil, errors.New("unrecognized request")
	}
	resp := &http.Response{
		Status:     "101 Switching Protocols",
		StatusCode: 101,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
	}
	resp.Header.Set("Connection", "upgrade")
	resp.Header.Set("Upgrade", "websocket")
	err = resp.Write(conn)
	if err != nil {
		return nil, err
	}

	var remoteAddr net.Addr
	forwardedForHeader := req.Header.Get("X-Forwarded-For")
	if forwardedForHeader != "" && t.trustedReverseProxyHops != 0 {
		forwardedForHeaderIPs := strings.Split(forwardedForHeader, ",")
		position := len(forwardedForHeaderIPs) - t.trustedReverseProxyHops
		if position < 0 {
			pt.Log(pt.LogSeverityWarning,
				fmt.Sprintf("tried to skip %d X-FORWARDED-FOR addresses, but there were only %d. Using requester origin IP as client address instead.",
					t.trustedReverseProxyHops, len(forwardedForHeaderIPs)))
			position = 0
		}
		forwardedForHeader = forwardedForHeaderIPs[position]
		forwardedForHeaderNoSpace := strings.TrimSpace(forwardedForHeader)
		parsedClientIP := net.ParseIP(forwardedForHeaderNoSpace)
		if parsedClientIP == nil {
			pt.Log(pt.LogSeverityWarning, "unable to parse client IP address in X-Forwarded-For header")
		}
		if parsedClientIP.IsLoopback() || parsedClientIP.IsUnspecified() || parsedClientIP.IsMulticast() || parsedClientIP.IsLinkLocalUnicast() || parsedClientIP.IsPrivate() {
			pt.Log(pt.LogSeverityWarning, "unexpected internal address in X-Forwarded-For header")
		}
		remoteAddr = &net.TCPAddr{
			IP:   parsedClientIP,
			Port: 60000,
		}
	}
	return &connWithAlternativeRemoteAddr{&bufferedConn{Conn: conn, reader: connReader}, remoteAddr}, nil
}

// A peer may send its first tunnel bytes in the same read as the HTTP headers.
// Keep that reader for the stream lifetime instead of discarding those bytes.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

type connWithAlternativeRemoteAddr struct {
	net.Conn
	remoteAddr net.Addr
}

func (c connWithAlternativeRemoteAddr) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return c.Conn.RemoteAddr()
}
