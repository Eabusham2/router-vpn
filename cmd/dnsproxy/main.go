package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type upstream struct {
	Protocol   string
	Server     string
	Port       int
	ServerName string
	Path       string
}

func getenv(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func envInt(k string, d int) int {
	v, err := strconv.Atoi(getenv(k, strconv.Itoa(d)))
	if err != nil || v < 1 || v > 65535 {
		return d
	}
	return v
}

func main() {
	listen := flag.String("listen", getenv("HOMEVPN_DNS_LISTEN", "127.0.0.1:53"), "local DNS listen address")
	protocol := flag.String("protocol", getenv("HOMEVPN_DNS_PROTOCOL", "udp"), "udp, tcp, tls, https, or rescue")
	server := flag.String("server", getenv("HOMEVPN_DNS_HOST", "1.1.1.1"), "upstream DNS address")
	port := flag.Int("port", envInt("HOMEVPN_DNS_PORT", 53), "upstream DNS port")
	serverName := flag.String("server-name", getenv("HOMEVPN_DNS_SERVER_NAME", ""), "TLS server name")
	path := flag.String("path", getenv("HOMEVPN_DNS_PATH", "/dns-query"), "DoH path")
	flag.Parse()

	primary := upstream{Protocol: strings.ToLower(*protocol), Server: *server, Port: *port, ServerName: *serverName, Path: *path}
	if primary.Protocol == "h3" || primary.Protocol == "doh3" {
		// Raw kernel modes intentionally avoid a QUIC dependency. Rescue/DoH on 443
		// still works; sing-box modes handle native DoH3 themselves.
		primary.Protocol = "https"
		if primary.Port == 0 {
			primary.Port = 443
		}
	}
	if primary.Protocol == "doh" {
		primary.Protocol = "https"
	}
	if primary.Protocol == "dot" {
		primary.Protocol = "tls"
	}

	udpAddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer udpConn.Close()

	tcpLn, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	defer tcpLn.Close()

	log.Printf("RouterVPN DNS listening on %s -> %s", *listen, describe(primary))
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); serveUDP(udpConn, primary) }()
	go func() { defer wg.Done(); serveTCP(tcpLn, primary) }()
	wg.Wait()
}

func describe(u upstream) string {
	return fmt.Sprintf("%s://%s", u.Protocol, net.JoinHostPort(u.Server, strconv.Itoa(u.Port)))
}

func serveUDP(conn *net.UDPConn, u upstream) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			resp, err := resolve(q, u)
			if err == nil && len(resp) >= 12 {
				_, _ = conn.WriteToUDP(resp, addr)
			}
		}()
	}
}

func serveTCP(ln net.Listener, u upstream) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(15 * time.Second))
			for {
				var h [2]byte
				if _, err := io.ReadFull(c, h[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(h[:]))
				if n < 12 || n > 65535 {
					return
				}
				q := make([]byte, n)
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				resp, err := resolve(q, u)
				if err != nil || len(resp) > 65535 {
					return
				}
				binary.BigEndian.PutUint16(h[:], uint16(len(resp)))
				if _, err := c.Write(h[:]); err != nil {
					return
				}
				if _, err := c.Write(resp); err != nil {
					return
				}
			}
		}()
	}
}

func resolve(q []byte, u upstream) ([]byte, error) {
	if u.Protocol != "rescue" {
		return resolveOne(q, u)
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
	var last error
	for _, candidate := range chain {
		resp, err := resolveOne(q, candidate)
		if err == nil {
			return resp, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("no DNS rescue upstreams")
	}
	return nil, last
}

func resolveOne(q []byte, u upstream) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	switch u.Protocol {
	case "udp":
		return dnsUDP(ctx, q, u)
	case "tcp":
		return dnsTCP(ctx, q, u, false)
	case "tls":
		return dnsTCP(ctx, q, u, true)
	case "https":
		return dnsHTTPS(ctx, q, u)
	default:
		return nil, fmt.Errorf("unsupported DNS protocol %q", u.Protocol)
	}
}

func dnsUDP(ctx context.Context, q []byte, u upstream) ([]byte, error) {
	d := net.Dialer{}
	c, err := d.DialContext(ctx, "udp", net.JoinHostPort(u.Server, strconv.Itoa(u.Port)))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err = c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

func dnsTCP(ctx context.Context, q []byte, u upstream, useTLS bool) ([]byte, error) {
	addr := net.JoinHostPort(u.Server, strconv.Itoa(u.Port))
	d := net.Dialer{Timeout: 4 * time.Second}
	var c net.Conn
	var err error
	if useTLS {
		name := u.ServerName
		if name == "" && net.ParseIP(u.Server) == nil {
			name = u.Server
		}
		c, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name})
	} else {
		c, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if len(q) > 65535 {
		return nil, errors.New("DNS query too large")
	}
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(q)))
	if _, err = c.Write(h[:]); err != nil {
		return nil, err
	}
	if _, err = c.Write(q); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n < 12 {
		return nil, errors.New("short DNS response")
	}
	resp := make([]byte, n)
	_, err = io.ReadFull(c, resp)
	return resp, err
}

func dnsHTTPS(ctx context.Context, q []byte, u upstream) ([]byte, error) {
	name := u.ServerName
	if name == "" {
		name = u.Server
	}
	path := u.Path
	if path == "" {
		path = "/dns-query"
	}
	addr := net.JoinHostPort(u.Server, strconv.Itoa(u.Port))
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{Transport: tr, Timeout: 4 * time.Second}
	url := "https://" + net.JoinHostPort(name, strconv.Itoa(u.Port)) + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(q)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/dns-message")
	req.Header.Set("accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("DoH status %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}
