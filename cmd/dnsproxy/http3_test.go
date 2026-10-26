package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"router-vpn/internal/common"
)

const dnsTestName = "resolver.dns-proxy.invalid"

func dnsTestCertificate(t *testing.T, name string) (tls.Certificate, *x509.CertPool, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated DNS proxy test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{name}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}, pool, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

type dnsTestH3 struct {
	upstream upstream
	roots    *x509.CertPool
	pem      []byte
	requests atomic.Int32
	conns    atomic.Int32
	tcpCalls atomic.Int32
	sni      chan string
}

func newDNSTestH3(t *testing.T, handler http.HandlerFunc) *dnsTestH3 {
	return newDNSTestH3At(t, handler, "127.0.0.1", dnsTestName)
}

func newDNSTestH3At(t *testing.T, handler http.HandlerFunc, address, identity string) *dnsTestH3 {
	t.Helper()
	certificate, roots, pem := dnsTestCertificate(t, dnsTestName)
	ip := net.ParseIP(address)
	udpNetwork, tcpNetwork := "udp4", "tcp4"
	if ip.To4() == nil {
		udpNetwork, tcpNetwork = "udp6", "tcp6"
	}
	udp, err := net.ListenUDP(udpNetwork, &net.UDPAddr{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	f := &dnsTestH3{upstream: upstream{Protocol: "h3", Server: address, Port: udp.LocalAddr().(*net.UDPAddr).Port, ServerName: identity, Path: "/owned-query?node=captured"}, roots: roots, pem: pem, sni: make(chan string, 32)}
	server := &http3.Server{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		select {
		case f.sni <- hello.ServerName:
		default:
		}
		return nil, nil
	}}, QUICConfig: &quic.Config{Versions: []quic.Version{quic.Version1}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.ProtoMajor != 3 || r.TLS == nil || r.TLS.NegotiatedProtocol != http3.NextProtoH3 || r.Host != net.JoinHostPort(dnsTLSName(f.upstream), strconv.Itoa(f.upstream.Port)) || r.Method != http.MethodPost || r.Header.Get("content-type") != "application/dns-message" || r.Header.Get("accept") != "application/dns-message" {
			t.Error("real HTTP/3 request lost its captured protocol/authority/headers")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		handler(w, r)
	}), ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context { f.conns.Add(1); return ctx }}
	served := make(chan error, 1)
	go func() { served <- server.Serve(udp) }()
	// TCP on the same literal IP/port is a downgrade witness, never a resolver.
	tcp, err := net.Listen(tcpNetwork, udp.LocalAddr().String())
	if err != nil {
		_ = server.Close()
		_ = udp.Close()
		t.Fatal(err)
	}
	tcpDone := make(chan struct{})
	go func() {
		defer close(tcpDone)
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			f.tcpCalls.Add(1)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = udp.Close()
		_ = tcp.Close()
		<-tcpDone
		select {
		case <-served:
		case <-time.After(3 * time.Second):
			t.Error("actual HTTP/3 fixture listener did not join")
		}
		if f.tcpCalls.Load() != 0 {
			t.Error("DoH3 failure dialed a forbidden TCP/HTTPS fallback")
		}
	})
	return f
}

func TestDNSHTTP3LiteralIPCertificateAndIPv6(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "::1"} {
		t.Run(address, func(t *testing.T) {
			f := newDNSTestH3At(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("content-type", "application/dns-message")
				_, _ = w.Write(dnsTestResponse(t, r))
			}, address, "")
			client, err := newDNSHTTP3Client(f.upstream, f.roots)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			query := dnsTestQuery(t)
			response, err := client.resolve(ctx, query)
			if err != nil || common.ValidateDNSProbeResponse(query, response) != nil {
				t.Fatal("literal IP certificate/IPv6 H3 path failed", err)
			}
			select {
			case sni := <-f.sni:
				if sni != "" {
					t.Fatal("literal IP certificate validation invented a DNS server name", sni)
				}
			default:
				t.Fatal("the actual selected IP did not perform TLS")
			}
		})
	}
}

func dnsTestResponse(t *testing.T, r *http.Request) []byte {
	t.Helper()
	query, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil || common.ValidateDNSForwardQuery(query) != nil {
		t.Error("HTTP/3 fixture received an invalid DNS query", err)
		return nil
	}
	response := append([]byte(nil), query...)
	response[2], response[3] = 0x81, 0x80
	return response
}

func dnsTestQuery(t *testing.T) []byte {
	t.Helper()
	query, err := common.NewDNSProbeQuery(1)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func TestDNSHTTP3ActualExchangePinsEndpointIdentityPathAndReusesOwner(t *testing.T) {
	f := newDNSTestH3(t, func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/owned-query?node=captured" {
			t.Error("selected DoH3 path or query changed", r.RequestURI)
		}
		w.Header().Set("content-type", "application/dns-message")
		_, _ = w.Write(dnsTestResponse(t, r))
	})
	client, err := newDNSHTTP3Client(f.upstream, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for range 2 {
		query := dnsTestQuery(t)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		response, err := client.resolve(ctx, query)
		cancel()
		if err != nil || common.ValidateDNSProbeResponse(query, response) != nil {
			t.Fatal("actual selected HTTP/3 resolver did not return the captured question", err)
		}
	}
	if f.requests.Load() != 2 || f.conns.Load() != 1 {
		t.Fatal("two DNS requests did not reuse exactly one captured QUIC connection", f.requests.Load(), f.conns.Load())
	}
	select {
	case name := <-f.sni:
		if name != dnsTestName {
			t.Fatal("TLS identity was replaced with the dial IP", name)
		}
	default:
		t.Fatal("real TLS handshake never observed")
	}
	address := client.socket.LocalAddr().(*net.UDPAddr)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	probe, err := net.ListenUDP("udp4", address)
	if err != nil {
		t.Fatal("closed HTTP/3 owner retained its actual UDP socket", err)
	}
	_ = probe.Close()
	if _, err := client.resolve(context.Background(), dnsTestQuery(t)); err == nil {
		t.Fatal("retired HTTP/3 owner admitted a new request")
	}
}

func TestDNSHTTP3RejectsTLSAndResponseFailuresWithoutFallback(t *testing.T) {
	for _, kind := range []string{"wrong-ca", "wrong-name", "wrong-path", "redirect", "status", "content-type", "content-encoding", "short", "truncated-http", "oversized", "oversized-header", "wrong-id", "wrong-question", "truncated-dns", "trailing"} {
		t.Run(kind, func(t *testing.T) {
			f := newDNSTestH3(t, func(w http.ResponseWriter, r *http.Request) {
				response := dnsTestResponse(t, r)
				w.Header().Set("content-type", "application/dns-message")
				switch kind {
				case "wrong-path":
					if r.RequestURI != "/wrong-query" {
						t.Error("actual path was silently replaced")
					}
					w.WriteHeader(http.StatusNotFound)
				case "redirect":
					w.Header().Set("location", "https://foreign.invalid/dns-query")
					w.WriteHeader(http.StatusTemporaryRedirect)
				case "status":
					w.WriteHeader(http.StatusServiceUnavailable)
				case "content-type":
					w.Header().Set("content-type", "text/html")
				case "content-encoding":
					w.Header().Set("content-encoding", "gzip")
				case "short":
					response = response[:11]
				case "truncated-http":
					w.Header().Set("content-length", strconv.Itoa(len(response)+10))
				case "oversized":
					response = bytes.Repeat([]byte{'x'}, 65536)
				case "oversized-header":
					w.Header().Set("x-overflow", strings.Repeat("x", 9000))
				case "wrong-id":
					response[0] ^= 1
				case "wrong-question":
					response[13] = 'x'
				case "truncated-dns":
					response[2] |= 2
				case "trailing":
					response = append(response, 0)
				}
				_, _ = w.Write(response)
			})
			u, roots := f.upstream, f.roots
			switch kind {
			case "wrong-ca":
				_, roots, _ = dnsTestCertificate(t, "unrelated.invalid")
			case "wrong-name":
				u.ServerName = "wrong-identity.invalid"
			case "wrong-path":
				u.Path = "/wrong-query"
			}
			client, err := newDNSHTTP3Client(u, roots)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := client.resolve(ctx, dnsTestQuery(t)); err == nil {
				t.Fatal("failed selected HTTP/3 policy was accepted", kind)
			}
			want := int32(1)
			if kind == "wrong-ca" || kind == "wrong-name" {
				want = 0
			}
			if f.requests.Load() != want {
				t.Fatal("failed policy followed a redirect or crossed a failed TLS handshake", f.requests.Load())
			}
		})
	}
}

func TestDNSHTTP3CancellationRetiresOnlyTheCapturedRequest(t *testing.T) {
	entered, retired := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	f := newDNSTestH3(t, func(w http.ResponseWriter, r *http.Request) {
		response := dnsTestResponse(t, r)
		if first.CompareAndSwap(false, true) {
			close(entered)
			<-r.Context().Done()
			close(retired)
			return
		}
		w.Header().Set("content-type", "application/dns-message")
		_, _ = w.Write(response)
	})
	client, err := newDNSHTTP3Client(f.upstream, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	query := dnsTestQuery(t)
	go func() { _, err := client.resolve(ctx, query); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP/3 request never entered the controlled server")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("HTTP/3 cancellation lost its captured request context", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP/3 cancellation left the request worker blocked")
	}
	select {
	case <-retired:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled HTTP/3 stream did not retire on the actual peer")
	}
	fresh, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if _, err := client.resolve(fresh, dnsTestQuery(t)); err != nil || f.conns.Load() != 1 {
		t.Fatal("old request cancellation closed or replaced the independent connection owner", err)
	}
}

type dnsBlockingPacketClose struct {
	net.PacketConn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *dnsBlockingPacketClose) Close() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.PacketConn.Close()
}

func TestDNSHTTP3CloseWaitsForTheExactSocket(t *testing.T) {
	f := newDNSTestH3(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/dns-message")
		_, _ = w.Write(dnsTestResponse(t, r))
	})
	client, err := newDNSHTTP3Client(f.upstream, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := client.resolve(ctx, dnsTestQuery(t)); err != nil {
		t.Fatal(err)
	}
	blocked := &dnsBlockingPacketClose{PacketConn: client.socket, entered: make(chan struct{}), release: make(chan struct{})}
	client.socket = blocked
	done := make(chan error, 1)
	go func() { done <- client.Close() }()
	select {
	case <-blocked.entered:
	case <-time.After(2 * time.Second):
		close(blocked.release)
		t.Fatal("HTTP/3 shutdown never reached the captured UDP socket")
	}
	select {
	case <-done:
		close(blocked.release)
		t.Fatal("HTTP/3 cleanup acknowledged before the captured socket closed")
	default:
	}
	close(blocked.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDNSHTTP3UnreachableServerCannotFallBackOrOutliveCancellation(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, roots, _ := dnsTestCertificate(t, dnsTestName)
	client, err := newDNSHTTP3Client(upstream{Protocol: "h3", Server: "127.0.0.1", Port: listener.LocalAddr().(*net.UDPAddr).Port, ServerName: dnsTestName}, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	query := dnsTestQuery(t)
	go func() { _, err := client.resolve(ctx, query); done <- err }()
	_ = listener.SetReadDeadline(time.Now().Add(2 * time.Second))
	packet := make([]byte, 65536)
	n, _, err := listener.ReadFromUDP(packet)
	if err != nil || n < 1200 || bytes.Equal(packet[:n], query) || packet[0]&0xc0 != 0xc0 {
		cancel()
		t.Fatal("selected HTTP/3 did not send a QUIC Initial to the captured literal address", n, err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled QUIC handshake lost its request identity", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled QUIC handshake worker did not finish")
	}
	if err := client.Close(); err != nil {
		t.Fatal("cancelled owner did not join its dial and socket", err)
	}
}
