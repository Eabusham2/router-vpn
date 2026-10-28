package mobiletor

import (
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
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const externalTarget = "https://1.1.1.1/cdn-cgi/trace"

func lastRelayExternalTLSFixture(t *testing.T, wrongHost bool, handler http.HandlerFunc) (*httptest.Server, *x509.CertPool, *atomic.Int32) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Router VPN isolated response fixture"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsedCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("1.0.0.1")}
	if wrongHost {
		ips = []net.IP{net.ParseIP("9.9.9.9")}
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IPAddresses: ips, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parsedCA, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsedCA)
	connections := &atomic.Int32{}
	server := httptest.NewUnstartedServer(handler)
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, pool, connections
}

func lastRelayExternalDial(t *testing.T, server *httptest.Server) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func closeLastRelayExternal(t *testing.T, stream *LastRelayExternalStream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := stream.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestLastRelayExternalUsesOneVerifiedTLSStreamAndOneFreshResponse(t *testing.T) {
	for _, target := range []string{externalTarget, "https://1.0.0.1/cdn-cgi/trace"} {
		t.Run(target, func(t *testing.T) {
			var requests atomic.Int32
			server, roots, connections := lastRelayExternalTLSFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.RequestURI() != "/cdn-cgi/trace" || r.Host != strings.Split(strings.TrimPrefix(target, "https://"), "/")[0] || r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("response probe changed its exact request", r.Method, r.URL, r.Host)
				}
				_, _ = io.WriteString(w, "ip=203.0.113.8\nhttp=http/1.1\n")
			})
			raw := lastRelayExternalDial(t, server)
			local := raw.LocalAddr().String()
			stream, err := newLastRelayExternalStream(context.Background(), raw, target, func() bool { return true }, roots)
			if err != nil {
				t.Fatal(err)
			}
			defer closeLastRelayExternal(t, stream)
			if stream.Healthy() {
				t.Fatal("unprepared TLS stream advertised health")
			}
			if stream.Target() != target || stream.TargetAddress().Port() != 443 || stream.LocalAddress() != local {
				t.Fatal("native socket or target tuple was replaced")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if elapsed, err := stream.Measure(ctx, target); err == nil || elapsed != 0 {
				t.Fatal("unprepared stream produced a response time")
			}
			if err := stream.Prepare(ctx); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 0 {
				t.Fatal("TLS preparation fabricated an external response")
			}
			if !stream.Healthy() {
				t.Fatal("verified TLS stream lost its retained lifetime")
			}
			if err := stream.Prepare(ctx); err == nil {
				t.Fatal("TLS anchor was replaced or prepared twice")
			}
			elapsed, err := stream.Measure(ctx, target)
			if err != nil || elapsed <= 0 || elapsed > time.Second {
				t.Fatal("actual TLS response did not produce bounded elapsed time", elapsed, err)
			}
			if elapsed, err := stream.Measure(ctx, target); err == nil || elapsed != 0 {
				t.Fatal("old external result was reused")
			}
			if requests.Load() != 1 || connections.Load() != 1 {
				t.Fatal("external probe reconnected or sent extra requests", requests.Load(), connections.Load())
			}
		})
	}
}

func TestLastRelayExternalRejectsRealTLSAndHTTPFailuresWithoutScore(t *testing.T) {
	for _, mode := range []string{"untrusted", "wrong-host", "redirect", "server-error", "closed-stream", "empty", "oversized-body", "oversized-header", "encoded", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			server, roots, connections := lastRelayExternalTLSFixture(t, mode == "wrong-host", func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				switch mode {
				case "redirect":
					w.Header().Set("Location", "https://1.0.0.1/cdn-cgi/trace")
					w.WriteHeader(302)
				case "server-error":
					w.WriteHeader(503)
				case "closed-stream":
					w.Header().Set("Connection", "close")
					_, _ = io.WriteString(w, "real bytes")
				case "empty":
					w.Header().Set("Content-Length", "0")
					w.WriteHeader(200)
				case "oversized-body":
					_, _ = io.WriteString(w, strings.Repeat("b", lastRelayExternalBodyLimit+1))
				case "oversized-header":
					w.Header().Set("X-Too-Large", strings.Repeat("h", 3*lastRelayExternalBodyLimit))
					_, _ = io.WriteString(w, "body")
				case "encoded":
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = io.WriteString(w, "body")
				case "truncated":
					w.Header().Set("Content-Length", "100")
					_, _ = io.WriteString(w, "partial")
				default:
					_, _ = io.WriteString(w, "body")
				}
			})
			if mode == "untrusted" {
				roots = x509.NewCertPool()
			}
			stream, err := newLastRelayExternalStream(context.Background(), lastRelayExternalDial(t, server), externalTarget, func() bool { return true }, roots)
			if err != nil {
				t.Fatal(err)
			}
			defer closeLastRelayExternal(t, stream)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			prepareErr := stream.Prepare(ctx)
			if mode == "untrusted" || mode == "wrong-host" {
				if prepareErr == nil || requests.Load() != 0 {
					t.Fatal("invalid real TLS identity reached HTTP")
				}
			} else {
				if prepareErr != nil {
					t.Fatal(prepareErr)
				}
				if elapsed, err := stream.Measure(ctx, externalTarget); err == nil || elapsed != 0 {
					t.Fatal("failed HTTP response acquired a score", elapsed, err)
				}
			}
			if connections.Load() != 1 || requests.Load() > 1 {
				t.Fatal("failed response fell back or reconnected")
			}
		})
	}
}

func TestLastRelayExternalRejectsChangedTargetAndOwner(t *testing.T) {
	for _, fault := range []string{"target", "owner"} {
		t.Run(fault, func(t *testing.T) {
			var requests atomic.Int32
			server, roots, _ := lastRelayExternalTLSFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = io.WriteString(w, "body")
			})
			var current atomic.Bool
			current.Store(true)
			stream, err := newLastRelayExternalStream(context.Background(), lastRelayExternalDial(t, server), externalTarget, current.Load, roots)
			if err != nil {
				t.Fatal(err)
			}
			defer closeLastRelayExternal(t, stream)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := stream.Prepare(ctx); err != nil {
				t.Fatal(err)
			}
			if fault == "target" {
				if elapsed, err := stream.Measure(ctx, "https://1.0.0.1/cdn-cgi/trace"); err == nil || elapsed != 0 {
					t.Fatal("another candidate's endpoint was measured")
				}
			} else {
				current.Store(false)
				if stream.Healthy() {
					t.Fatal("retired TLS stream retained health")
				}
				if elapsed, err := stream.Measure(ctx, externalTarget); err == nil || elapsed != 0 {
					t.Fatal("retired native owner produced a measurement")
				}
			}
			if requests.Load() != 0 {
				t.Fatal("invalid target or source reached external HTTP")
			}
		})
	}
}

func TestLastRelayExternalInvalidConstructionKeepsItsSocket(t *testing.T) {
	for _, target := range []string{"", "http://1.1.1.1/cdn-cgi/trace", "https://example.com/cdn-cgi/trace", "https://1.1.1.1:443/cdn-cgi/trace", "https://1.1.1.1/cdn-cgi/trace?x=1", "https://127.0.0.1/cdn-cgi/trace"} {
		raw, peer := net.Pipe()
		stream, err := NewLastRelayExternalStream(context.Background(), raw, target, func() bool { return true })
		if err == nil || stream == nil {
			t.Fatal("invalid target dropped native ownership or was admitted", target)
		}
		closeLastRelayExternal(t, stream)
		var b [1]byte
		if _, err := peer.Read(b[:]); !errors.Is(err, io.EOF) {
			t.Fatal("invalid target left socket open", err)
		}
		_ = peer.Close()
	}
}

type lastRelayDelayedRead struct {
	net.Conn
	enabled   atomic.Bool
	started   chan struct{}
	startOnce sync.Once
	entered   chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (c *lastRelayDelayedRead) Read(b []byte) (int, error) {
	held := c.enabled.Load()
	if held {
		c.startOnce.Do(func() { close(c.started) })
	}
	n, err := c.Conn.Read(b)
	if held {
		c.once.Do(func() { close(c.entered) })
		<-c.release
	}
	return n, err
}

func TestLastRelayExternalCancellationRetainsEnteredIOUntilItUnwinds(t *testing.T) {
	request, respond := make(chan struct{}), make(chan struct{})
	server, roots, _ := lastRelayExternalTLSFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
		close(request)
		<-respond
		_, _ = io.WriteString(w, "body")
	})
	defer close(respond)
	raw := &lastRelayDelayedRead{Conn: lastRelayExternalDial(t, server), started: make(chan struct{}), entered: make(chan struct{}), release: make(chan struct{})}
	stream, err := newLastRelayExternalStream(context.Background(), raw, externalTarget, func() bool { return true }, roots)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := stream.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	raw.enabled.Store(true)
	measure, cancelMeasure := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		elapsed, err := stream.Measure(measure, externalTarget)
		if elapsed != 0 {
			done <- errors.New("cancelled response acquired elapsed time")
			return
		}
		done <- err
	}()
	<-request
	select {
	case <-raw.started:
	case <-time.After(time.Second):
		t.Fatal("external response Read never entered its actual socket")
	}
	cancelMeasure()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled response succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("caller waited for ignored raw Read")
	}
	select {
	case <-raw.entered:
	case <-time.After(time.Second):
		t.Fatal("native raw Read never began unwinding")
	}
	cleanup, finish := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err := stream.Close(cleanup); err == nil {
		t.Fatal("raw Close discharged a still-entered TLS Read")
	}
	finish()
	close(raw.release)
	closeLastRelayExternal(t, stream)
}

type lastRelayCloseFailure struct {
	net.Conn
	calls  atomic.Int32
	failed chan struct{}
}

func (c *lastRelayCloseFailure) Close() error {
	if c.calls.Add(1) == 1 {
		close(c.failed)
		return errors.New("held native socket")
	}
	return c.Conn.Close()
}

func TestLastRelayExternalFailedCloseRemainsOwnedForRetry(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	raw := &lastRelayCloseFailure{Conn: left, failed: make(chan struct{})}
	stream, err := NewLastRelayExternalStream(context.Background(), raw, externalTarget, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	stream.Cancel()
	<-raw.failed
	stream.mu.Lock()
	joined, attempt := stream.joined, stream.attempt
	stream.mu.Unlock()
	<-attempt.done
	if joined {
		t.Fatal("failed raw close fabricated joined ownership")
	}
	closeLastRelayExternal(t, stream)
	if raw.calls.Load() < 2 {
		t.Fatal("failed native close was not retried")
	}
}
