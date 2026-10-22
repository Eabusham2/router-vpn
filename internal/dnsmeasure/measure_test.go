package dnsmeasure

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
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
)

const firstRequest = "11111111111111111111111111111111"
const secondRequest = "22222222222222222222222222222222"

type fakeEngine struct {
	mu       sync.Mutex
	identity string
	active   bool
	releases int
	dials    []string
	selected atomic.Int32
	dial     func(context.Context, string) (net.Conn, error)
	selectFn func(context.Context) error
	ctx      context.Context
	cancel   context.CancelFunc
}

func newFake() *fakeEngine {
	ctx, cancel := context.WithCancel(context.Background())
	return &fakeEngine{identity: "proved-native-generation", ctx: ctx, cancel: cancel}
}
func (e *fakeEngine) Identity() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.identity
}
func (e *fakeEngine) BeginMeasurement(parent context.Context) (context.Context, func(), error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.active {
		return nil, nil, errors.New("busy")
	}
	e.active = true
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(e.ctx, cancel)
	return ctx, func() {
		stop()
		cancel()
		e.mu.Lock()
		e.active = false
		e.releases++
		e.mu.Unlock()
	}, nil
}
func (e *fakeEngine) Dial(ctx context.Context, address string) (net.Conn, error) {
	e.mu.Lock()
	e.dials = append(e.dials, address)
	e.mu.Unlock()
	return e.dial(ctx, address)
}
func (e *fakeEngine) SelectedDNS(ctx context.Context) error {
	e.selected.Add(1)
	if e.selectFn != nil {
		return e.selectFn(ctx)
	}
	return nil
}
func fixture(t *testing.T) (*Service, *fakeEngine) {
	t.Helper()
	e := newFake()
	description := Description{NodeID: "saved-exit", SessionID: "proved-session", RouteLabel: "Current Tor connection", IPv6Enabled: true, Selected: Endpoint{ID: "selected", Name: "Selected DNS", Kind: "selected", Address: "10.77.0.1", Port: 5353, Transport: "udp", Route: "entry-wg", RouteLabel: "Selected DNS via entry-wg"}}
	s, err := New(e, description)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.cancel()
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, e
}
func status(t *testing.T, s *Service) Status {
	t.Helper()
	var result Status
	if err := json.Unmarshal([]byte(s.StatusJSON()), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func finish(t *testing.T, s *Service, request string) Status {
	t.Helper()
	if err := s.Drain(request); err != nil {
		t.Fatal(err)
	}
	result := status(t, s)
	if !result.Drained || !result.Complete {
		t.Fatalf("not complete and drained: %+v", result)
	}
	return result
}
func answer(query []byte) []byte {
	data := append([]byte(nil), query...)
	data[2], data[3], data[7] = 0x81, 0x80, 1
	return append(data, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34)
}
func readFrame(connection net.Conn) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return nil, err
	}
	data := make([]byte, binary.BigEndian.Uint16(header[:]))
	_, err := io.ReadFull(connection, data)
	return data, err
}
func writeFrame(connection net.Conn, data []byte) {
	header := []byte{byte(len(data) >> 8), byte(len(data))}
	_, _ = connection.Write(append(header, data...))
}
func served(fn func(net.Conn)) net.Conn {
	client, server := net.Pipe()
	go func() { defer server.Close(); _ = server.SetDeadline(time.Now().Add(SampleTimeout)); fn(server) }()
	return client
}
func tcpAnswer(connection net.Conn) {
	query, err := readFrame(connection)
	if err == nil {
		writeFrame(connection, answer(query))
	}
}
func certificates(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test resolver"}, DNSNames: []string{"cloudflare-dns.com", "dns.google", "dns.quad9.net"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}, &tls.Config{RootCAs: roots}
}

func TestAllCatalogTransportsUseOwnedLiteralExitAndKeepSelectedHome(t *testing.T) {
	serverTLS, clientTLS := certificates(t)
	for _, transport := range []string{"tcp", "tls", "https"} {
		t.Run(transport, func(t *testing.T) {
			s, e := fixture(t)
			s.testTLS = clientTLS
			e.dial = func(ctx context.Context, address string) (net.Conn, error) {
				if !AllowedPublicAddress(address) {
					t.Errorf("unowned address: %s", address)
				}
				return served(func(raw net.Conn) {
					connection := raw
					if transport != "tcp" {
						secure := tls.Server(raw, serverTLS)
						if secure.Handshake() != nil {
							return
						}
						connection = secure
					}
					if transport != "https" {
						tcpAnswer(connection)
						return
					}
					request, err := http.ReadRequest(bufio.NewReader(connection))
					if err != nil {
						return
					}
					if request.Method != "POST" || request.URL.Path != "/dns-query" || request.Header.Get("Content-Type") != "application/dns-message" || request.Header.Get("Cache-Control") != "no-store" || request.Header.Get("Accept-Encoding") != "identity" {
						t.Error("DoH request shape changed")
					}
					query, _ := io.ReadAll(request.Body)
					response := answer(query)
					_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: "+strconv.Itoa(len(response))+"\r\nConnection: close\r\n\r\n")
					_, _ = connection.Write(response)
				}), nil
			}
			if err := s.Start(firstRequest, transport); err != nil {
				t.Fatal(err)
			}
			r := finish(t, s, firstRequest)
			if r.Failure != "" || r.Schema != 1 || r.Request != firstRequest || r.NodeID != "saved-exit" || r.SessionID != "proved-session" || r.PublicTransport != transport || len(r.Results) != 13 {
				t.Fatalf("wrong receipt: %+v", r)
			}
			for _, row := range r.Results {
				if !row.Ready || row.Samples != 3 || row.Failed != 0 || row.Median == nil || *row.Median <= 0 {
					t.Fatalf("unproved sample: %+v", row)
				}
			}
			selected := r.Results[0]
			if selected.ID != "selected" || selected.Transport != "udp" || selected.Port != 5353 || selected.Address != "10.77.0.1" || selected.Route != "entry-wg" || e.selected.Load() != 3 {
				t.Fatalf("Home DNS was substituted: %+v", selected)
			}
			e.mu.Lock()
			defer e.mu.Unlock()
			if len(e.dials) != 36 || e.active || e.releases != 1 {
				t.Fatalf("native owner leaked: dials=%d active=%v releases=%d", len(e.dials), e.active, e.releases)
			}
			for _, address := range e.dials {
				if strings.Contains(address, "10.77.0.1") {
					t.Error("selected Home was sent to public probe dialer")
				}
			}
		})
	}
}

func TestUnavailableResolversHaveNoMedianAndNoFallback(t *testing.T) {
	s, e := fixture(t)
	e.selectFn = func(context.Context) error { return errors.New("captured Home DNS failed") }
	e.dial = func(ctx context.Context, address string) (net.Conn, error) {
		if address != "1.1.1.1:53" {
			return nil, errors.New("unreachable")
		}
		return served(tcpAnswer), nil
	}
	if err := s.Start(firstRequest, "tcp"); err != nil {
		t.Fatal(err)
	}
	r := finish(t, s, firstRequest)
	for _, row := range r.Results {
		if row.ID == "cf4a" {
			if !row.Ready || row.Median == nil {
				t.Fatal("valid response lost")
			}
			continue
		}
		if row.Ready || row.Median != nil || row.Samples != 0 || row.Failed != 3 || row.Failure == "" {
			t.Fatalf("failure gained a latency: %+v", row)
		}
	}
	if e.selected.Load() != 3 {
		t.Fatal("selected-DNS failed request retried through another resolver")
	}
}

func TestIPv6OffCatalogRowsStayVisibleWithoutAnyIPv6Dial(t *testing.T) {
	s, e := fixture(t)
	s.description.IPv6Enabled = false
	e.dial = func(_ context.Context, address string) (net.Conn, error) {
		if strings.HasPrefix(address, "[") {
			t.Error("IPv6-Off opened an IPv6 resolver")
		}
		return served(tcpAnswer), nil
	}
	if err := s.Start(firstRequest, "tcp"); err != nil {
		t.Fatal(err)
	}
	r := finish(t, s, firstRequest)
	filtered := 0
	for _, row := range r.Results {
		if strings.Contains(row.Address, ":") {
			filtered++
			if row.Ready || row.Median != nil || row.Samples != 0 || row.Failed != 3 || !strings.Contains(row.Failure, "IPv6 is disabled") {
				t.Fatal("filtered row was hidden or mislabeled", row)
			}
		}
	}
	if filtered != 6 {
		t.Fatal("IPv6 catalog rows missing", filtered)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.dials) != 18 {
		t.Fatal("IPv6 policy changed public query count", len(e.dials))
	}
}

func TestTLSCertificateFailureCannotBecomeLatency(t *testing.T) {
	serverTLS, _ := certificates(t)
	for _, transport := range []string{"tls", "https"} {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			t.Run(transport+"/"+tls.VersionName(version), func(t *testing.T) {
				s, e := fixture(t)
				config := serverTLS.Clone()
				config.MinVersion, config.MaxVersion = version, version
				e.dial = untrustedTLSResolver(t, config, transport)
				if err := s.Start(firstRequest, transport); err != nil {
					t.Fatal(err)
				}
				r := finish(t, s, firstRequest)
				if len(r.Results) != 13 || !r.Results[0].Ready {
					t.Fatal("certificate rejection changed the selected DNS row or catalog")
				}
				for _, row := range r.Results[1:] {
					if row.Ready || row.Median != nil || row.Samples != 0 || row.Failed != 3 {
						t.Fatal("untrusted certificate was accepted")
					}
				}
				e.mu.Lock()
				defer e.mu.Unlock()
				if len(e.dials) != 36 || e.active || e.releases != 1 {
					t.Fatal("certificate rejection did not join every sample and native activity")
				}
			})
		}
	}
}

func untrustedTLSResolver(t *testing.T, config *tls.Config, transport string) func(context.Context, string) (net.Conn, error) {
	t.Helper()
	// A real TCP pair lets a TLS rejection alert cross a pending server flight.
	// Go 1.23 can otherwise block both writes on unbuffered net.Pipe until the
	// sample deadline, exercising an artificial duplex deadlock instead of the
	// certificate rejection. Keep the production sample/drain bounds unchanged.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{})
	var peers sync.WaitGroup
	go func() {
		defer close(accepted)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			peers.Add(1)
			go func() {
				defer peers.Done()
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(SampleTimeout))
				connection := tls.Server(raw, config)
				if connection.Handshake() != nil {
					return
				}
				// A verification bypass must produce eligible answers and fail the
				// test, rather than being hidden by a peer that sends no DNS reply.
				if transport == "tls" {
					tcpAnswer(connection)
					return
				}
				request, err := http.ReadRequest(bufio.NewReader(connection))
				if err != nil {
					return
				}
				query, err := io.ReadAll(io.LimitReader(request.Body, maxDNSMessage+1))
				if err != nil || len(query) > maxDNSMessage {
					return
				}
				response := answer(query)
				_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: "+strconv.Itoa(len(response))+"\r\nConnection: close\r\n\r\n")
				_, _ = connection.Write(response)
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-accepted; peers.Wait() })
	return func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}
}

func TestDoHRejectsRedirectWrongMediaOversizeAndTruncation(t *testing.T) {
	serverTLS, clientTLS := certificates(t)
	for _, scenario := range []string{"redirect", "media", "oversize", "truncated", "gzip", "headers"} {
		t.Run(scenario, func(t *testing.T) {
			s, e := fixture(t)
			s.testTLS = clientTLS
			e.dial = func(context.Context, string) (net.Conn, error) {
				return served(func(raw net.Conn) {
					connection := tls.Server(raw, serverTLS)
					if connection.Handshake() != nil {
						return
					}
					request, err := http.ReadRequest(bufio.NewReader(connection))
					if err != nil {
						return
					}
					query, _ := io.ReadAll(request.Body)
					body := answer(query)
					header := "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
					switch scenario {
					case "redirect":
						header = "HTTP/1.1 302 Found\r\nLocation: https://unowned.invalid/dns-query\r\nContent-Type: application/dns-message\r\n"
					case "media":
						header = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
					case "oversize":
						body = make([]byte, maxDNSMessage+1)
					case "truncated":
						body = body[:len(body)-1]
					case "gzip":
						header += "Content-Encoding: gzip\r\n"
					case "headers":
						header += "X-Oversized: " + strings.Repeat("x", 4*maxDNSMessage) + "\r\n"
					}
					_, _ = io.WriteString(connection, header+"Content-Length: "+strconv.Itoa(len(body))+"\r\n\r\n")
					_, _ = connection.Write(body)
				}), nil
			}
			endpoint := candidates("https", "Current Tor connection")[0]
			if value, err := s.sample(context.Background(), endpoint); err == nil || value != 0 {
				t.Fatal("invalid DoH response accepted")
			}
			e.mu.Lock()
			defer e.mu.Unlock()
			if len(e.dials) != 1 {
				t.Fatal("DoH followed a redirect or retried elsewhere")
			}
		})
	}
}

func TestFreshNonceCancelBeforeStartAndProofInvalidation(t *testing.T) {
	s, e := fixture(t)
	e.dial = func(context.Context, string) (net.Conn, error) { return served(tcpAnswer), nil }
	for _, transport := range []string{"udp", "h3", "", "https://1.1.1.1"} {
		if s.Start(firstRequest, transport) == nil {
			t.Fatal("unbounded transport accepted")
		}
	}
	if s.Start("uppercase-or-short", "tcp") == nil {
		t.Fatal("invalid nonce accepted")
	}
	if s.Drain(firstRequest) == nil {
		t.Fatal("unknown request claimed drained")
	}
	s.Cancel(firstRequest)
	if err := s.Drain(firstRequest); err != nil {
		t.Fatal("cancel-before-start not acknowledged", err)
	}
	if s.Start(firstRequest, "tcp") == nil {
		t.Fatal("cancelled queued start reopened")
	}
	if err := s.Start(secondRequest, "tcp"); err != nil {
		t.Fatal(err)
	}
	finish(t, s, secondRequest)
	if s.Start(secondRequest, "tcp") == nil {
		t.Fatal("request nonce reused")
	}
	e.mu.Lock()
	e.identity = "new-generation"
	e.mu.Unlock()
	r := status(t, s)
	if !r.Complete || !r.Drained || r.Failure == "" || len(r.Results) != 0 {
		t.Fatal("stale owner kept its results")
	}
	if s.Start("33333333333333333333333333333333", "tls") == nil {
		t.Fatal("retired owner reopened")
	}
}

func TestCancelRetainsLateDialAndExclusiveActivityThroughActualClose(t *testing.T) {
	for _, reason := range []string{"cancel", "network", "proof", "identity"} {
		t.Run(reason, func(t *testing.T) {
			s, e := fixture(t)
			entered, release := make(chan struct{}, Workers), make(chan struct{})
			var closed atomic.Int32
			e.dial = func(context.Context, string) (net.Conn, error) {
				entered <- struct{}{}
				<-release
				return &countClose{Conn: served(tcpAnswer), closed: &closed}, nil
			}
			if err := s.Start(firstRequest, "tcp"); err != nil {
				t.Fatal(err)
			}
			<-entered
			switch reason {
			case "cancel":
				s.Cancel(firstRequest)
			case "network":
				s.Invalidate()
			case "proof":
				e.cancel()
			case "identity":
				e.mu.Lock()
				e.identity = "replacement"
				e.mu.Unlock()
			}
			if status(t, s).Drained {
				t.Fatal("late native dial acknowledged as drained")
			}
			e.mu.Lock()
			active := e.active
			e.mu.Unlock()
			if !active {
				t.Fatal("activity released before dial returned")
			}
			if s.Start(secondRequest, "tcp") == nil {
				t.Fatal("new request overlapped retained native dial")
			}
			joined := make(chan error, 1)
			go func() { joined <- s.Drain(firstRequest) }()
			select {
			case <-joined:
				t.Fatal("Drain returned before native dial")
			case <-time.After(30 * time.Millisecond):
			}
			close(release)
			if err := <-joined; err != nil {
				t.Fatal(err)
			}
			r := status(t, s)
			if !r.Drained || r.Failure == "" || len(r.Results) != 0 || closed.Load() == 0 {
				t.Fatal("late success or leaked socket after cancellation")
			}
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.active || e.releases != 1 {
				t.Fatal("activity did not release exactly once after drain")
			}
		})
	}
}

type countClose struct {
	net.Conn
	closed *atomic.Int32
}

func (c *countClose) Close() error { c.closed.Add(1); return c.Conn.Close() }

func TestFailedNativeCloseKeepsDrainAndScopeUntilRetrySucceeds(t *testing.T) {
	s, e := fixture(t)
	var permit atomic.Bool
	entered := make(chan struct{}, 64)
	e.dial = func(context.Context, string) (net.Conn, error) {
		return &retryClose{Conn: served(tcpAnswer), permit: &permit, entered: entered}, nil
	}
	if err := s.Start(firstRequest, "tcp"); err != nil {
		t.Fatal(err)
	}
	<-entered
	s.Cancel(firstRequest)
	r := status(t, s)
	if r.Drained {
		t.Fatal("failed close marked drained")
	}
	e.mu.Lock()
	active := e.active
	e.mu.Unlock()
	if !active {
		t.Fatal("failed close released native activity")
	}
	permit.Store(true)
	r = finish(t, s, firstRequest)
	if len(r.Results) != 0 || r.Failure == "" {
		t.Fatal("close failure retained usable results")
	}
}

type retryClose struct {
	net.Conn
	permit  *atomic.Bool
	entered chan struct{}
}

type terminalClose struct {
	net.Conn
	err error
}

func (c *terminalClose) Close() error { return c.err }

func TestAlreadyClosedNativeSocketsReleaseTheOwnedScope(t *testing.T) {
	for _, terminal := range []error{net.ErrClosed, io.ErrClosedPipe} {
		t.Run(terminal.Error(), func(t *testing.T) {
			s, e := fixture(t)
			e.dial = func(context.Context, string) (net.Conn, error) {
				client, server := net.Pipe()
				_ = client.Close()
				_ = server.Close()
				return &terminalClose{Conn: client, err: errors.Join(errors.New("native socket is already closed"), terminal)}, nil
			}
			if err := s.Start(firstRequest, "tcp"); err != nil {
				t.Fatal(err)
			}
			r := finish(t, s, firstRequest)
			if !r.Drained || !r.Complete || len(r.Results) != 13 || r.Results[1].Ready {
				t.Fatal("terminal native close retained a scope or invented a DNS answer")
			}
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.active || e.releases != 1 {
				t.Fatal("documented terminal socket close did not release the exact native scope")
			}
		})
	}
}

func (c *retryClose) Close() error {
	select {
	case c.entered <- struct{}{}:
	default:
	}
	if !c.permit.Load() {
		return errors.New("native Close pending")
	}
	return c.Conn.Close()
}

func TestScopeExcludesConcurrentMeasurementsAndFailedStartCanDrain(t *testing.T) {
	s, e := fixture(t)
	e.mu.Lock()
	e.active = true
	e.mu.Unlock()
	if s.Start(firstRequest, "tcp") == nil {
		t.Fatal("busy native activity accepted")
	}
	s.Cancel(firstRequest)
	if err := s.Drain(firstRequest); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.active || e.releases != 0 {
		t.Fatal("rejected measurement released another controller's scope")
	}
	e.active = false
}
