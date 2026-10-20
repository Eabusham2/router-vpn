package hopmeasure

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type publicFixture struct {
	server               *httptest.Server
	tls                  *tls.Config
	identity             atomic.Bool
	mode                 atomic.Value
	mu                   sync.Mutex
	tags                 []string
	downloaded, uploaded atomic.Int64
	dial                 func(context.Context, string, string) (net.Conn, error)
}

func (f *publicFixture) Identity() string {
	if !f.identity.Load() {
		return ""
	}
	return "captured-native-public-owner"
}
func (f *publicFixture) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if f.Identity() == "" || tag != "external-entry" && tag != "custom-exit" || address != PublicAddress {
		return nil, errors.New("unowned public fixture dial")
	}
	f.mu.Lock()
	f.tags = append(f.tags, tag)
	f.mu.Unlock()
	if f.dial != nil {
		return f.dial(ctx, tag, address)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", f.server.Listener.Addr().String())
}
func newPublicFixture(t *testing.T) *publicFixture {
	t.Helper()
	f := &publicFixture{}
	f.identity.Store(true)
	f.mode.Store("")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: PublicHost}, DNSNames: []string{PublicHost}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsed)
	f.tls = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != PublicHost || r.Header.Get("Authorization") != "" || r.Header.Get("Accept-Encoding") != "identity" || !strings.Contains(r.Header.Get("Cache-Control"), "no-store") || len(r.URL.Query().Get("routervpn")) != 32 {
			t.Errorf("public request escaped exact HTTPS origin/headers: %s", r.URL)
			http.Error(w, "bad request", 400)
			return
		}
		mode := f.mode.Load().(string)
		if mode == "redirect" {
			http.Redirect(w, r, "https://foreign.invalid/", 302)
			return
		}
		if mode == "compressed" {
			w.Header().Set("Content-Encoding", "gzip")
		}
		if mode == "partial" {
			w.WriteHeader(206)
			return
		}
		if mode == "range" {
			w.Header().Set("Content-Range", "bytes 0-0/2")
		}
		if mode == "retired" {
			f.identity.Store(false)
		}
		switch r.URL.Path {
		case "/__down":
			if r.Method != "GET" {
				t.Error("download method changed")
			}
			size, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
			if size < 1 || size > MaxBytes {
				t.Error("public request size unbounded")
				return
			}
			actual := size
			if mode == "short" {
				actual--
			}
			if mode == "extra" {
				actual++
			}
			if mode == "bad-length" {
				w.Header().Set("Content-Length", strconv.Itoa(size+1))
			} else {
				w.Header().Set("Content-Length", strconv.Itoa(actual))
			}
			data := make([]byte, actual)
			for i := range data {
				data[i] = byte(i % 251)
			}
			n, _ := w.Write(data)
			f.downloaded.Add(int64(n))
		case "/__up":
			if r.Method != "POST" || r.ContentLength < 1 || r.ContentLength > MaxBytes {
				t.Error("public upload size/method changed")
			}
			n, e := io.Copy(io.Discard, r.Body)
			f.uploaded.Add(n)
			if e != nil || n != r.ContentLength {
				t.Error("fixture upload incomplete")
				http.Error(w, "incomplete", 400)
				return
			}
			if mode == "huge-ack" {
				_, _ = w.Write(make([]byte, 8193))
				return
			}
			w.Header().Set("Content-Length", "0")
		default:
			t.Error("public endpoint changed")
			http.NotFound(w, r)
		}
	}))
	f.server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	return f
}
func (f *publicFixture) service(t *testing.T, hops ...Hop) *Service {
	t.Helper()
	s, err := New(f, hops)
	if err != nil {
		t.Fatal(err)
	}
	s.publicTLS = f.tls
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}
func publicHop(role string) Hop {
	tag := "custom-exit"
	if role == "entry" {
		tag = "external-entry"
	}
	return Hop{ID: role + "-node", Role: role, Tag: tag, Kind: "public-path"}
}

func TestPublicHopPayloadUsesEachCapturedRouteAndReportsRealBytes(t *testing.T) {
	f := newPublicFixture(t)
	s := f.service(t, publicHop("entry"), publicHop("exit"))
	id := strings.Repeat("a", 32)
	if err := s.Start(id, 65536); err != nil {
		t.Fatal(err)
	}
	if err := s.Drain(id); err != nil {
		t.Fatal(err)
	}
	var status Status
	if json.Unmarshal([]byte(s.StatusJSON()), &status) != nil {
		t.Fatal("invalid public status")
	}
	if !status.Complete || !status.Drained || status.Failure != "" || len(status.Results) != 2 {
		t.Fatalf("public measurement incomplete: %+v", status)
	}
	for _, r := range status.Results {
		if !r.Ready || r.Kind != "public-path" || !strings.Contains(r.Label, "Cloudflare edge") || r.Idle.Samples != 6 {
			t.Fatalf("public path mislabelled: %+v", r)
		}
		for _, x := range []*Transfer{r.Download, r.Upload} {
			if x == nil || x.Bytes != 65536 || x.Seconds <= 0 || math.Abs(x.Mbps-float64(x.Bytes)*8/x.Seconds/1e6) > 1e-9 {
				t.Fatal("fabricated public transfer", x)
			}
		}
	}
	if f.uploaded.Load() != 2*65536 || f.downloaded.Load() < 2*65536+14 {
		t.Fatal("measurement did not exchange actual bytes")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]bool{}
	for _, tag := range f.tags {
		seen[tag] = true
	}
	if len(seen) != 2 || !seen["external-entry"] || !seen["custom-exit"] {
		t.Fatal("entry and exit routing collapsed", f.tags)
	}
	if strings.Contains(s.StatusJSON(), "fixture-secret") || strings.Contains(s.StatusJSON(), "api_token") {
		t.Fatal("private metadata escaped public result")
	}
}

func TestPublicHTTPRejectsInvalidTLSBodiesAndOwnerChanges(t *testing.T) {
	for _, mode := range []string{"redirect", "compressed", "partial", "range", "short", "extra", "bad-length", "retired", "huge-ack", "untrusted-tls"} {
		t.Run(mode, func(t *testing.T) {
			f := newPublicFixture(t)
			s := f.service(t, publicHop("exit"))
			f.mode.Store(mode)
			if mode == "untrusted-tls" {
				s.publicTLS = nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			n, elapsed, err := s.publicRequest(ctx, s.hops[0], 65536, mode == "huge-ack", nil)
			if err == nil || n != 0 || elapsed != 0 {
				t.Fatalf("invalid public response earned a result: %d %v %v", n, elapsed, err)
			}
		})
	}
}

type publicGateConn struct {
	net.Conn
	closeStarted, closeRelease chan struct{}
	once                       sync.Once
}

func (c *publicGateConn) Close() error {
	c.once.Do(func() { close(c.closeStarted); <-c.closeRelease })
	return c.Conn.Close()
}
func TestPublicCancellationDrainsLateNativeDialAndClose(t *testing.T) {
	f := newPublicFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	closedStarted, closedRelease := make(chan struct{}), make(chan struct{})
	left, right := net.Pipe()
	defer right.Close()
	f.dial = func(context.Context, string, string) (net.Conn, error) {
		close(entered)
		<-release
		return &publicGateConn{Conn: left, closeStarted: closedStarted, closeRelease: closedRelease}, nil
	}
	s := f.service(t, publicHop("exit"))
	id := strings.Repeat("b", 32)
	if err := s.Start(id, 65536); err != nil {
		t.Fatal(err)
	}
	<-entered
	s.Cancel(id)
	var status Status
	_ = json.Unmarshal([]byte(s.StatusJSON()), &status)
	if !status.Complete || status.Drained || len(status.Results) != 0 {
		t.Fatal("cancel pretended pending dial was drained", status)
	}
	drainDone := make(chan error, 1)
	go func() { drainDone <- s.Drain(id) }()
	select {
	case err := <-drainDone:
		t.Fatal("late dial escaped drain", err)
	case <-time.After(15 * time.Millisecond):
	}
	close(release)
	<-closedStarted
	select {
	case err := <-drainDone:
		t.Fatal("late close escaped drain", err)
	case <-time.After(15 * time.Millisecond):
	}
	close(closedRelease)
	if err := <-drainDone; err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal([]byte(s.StatusJSON()), &status)
	if !status.Drained || len(status.Results) != 0 {
		t.Fatal("cancelled bytes survived drain", status)
	}
	if err := s.Drain(strings.Repeat("c", 32)); err == nil {
		t.Fatal("another request drained this owner")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Drain(id); err != nil {
		t.Fatal("closed Box lost the captured cleanup request", err)
	}
}

func TestPublicMeasurementCaptureRejectsPrivateOrForeignRoutes(t *testing.T) {
	f := newPublicFixture(t)
	mutations := map[string]func(*Hop){
		"fake-private-token": func(h *Hop) { h.Token = "secret" }, "fake-private-api": func(h *Hop) { h.API = "http://10.0.0.1:8787" },
		"fake-private-proof": func(h *Hop) { h.Proof = strings.Repeat("a", 64) }, "foreign-tag": func(h *Hop) { h.Tag = "direct" },
		"wrong-role": func(h *Hop) { h.Role = "entry" }, "wrong-kind": func(h *Hop) { h.Kind = "ping" },
		"secret-label": func(h *Hop) { h.Label = "bad\nlabel" }, "oversized-label": func(h *Hop) { h.Label = strings.Repeat("a", 161) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			hop := publicHop("exit")
			mutate(&hop)
			if _, err := New(f, []Hop{hop}); err == nil {
				t.Fatal("invalid frozen public path accepted")
			}
		})
	}
	if _, err := New(f, []Hop{publicHop("exit"), publicHop("exit")}); err == nil {
		t.Fatal("same identity used twice")
	}
	if _, err := f.Dial(context.Background(), "custom-exit", "foreign.invalid:443"); err == nil {
		t.Fatal("arbitrary public endpoint accepted")
	}
	f.identity.Store(false)
	if _, err := New(f, []Hop{publicHop("exit")}); err == nil {
		t.Fatal("retired native owner captured")
	}
}

func TestPublicOwnerChangedDuringFinalResponseCannotPublish(t *testing.T) {
	f := newPublicFixture(t)
	s := f.service(t, publicHop("exit"))
	f.mode.Store("retired")
	id := fmt.Sprintf("%032x", 17)
	if err := s.Start(id, 65536); err != nil {
		t.Fatal(err)
	}
	if err := s.Drain(id); err != nil {
		t.Fatal(err)
	}
	var status Status
	_ = json.Unmarshal([]byte(s.StatusJSON()), &status)
	if len(status.Results) != 0 || status.Failure == "" || !status.Drained {
		t.Fatal("changed path published a public result", status)
	}
}
