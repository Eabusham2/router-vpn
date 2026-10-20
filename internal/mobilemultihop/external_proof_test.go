package mobilemultihop

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type externalProofFixture struct {
	current atomic.Bool
	dns     func(context.Context, string) error
	dial    func(context.Context, string, string) (net.Conn, error)
}

func (e *externalProofFixture) Identity() string {
	if e.current.Load() {
		return "captured-native-box"
	}
	return ""
}
func (e *externalProofFixture) DNSProof(ctx context.Context, tag string) error {
	return e.dns(ctx, tag)
}
func (e *externalProofFixture) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	return e.dial(ctx, tag, address)
}

func externalRequestFixture(t *testing.T, entry string) (*ExternalProofRequest, *externalProofFixture, *[]string) {
	t.Helper()
	graph, capture := externalTestFixture(t, "shadowsocks", entry)
	policy, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture))
	if err != nil {
		t.Fatal(err)
	}
	order := []string{}
	engine := &externalProofFixture{}
	engine.current.Store(true)
	engine.dns = func(ctx context.Context, tag string) error {
		if tag != "tun-in" || ctx.Err() != nil {
			t.Fatal("wrong DNS owner")
		}
		order = append(order, "dns")
		return nil
	}
	engine.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("unsubstituted public networking")
		return nil, errors.New("unexpected")
	}
	r, err := NewExternalProofRequest(context.Background(), policy, "session-old", engine)
	if err != nil {
		t.Fatal(err)
	}
	r.public = func(ctx context.Context, tag, ip string) error {
		if !externalPublicIP(ip) {
			t.Fatal("missing selected public identity")
		}
		order = append(order, tag)
		return nil
	}
	r.private = func(ctx context.Context) error { order = append(order, "private-entry"); return nil }
	t.Cleanup(r.Cancel)
	return r, engine, &order
}

func TestExternalProofBindsSelectedDNSBothEntriesAndExit(t *testing.T) {
	for _, entry := range []string{"", "router-wg", "socks5"} {
		t.Run(entry, func(t *testing.T) {
			r, _, order := externalRequestFixture(t, entry)
			if r.Healthy() {
				t.Fatal("unproved connection was healthy")
			}
			before := time.Now().UnixMilli()
			raw, err := r.Run()
			if err != nil {
				t.Fatal(err)
			}
			var p ExternalProofResult
			var keys map[string]any
			if json.Unmarshal([]byte(raw), &p) != nil || json.Unmarshal([]byte(raw), &keys) != nil || len(keys) != 11 {
				t.Fatal("host envelope differs", raw)
			}
			if p.Schema != 1 || p.SessionID != "session-old" || p.SourceSHA256 != r.policy.SourceSHA256() || p.ConfigSHA256 != externalDigest([]byte(r.policy.Config())) || !p.DNSProven || p.IP != r.meta.ExpectedPublicIP || p.CheckedAt < before || p.CheckedAt > time.Now().UnixMilli() || !r.Healthy() {
				t.Fatal("unbound successful proof", raw)
			}
			want := "dns,custom-exit"
			if entry == "router-wg" {
				want = "private-entry," + want
				if p.EntryNodeID != strings.Repeat("c", 64) {
					t.Fatal("wrong private entry")
				}
			}
			if entry == "socks5" {
				want = "external-entry," + want
			}
			if strings.Join(*order, ",") != want || p.EntryProven != (entry != "") {
				t.Fatal("proof order or graph differs", *order)
			}
			if _, err := r.Run(); err == nil {
				t.Fatal("proof was reused")
			}
			r.Cancel()
			if r.Healthy() {
				t.Fatal("canceled successful proof stayed healthy")
			}
		})
	}
}

func TestExternalProofRejectsFailureCancellationAndChangedNativeOwner(t *testing.T) {
	for _, mode := range []string{"cancel-before", "cancel-dns", "cancel-exit", "retired-dns", "retired-exit", "dns-failure", "entry-failure", "exit-failure"} {
		t.Run(mode, func(t *testing.T) {
			r, engine, order := externalRequestFixture(t, "router-wg")
			if mode == "cancel-before" {
				r.Cancel()
			}
			baseDNS := engine.dns
			engine.dns = func(ctx context.Context, tag string) error {
				_ = baseDNS(ctx, tag)
				switch mode {
				case "cancel-dns":
					r.Cancel()
				case "retired-dns":
					engine.current.Store(false)
				case "dns-failure":
					return errors.New("secret resolver failure")
				}
				return nil
			}
			if mode == "entry-failure" {
				r.private = func(context.Context) error { return errors.New("private-token") }
			}
			basePublic := r.public
			r.public = func(ctx context.Context, tag, ip string) error {
				_ = basePublic(ctx, tag, ip)
				switch mode {
				case "cancel-exit":
					r.Cancel()
				case "retired-exit":
					engine.current.Store(false)
				case "exit-failure":
					return errors.New("wrong public address")
				}
				return nil
			}
			raw, err := r.Run()
			if err == nil || raw != "" || r.Healthy() || strings.Contains(err.Error(), "private-token") || strings.Contains(err.Error(), "secret resolver") {
				t.Fatal("invalid or private proof escaped", raw, err)
			}
			if mode == "cancel-before" && len(*order) != 0 {
				t.Fatal("canceled request opened work")
			}
			if mode == "entry-failure" && len(*order) != 0 {
				t.Fatal("failed entry reached DNS or exit")
			}
			if strings.Contains(mode, "dns") && strings.Contains(strings.Join(*order, ","), "custom-exit") {
				t.Fatal("invalid DNS still reached exit")
			}
		})
	}
}

func TestExternalProofCancelUnblocksOnlyCapturedDNSRequest(t *testing.T) {
	r, engine, _ := externalRequestFixture(t, "")
	entered := make(chan struct{})
	engine.dns = func(ctx context.Context, _ string) error { close(entered); <-ctx.Done(); return ctx.Err() }
	result := make(chan error, 1)
	go func() { _, err := r.Run(); result <- err }()
	<-entered
	replacement, _, _ := externalRequestFixture(t, "")
	r.Cancel()
	r.Cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled DNS succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("native DNS cancellation did not unblock")
	}
	if replacement.ctx.Err() != nil || r.Healthy() {
		t.Fatal("old cancel reached replacement")
	}
}

func TestExternalEntryProofRequiredForEveryDNSPolicy(t *testing.T) {
	for _, entry := range []string{"router-wg", "socks5"} {
		graph, capture := externalTestFixture(t, "shadowsocks", entry)
		captured := capture["entry"].(map[string]any)
		if entry == "router-wg" {
			delete(captured, "api_token")
		} else {
			delete(captured["external"].(map[string]any), "expected_public_ip")
		}
		if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture)); err == nil {
			t.Fatal("non-Home DNS bypassed entry proof", entry)
		}
	}
}

func TestExternalTraceRejectsWrongDuplicateAndNonPublicAddresses(t *testing.T) {
	for _, body := range []string{"", "ip=10.0.0.1\n", "ip=203.0.113.9\n", "ip=203.0.113.88\nip=203.0.113.88\n", "other=203.0.113.88\n", strings.Repeat("x", 8193)} {
		if externalTraceAddress([]byte(body), "203.0.113.88") == nil {
			t.Fatal("invalid exit proof accepted")
		}
	}
	if err := externalTraceAddress([]byte("fl=abc\nip=203.0.113.88\n"), "203.0.113.88"); err != nil {
		t.Fatal(err)
	}
}

func TestExternalProofHTTPUsesExactRouteTLSAndBoundedResponse(t *testing.T) {
	var seen atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		if r.Header.Get("Authorization") != "Bearer private-token" || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Cache-Control") != "no-store" {
			t.Error("proof request changed")
		}
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "https://example.org", 302)
		case "/large":
			fmt.Fprint(w, strings.Repeat("x", 8193))
		case "/encoding":
			w.Header().Set("Content-Encoding", "gzip")
			fmt.Fprint(w, "ip=203.0.113.88\n")
		default:
			fmt.Fprint(w, "ip=203.0.113.88\n")
		}
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	config := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	dial := func(ctx context.Context, tag, address string) (net.Conn, error) {
		if tag != "captured-route" || address != server.Listener.Addr().String() {
			t.Fatal("route changed", tag, address)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	data, err := externalProofHTTP(context.Background(), dial, "captured-route", server.URL+"/ok", "private-token", config)
	if err != nil || externalTraceAddress(data, "203.0.113.88") != nil {
		t.Fatal("actual TLS response failed", err)
	}
	for _, path := range []string{"/redirect", "/large", "/encoding"} {
		if body, err := externalProofHTTP(context.Background(), dial, "captured-route", server.URL+path, "private-token", config); err == nil || body != nil {
			t.Fatal("invalid HTTP response accepted", path)
		}
	}
	if _, err := externalProofHTTP(context.Background(), dial, "captured-route", server.URL+"/ok", "private-token", nil); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if seen.Load() != 4 {
		t.Fatal("redirect or untrusted TLS reached another request", seen.Load())
	}
}

func TestExternalProofLateDialAndUnsupportedDeadlineCannotSucceed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	left, right := net.Pipe()
	defer right.Close()
	entered, resume := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	dial := func(context.Context, string, string) (net.Conn, error) { close(entered); <-resume; return left, nil }
	go func() {
		_, err := externalProofHTTP(ctx, dial, "entry", "http://10.1.2.3/health", "", nil)
		result <- err
	}()
	<-entered
	cancel()
	close(resume)
	if err := <-result; err == nil {
		t.Fatal("late dial succeeded after cancellation")
	}
	if _, err := left.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("late owned socket was leaked", err)
	}
}
