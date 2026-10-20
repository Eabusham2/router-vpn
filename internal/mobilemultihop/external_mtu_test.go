package mobilemultihop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func externalMTUFixture(t *testing.T) (*ExternalProofRequest, *externalProofFixture, string, string) {
	t.Helper()
	graph, captured := externalTestFixture(t, "shadowsocks", "router-wg")
	source, capture := externalTestJSON(t, graph), externalTestJSON(t, captured)
	policy, err := NewExternalPolicy(source, capture)
	if err != nil {
		t.Fatal(err)
	}
	engine := &externalProofFixture{}
	engine.current.Store(true)
	engine.dns = func(ctx context.Context, tag string) error {
		if tag != "tun-in" || ctx.Err() != nil {
			return errors.New("wrong DNS owner")
		}
		return nil
	}
	engine.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Error("MTU verification used the internal outbound instead of the system TUN")
		return nil, errors.New("forbidden internal dial")
	}
	r, err := NewExternalProofRequest(context.Background(), policy, "captured-session", engine)
	if err != nil {
		t.Fatal(err)
	}
	r.public = func(context.Context, string, string) error { return nil }
	r.private = func(context.Context) error { return nil }
	t.Cleanup(r.Cancel)
	return r, engine, source, capture
}

func TestExternalMTUAuthorityRequiresExactSuccessfulProof(t *testing.T) {
	r, _, source, capture := externalMTUFixture(t)
	if _, _, err := r.MTUAuthority(source, capture); err == nil {
		t.Fatal("unproved connection granted MTU authority")
	}
	if _, err := r.Run(); err != nil {
		t.Fatal(err)
	}
	config, authority, err := r.MTUAuthority(source, capture)
	if err != nil || config != r.policy.Config() {
		t.Fatal("matching proof rejected", err)
	}
	var got map[string]any
	if json.Unmarshal([]byte(authority), &got) != nil || len(got) != 6 || got["id"] != "saved-exit" || got["schema"] != float64(1) || got["source_sha256"] != r.policy.SourceSHA256() || got["expected_public_ip"] != "203.0.113.88" || got["mtu_policy"] != "auto" || got["jumbo_tun"] != false {
		t.Fatal("MTU authority lost its exact proof or leaked unrelated profile data", authority)
	}
	if strings.Contains(authority, "captured-entry-token") || strings.Contains(authority, "effective_mtu") || strings.Contains(authority, "8800") {
		t.Fatal("saved history or private credentials became authority")
	}
	for _, mutation := range []string{"public-ip", "exit-id", "dns", "entry-token", "mode"} {
		selected := externalTestRead(t, capture)
		profile := selected["profile"].(map[string]any)
		switch mutation {
		case "public-ip":
			selected["expected_public_ip"] = "203.0.113.99"
			profile["external"].(map[string]any)["expected_public_ip"] = "203.0.113.99"
		case "exit-id":
			selected["exit_id"] = "foreign-exit"
			profile["id"] = "foreign-exit"
		case "dns":
			profile["dns_mode"] = "custom"
			profile["dns_protocol"] = "tcp"
			profile["dns_host"] = "9.9.9.9"
			profile["dns_port"] = float64(5353)
		case "entry-token":
			selected["entry"].(map[string]any)["api_token"] = "foreign-token"
		case "mode":
			profile["mtu_policy"] = "fixed"
			profile["manual_mtu"] = float64(1380)
		}
		if _, _, err := r.MTUAuthority(source, externalTestJSON(t, selected)); err == nil {
			t.Fatal("changed capture adopted proof", mutation)
		}
	}
	if _, _, err := r.MTUAuthority(source+" ", capture); err == nil {
		t.Fatal("different original source adopted proof")
	}
	r.Cancel()
	if _, _, err := r.MTUAuthority(source, capture); err == nil {
		t.Fatal("retired proof granted authority")
	}
}

func TestExternalMTULifetimeBelongsOnlyToRetainedProof(t *testing.T) {
	r, engine, _, _ := externalMTUFixture(t)
	if _, _, err := r.MTULifetime(context.Background()); err == nil {
		t.Fatal("unproved lifetime granted")
	}
	if _, err := r.Run(); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := r.MTULifetime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
	if ctx.Err() == nil || !r.Healthy() {
		t.Fatal("lease release canceled proof or failed to stop itself")
	}
	ctx, release, err = r.MTULifetime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	r.Cancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("proof cancellation did not reach native operation")
	}
	other, _, _, _ := externalMTUFixture(t)
	if _, err := other.Run(); err != nil {
		t.Fatal(err)
	}
	if !other.Healthy() {
		t.Fatal("old proof cancellation affected another connection")
	}
	engine.current.Store(false)
	if _, _, err := r.MTULifetime(context.Background()); err == nil {
		t.Fatal("foreign owner granted lifetime")
	}
	if _, _, err := other.MTULifetime(nil); err == nil {
		t.Fatal("missing parent accepted")
	}
}

// Use a locally generated certificate for the fixed literal production origin.
// The only socket dial is redirected to this test server; no public route opens.
func externalMTUTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, *tls.Config) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), IPAddresses: []net.IP{net.ParseIP("1.1.1.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return server, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
}

func TestExternalMTUReprovesDNSAndPublicExitThroughSystemTUN(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-ip", "dns-failed", "owner-changed", "canceled-during-body", "untrusted-tls"} {
		t.Run(mode, func(t *testing.T) {
			r, engine, _, _ := externalMTUFixture(t)
			if _, err := r.Run(); err != nil {
				t.Fatal(err)
			}
			var dnsCalls, dials atomic.Int32
			engine.dns = func(ctx context.Context, tag string) error {
				dnsCalls.Add(1)
				if tag != "tun-in" || ctx.Err() != nil || mode == "dns-failed" {
					return errors.New("DNS failed")
				}
				return nil
			}
			server, trust := externalMTUTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				if q.Host != "1.1.1.1" || q.URL.Path != "/cdn-cgi/trace" || len(q.URL.Query().Get("routervpn_mtu")) != 32 || q.Header.Get("Authorization") != "" || q.Header.Get("Cache-Control") != "no-store" {
					t.Error("proof origin, nonce or privacy changed")
				}
				ip := "203.0.113.88"
				if mode == "wrong-ip" {
					ip = "203.0.113.77"
				}
				if mode == "owner-changed" {
					engine.current.Store(false)
				}
				if mode == "canceled-during-body" {
					r.Cancel()
				}
				fmt.Fprintf(w, "ip=%s\n", ip)
			}))
			dial := func(ctx context.Context, tag, address string) (net.Conn, error) {
				dials.Add(1)
				if tag != ExternalFinalTag || address != "1.1.1.1:443" || dnsCalls.Load() != 1 {
					return nil, errors.New("wrong captured system TUN path")
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}
			if mode == "untrusted-tls" {
				trust = nil
			}
			err := r.verifyMTU(context.Background(), dial, trust)
			if (err == nil) != (mode == "valid") {
				t.Fatal("invalid public path accepted or working path rejected", mode, err)
			}
			if dnsCalls.Load() != 1 || (mode == "dns-failed" && dials.Load() != 0) || (mode != "dns-failed" && dials.Load() != 1) {
				t.Fatal("DNS/exit proof ownership or ordering changed")
			}
		})
	}
}

func TestExternalMTUCancelDrainsCapturedDNSBeforeAnySocket(t *testing.T) {
	r, engine, _, _ := externalMTUFixture(t)
	if _, err := r.Run(); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	engine.dns = func(ctx context.Context, _ string) error { close(entered); <-ctx.Done(); return ctx.Err() }
	done := make(chan error, 1)
	go func() {
		done <- r.VerifyMTU(context.Background(), func(context.Context, string, string) (net.Conn, error) {
			t.Error("canceled DNS opened a socket")
			return nil, errors.New("unexpected")
		})
	}()
	<-entered
	r.Cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled MTU proof succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("MTU proof did not drain on cancellation")
	}
}
