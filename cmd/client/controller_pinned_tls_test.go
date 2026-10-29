package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/controllertransport"
)

type pinnedControllerTestProcess struct{ closed atomic.Bool }

func (*pinnedControllerTestProcess) PID() uint32 { return uint32(os.Getpid()) }
func (process *pinnedControllerTestProcess) Alive() error {
	if process.closed.Load() {
		return errors.New("captured test controller process exited")
	}
	return nil
}

func TestLocalControllerPinnedTLSUsesShippingIdentityAndCleanup(t *testing.T) {
	privateOperationRoot(t)
	identity, err := controllertransport.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// The public client constructor is fixed to this actual loopback endpoint.
	// A pre-existing listener is a failed fixture acquisition, never adopted or
	// stopped. All other resources belong only to this bounded test.
	listener, err := net.Listen("tcp4", controllertransport.Address)
	if err != nil {
		t.Fatal("could not acquire the owned loopback TLS fixture:", err)
	}
	defer listener.Close()
	owner := testLocalControllerOwner()
	owner.pinnedTLS = identity
	captured, err := owner.captureListener(listener)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{state: state{Mode: "off", Phase: "off"}, localController: owner}
	closing := newControllerShutdown(a, owner.ownerToken)
	var observed atomic.Int32
	server := &http.Server{Handler: owner.handler(closing.handler(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/status" || request.TLS == nil {
			t.Error("native TLS test reached a wrong or plaintext handler")
		}
		observed.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))), ReadHeaderTimeout: 3 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(captured) }()
	defer func() {
		_ = server.Close()
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Error("owned TLS fixture did not join:", err)
		}
	}()
	process := new(pinnedControllerTestProcess)
	client, err := controllertransport.NewClient(process, identity.Pin(), owner.accessToken, owner.ownerToken)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := client.VerifyIdentity(ctx); err != nil {
		t.Fatal("pinned client did not match the shipping identity contract:", err)
	}
	response, err := client.Request(ctx, http.MethodGet, "/api/status", nil, 1024)
	if err != nil || response.Status != http.StatusAccepted || observed.Load() != 1 {
		t.Fatal("pinned client did not cross the shipping private API admission:", err)
	}
	if err := client.Shutdown(ctx); err != nil {
		t.Fatal("pinned client did not match the shipping complete cleanup receipt:", err)
	}
	waitControllerShutdown(t, closing.done)
	select {
	case <-closing.exit:
	default:
		t.Fatal("pinned receipt did not request the actual controller exit")
	}
	if !a.controllerClosing() {
		t.Fatal("pinned shutdown did not retire actual controller admission")
	}
}

func TestLocalControllerPinnedDrainUsesShippingLifetime(t *testing.T) {
	privateOperationRoot(t)
	owner := testLocalControllerOwner()
	lifetime := make(chan struct{})
	owner.ownerDone = lifetime
	var err error
	owner.pinnedTLS, err = controllertransport.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", controllertransport.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	captured, err := owner.captureListener(listener)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{state: state{Mode: "off", Phase: "off"}, localController: owner}
	closing := newControllerShutdown(a, owner.ownerToken)
	var privateCalls atomic.Int32
	server := &http.Server{Handler: owner.handler(closing.handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		privateCalls.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))), ReadHeaderTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(captured) }()
	defer func() {
		_ = server.Close()
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	}()
	process := new(pinnedControllerTestProcess)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if draining, err := controllertransport.ReadDrain(ctx, process, owner.pinnedTLS.Pin()); err != nil || draining {
		t.Fatal("pinned drain did not cross the actual shipping TLS admission:", draining, err)
	}
	client, err := controllertransport.NewClient(process, owner.pinnedTLS.Pin(), owner.accessToken, owner.ownerToken)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if response, err := client.Request(ctx, http.MethodGet, "/api/status", nil, 1024); err != nil || response.Status != http.StatusAccepted {
		t.Fatal("pinned drain changed private API admission:", response.Status, err)
	}
	// Native wrappers observe the terminal phase before asynchronous cleanup
	// finishes, even after GUI/launcher lifetime EOF has revoked private work.
	close(lifetime)
	if draining, err := controllertransport.ReadDrain(ctx, process, owner.pinnedTLS.Pin()); err != nil || !draining {
		t.Fatal("retired launcher hid the exact native drain state:", draining, err)
	}
	if response, err := client.Request(ctx, http.MethodGet, "/api/status", nil, 1024); err != nil || response.Status != http.StatusServiceUnavailable || privateCalls.Load() != 1 {
		t.Fatal("read-only drain admitted private work after launcher retirement:", response.Status, err)
	}
	closing.begin()
	waitControllerShutdown(t, closing.done)
	if draining, err := controllertransport.ReadDrain(ctx, process, owner.pinnedTLS.Pin()); err != nil || !draining {
		t.Fatal("checked native cleanup lost the bounded terminal drain receipt:", draining, err)
	}
}

func TestLocalControllerPinnedDrainRequiresActualTLSAndExactRequest(t *testing.T) {
	owner := testLocalControllerOwner()
	var err error
	owner.pinnedTLS, err = controllertransport.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	a := &app{state: state{Mode: "off", Phase: "off"}, localController: owner}
	closing := newControllerShutdown(a, owner.ownerToken)
	handler := owner.handler(closing.handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("read-only drain reached a private application handler")
	})))
	// Independently test the real HTTP admission boundary if a caller supplied
	// an ordinary listener incorrectly. A header cannot claim actual TLS.
	plain := httptest.NewServer(handler)
	status, _, _ := testLocalControllerRequest(t, plain.Client(), plain.URL, http.MethodGet, controllertransport.DrainPath, "", nil)
	plain.Close()
	if status != http.StatusForbidden {
		t.Fatal("ordinary HTTP acquired pinned native drain authority", status)
	}
	config, err := owner.pinnedTLS.Config()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	listener, err := net.Listen("tcp4", controllertransport.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	captured, err := owner.captureListener(listener)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(captured) }()
	defer func() { _ = server.Close(); <-done }()
	cases := map[string]struct {
		method, path, body string
		change             func(*http.Request)
	}{
		"query":       {http.MethodGet, controllertransport.DrainPath + "?extra=1", "", nil},
		"encoded":     {http.MethodGet, "/api/controller/%64rain", "", nil},
		"mutation":    {http.MethodPost, controllertransport.DrainPath, "", nil},
		"body":        {http.MethodGet, controllertransport.DrainPath, "private", nil},
		"bearer":      {http.MethodGet, controllertransport.DrainPath, "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+owner.accessToken) }},
		"cookie":      {http.MethodGet, controllertransport.DrainPath, "", func(r *http.Request) { r.Header.Set("Cookie", "session=private") }},
		"challenge":   {http.MethodGet, controllertransport.DrainPath, "", func(r *http.Request) { r.Header.Set("X-RouterVPN-Challenge", strings.Repeat("a", 32)) }},
		"origin":      {http.MethodGet, controllertransport.DrainPath, "", func(r *http.Request) { r.Header.Set("Origin", controllertransport.BaseURL) }},
		"foreignHost": {http.MethodGet, controllertransport.DrainPath, "", func(r *http.Request) { r.Host = "localhost:8788" }},
	}
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			request, err := http.NewRequest(item.method, controllertransport.BaseURL+item.path, strings.NewReader(item.body))
			if err != nil {
				t.Fatal(err)
			}
			if item.change != nil {
				item.change(request)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			raw, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil || response.StatusCode != http.StatusForbidden || strings.Contains(string(raw), owner.accessToken) || strings.Contains(string(raw), owner.ownerToken) {
				t.Fatal("non-exact request acquired bounded native drain authority", response.StatusCode, readErr)
			}
		})
	}
}
