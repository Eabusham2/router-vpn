package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
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
	config, err := identity.Config()
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
	go func() { done <- server.Serve(tls.NewListener(listener, config)) }()
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
