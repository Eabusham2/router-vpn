package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestLocalControllerStartupRouteRegistrationIsPassive(t *testing.T) {
	a, _ := startupExternalTestApp(t, "hysteria2")
	defer cancelPendingStartupPolicy(a)
	registerStrategyRoutes(http.NewServeMux(), a)
	if _, scheduled := startupPolicyCancels.Load(a); scheduled {
		t.Fatal("route construction scheduled automatic connection before a listener and controller lifetime existed")
	}
	if a.connectionContext != nil || a.state.Phase != "off" || a.cmd != nil {
		t.Fatal("route construction admitted a connection")
	}
}

func TestLocalControllerStartupCapturedBeforeEOFCannotLaunchAfterEOF(t *testing.T) {
	a, _ := startupExternalTestApp(t, "hysteria2")
	ownerDone := make(chan struct{})
	a.localController = testLocalControllerOwner()
	a.localController.ownerDone = ownerDone
	capture, err := a.captureStartupPolicy()
	if err != nil || capture == nil {
		t.Fatal("live owner could not capture its real external startup", err)
	}
	close(ownerDone)
	// No server or cleanup goroutine is running: the closed lifetime itself
	// must reject a queued, previously captured connection before staging.
	harness := startupExternalDriver(t, "proof", "local")
	a.applyCapturedStartupPolicy(context.Background(), capture, harness.driver)
	if harness.calls.Load() != 0 || a.cmd != nil || a.connectionContext != nil || a.state.Phase != "off" {
		t.Fatal("a captured startup reached the actual native launch path after its desktop owner exited")
	}
	if capture, err := a.captureStartupPolicy(); err != nil || capture != nil {
		t.Fatal("a retired desktop could acquire another startup capture", err)
	}
	if _, finish, err := a.beginConnectionTransaction(); !errors.Is(err, errControllerClosing) {
		if finish != nil {
			finish()
		}
		t.Fatal("explicit connection admission waited for an asynchronous cleanup latch", err)
	}
	if _, err := a.beginMutationOperation(httptest.NewRequest(http.MethodPost, "/api/profile/save", nil)); !errors.Is(err, errControllerClosing) {
		t.Fatal("settings admission waited for an asynchronous cleanup latch", err)
	}
}

func TestLocalControllerStartupEOFDeniesHTTPWithoutCleanupScheduling(t *testing.T) {
	owner := testLocalControllerOwner()
	done := make(chan struct{})
	owner.ownerDone = done
	close(done)
	called := false
	handler := owner.handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	for _, path := range []string{"/api/status", "/api/connect", controllerIdentityPath} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Host = linuxOwnedControllerAddress
		request.RemoteAddr = "127.0.0.1:40123"
		request.Header.Set("Authorization", "Bearer "+owner.accessToken)
		if path == controllerIdentityPath {
			challenge := strings.Repeat("a", 32)
			request.Header.Set("X-RouterVPN-Challenge", challenge)
			request.Header.Set("Authorization", "RouterVPN-Identity "+localControllerMAC(owner.accessToken, "routervpn-controller-identity-request\n"+challenge))
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if called || response.Code != http.StatusServiceUnavailable {
			t.Fatal("retired desktop lifetime admitted authenticated HTTP work before cleanup was scheduled", path, response.Code)
		}
	}
}

type startupOwnerListener struct {
	accepts atomic.Int64
	closes  atomic.Int64
}

func (l *startupOwnerListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	return nil, net.ErrClosed
}
func (l *startupOwnerListener) Close() error { l.closes.Add(1); return nil }
func (l *startupOwnerListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8788}
}

func TestLocalControllerStartupAlreadyRetiredClosesBeforeServing(t *testing.T) {
	owner := testLocalControllerOwner()
	done := make(chan struct{})
	owner.ownerDone = done
	close(done)
	a := &app{localController: owner, state: state{Mode: "off", Phase: "off"}}
	closing := newControllerShutdown(a, owner.ownerToken)
	listener := &startupOwnerListener{}
	if err := serveClientHTTP(closing, listener, http.NotFoundHandler(), make(chan os.Signal)); err != nil {
		t.Fatal(err)
	}
	if listener.accepts.Load() != 0 || listener.closes.Load() != 1 || !a.controllerClosing() {
		t.Fatal("an already-retired controller entered HTTP Serve or left its listener open", listener.accepts.Load(), listener.closes.Load())
	}
	if _, scheduled := startupPolicyCancels.Load(a); scheduled {
		t.Fatal("an already-retired controller retained delayed startup")
	}
}
