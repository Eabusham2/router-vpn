package controllertransport

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type drainRoundTrip func(*http.Request) (*http.Response, error)

func (trip drainRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return trip(request)
}

func testDrainClient(t *testing.T, endpoint, pin string, owner *testProcess) *Client {
	t.Helper()
	client, err := newPinnedClient(owner, pin, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestControllerTransportDrainPinnedReadOnly(t *testing.T) {
	for _, state := range []string{"false", "true"} {
		t.Run(state, func(t *testing.T) {
			var received atomic.Uint32
			server, identity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received.Add(1)
				body, _ := io.ReadAll(r.Body)
				if r.TLS == nil || r.Method != http.MethodGet || r.URL.RequestURI() != DrainPath || len(body) != 0 ||
					len(r.Header.Values("Authorization")) != 0 || len(r.Header.Values("Cookie")) != 0 {
					t.Error("read-only drain disclosed credentials, body or another operation")
				}
				_, _ = io.WriteString(w, `{"schema":1,"process_id":731,"draining":`+state+`}`)
			}))
			client := testDrainClient(t, server.URL, identity.Pin(), new(testProcess))
			// Even an internal client carrying GUI credentials must not send them
			// through this separate read-only operation.
			client.access, client.shutdown = testAccess, testShutdown
			draining, err := client.readDrain(testContext(t))
			if err != nil || draining != (state == "true") || received.Load() != 1 {
				t.Fatal("captured read-only drain lost its exact process state", draining, err)
			}
		})
	}
}

func TestControllerTransportDrainRejectsUnprovedPeer(t *testing.T) {
	t.Run("wrong-pin", func(t *testing.T) {
		var received atomic.Uint32
		server, _ := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			received.Add(1)
			_, _ = io.WriteString(w, `{"schema":1,"process_id":731,"draining":true}`)
		}))
		identity, err := NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		client := testDrainClient(t, server.URL, identity.Pin(), new(testProcess))
		if draining, err := client.readDrain(testContext(t)); err == nil || draining || received.Load() != 0 {
			t.Fatal("wrong session pin received read-only drain authority", draining, err)
		}
	})
	t.Run("redirect", func(t *testing.T) {
		var redirected atomic.Uint32
		target, _ := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			redirected.Add(1)
			_, _ = io.WriteString(w, `{"schema":1,"process_id":731,"draining":true}`)
		}))
		server, identity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+DrainPath, http.StatusFound)
		}))
		client := testDrainClient(t, server.URL, identity.Pin(), new(testProcess))
		if draining, err := client.readDrain(testContext(t)); err == nil || draining || redirected.Load() != 0 {
			t.Fatal("redirect acquired read-only drain authority", draining, err)
		}
	})
	t.Run("failed-status", func(t *testing.T) {
		server, identity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"schema":1,"process_id":731,"draining":true}`)
		}))
		client := testDrainClient(t, server.URL, identity.Pin(), new(testProcess))
		if draining, err := client.readDrain(testContext(t)); err == nil || draining {
			t.Fatal("failed HTTP response acquired native drain authority", draining, err)
		}
	})
}

func TestControllerTransportDrainRejectsAmbiguousReceipt(t *testing.T) {
	cases := map[string]string{
		"wrong-schema": `{"schema":2,"process_id":731,"draining":true}`,
		"wrong-owner":  `{"schema":1,"process_id":732,"draining":true}`,
		"duplicate":    `{"schema":1,"process_id":731,"process_id":731,"draining":true}`,
		"null-state":   `{"schema":1,"process_id":731,"draining":null}`,
		"missing":      `{"schema":1,"process_id":731}`,
		"unknown":      `{"schema":1,"process_id":731,"draining":true,"private":"unexpected"}`,
		"trailing":     `{"schema":1,"process_id":731,"draining":true} {}`,
		"invalid":      `{"schema":1,"process_id":731,"draining":1}`,
		"oversized":    `{"schema":1,"process_id":731,"draining":true}` + strings.Repeat(" ", drainLimit),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			server, identity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
			client := testDrainClient(t, server.URL, identity.Pin(), new(testProcess))
			if draining, err := client.readDrain(testContext(t)); err == nil || draining {
				t.Fatal("ambiguous drain receipt acquired another owner's stop authority", name, draining, err)
			}
		})
	}
}

func TestControllerTransportDrainRevokesLateResult(t *testing.T) {
	owner := new(testProcess)
	entered, release := make(chan struct{}), make(chan struct{})
	server, identity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, `{"schema":1,"process_id":731,"draining":true}`)
	}))
	client := testDrainClient(t, server.URL, identity.Pin(), owner)
	done := make(chan error, 1)
	ctx := testContext(t)
	go func() {
		draining, err := client.readDrain(ctx)
		if draining {
			done <- errors.New("retired process published a delayed drain instruction")
		} else {
			done <- err
		}
	}()
	<-entered
	owner.dead.Store(true)
	close(release)
	if err := <-done; err == nil || strings.Contains(err.Error(), "published") {
		t.Fatal("late drain response survived its exact retained process", err)
	}
}

func TestControllerTransportDrainCancellationAndDeadline(t *testing.T) {
	entered, drained := make(chan struct{}), make(chan struct{})
	server, identity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(drained)
	}))
	client := testDrainClient(t, server.URL, identity.Pin(), new(testProcess))
	ctx, cancel := context.WithCancel(testContext(t))
	done := make(chan error, 1)
	go func() {
		draining, err := client.readDrain(ctx)
		if draining {
			done <- errors.New("cancelled drain acquired stop authority")
		} else {
			done <- err
		}
	}()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("native drain did not retain its caller cancellation", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-drained:
	case <-time.After(3 * time.Second):
		t.Fatal("read-only drain left its actual HTTP operation running")
	}
	// Observe the actual request deadline while still forwarding through the
	// production pinned TLS transport. No success or network result is doubled.
	boundedServer, boundedIdentity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"schema":1,"process_id":731,"draining":true}`)
	}))
	bounded := testDrainClient(t, boundedServer.URL, boundedIdentity.Pin(), new(testProcess))
	type actualDeadline struct{ observed, deadline time.Time }
	deadline := make(chan actualDeadline, 1)
	actual := bounded.http.Transport
	bounded.http.Transport = drainRoundTrip(func(request *http.Request) (*http.Response, error) {
		value, ok := request.Context().Deadline()
		if !ok {
			deadline <- actualDeadline{}
		} else {
			deadline <- actualDeadline{time.Now(), value}
		}
		return actual.RoundTrip(request)
	})
	if draining, err := bounded.readDrain(context.Background()); err != nil || !draining {
		t.Fatal("bounded actual drain request did not retain its positive control", draining, err)
	}
	observed := <-deadline
	if observed.deadline.IsZero() || observed.deadline.Sub(observed.observed) > 400*time.Millisecond {
		t.Fatal("native drain lost its existing bounded poll deadline", observed.deadline.Sub(observed.observed))
	}
}

func TestControllerTransportDrainPublicAPIJoinsTransport(t *testing.T) {
	identity, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	config, err := identity.Config()
	if err != nil {
		t.Fatal(err)
	}
	// This one composition case requires the actual public fixed origin. A
	// different existing listener is never adopted or treated as a passing test.
	listener, err := net.Listen("tcp4", Address)
	if err != nil {
		t.Fatal("the actual public drain test needs its owned loopback listener", err)
	}
	closed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != Address || r.URL.RequestURI() != DrainPath || r.Header.Get("Authorization") != "" {
			t.Error("public drain changed its fixed origin or disclosed private authority")
		}
		_, _ = io.WriteString(w, `{"schema":1,"process_id":731,"draining":true}`)
	}))
	_ = server.Listener.Close()
	server.Listener, server.TLS = listener, config
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	server.StartTLS()
	defer server.Close()
	if draining, err := ReadDrain(testContext(t), new(testProcess), identity.Pin()); err != nil || !draining {
		t.Fatal("actual public drain did not authenticate its captured owner", draining, err)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("public drain abandoned its retained TLS transport after returning")
	}
}
