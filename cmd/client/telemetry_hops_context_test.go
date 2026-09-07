package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestPrivateBenchmarkClientUsesTheConfiguredRoute(t *testing.T) {
	client := newPrivateBenchmarkHTTPClient(time.Second)
	defer client.CloseIdleConnections()
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableCompression || client.CheckRedirect == nil {
		t.Fatal("private benchmark must not inherit proxies, compress, or redirect credentials")
	}
}

func TestRoutedSpeedRefusesRedirectBeforeSendingCredentialsElsewhere(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer server.Close()
	p := common.RouterProfile{ID: "node", RouterAPI: server.URL, APIToken: "test-token"}
	if _, err := measureRoutedProfileSpeedContext(context.Background(), p, 1<<20); err == nil || !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("redirect did not fail closed: %v", err)
	}
	if redirected.Load() != 0 {
		t.Fatal("a benchmark redirected credentials or changed the tested route")
	}
}

func TestRoutedSpeedContextCancelsTransfers(t *testing.T) {
	for _, phase := range []string{"download", "upload"} {
		t.Run(phase, func(t *testing.T) {
			started := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-token" {
					http.Error(w, "unauthorized", http.StatusForbidden)
					return
				}
				if r.URL.Path == "/api/benchmark/download" && phase == "upload" {
					w.Header().Set("Content-Length", "1048576")
					_, _ = io.CopyN(w, strings.NewReader(strings.Repeat("x", 1<<20)), 1<<20)
					return
				}
				if phase == "download" {
					w.Header().Set("Content-Length", "1048576")
					_, _ = w.Write([]byte("partial"))
					w.(http.Flusher).Flush()
				} else {
					_, _ = io.Copy(io.Discard, r.Body)
				}
				started <- struct{}{}
				<-r.Context().Done()
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := common.RouterProfile{ID: "node", RouterAPI: server.URL, APIToken: "test-token"}
			done := make(chan error, 1)
			go func() {
				_, err := measureRoutedProfileSpeedContext(ctx, p, 1<<20)
				done <- err
			}()
			select {
			case <-started:
			case err := <-done:
				t.Fatalf("never reached %s: %v", phase, err)
			case <-time.After(3 * time.Second):
				t.Fatalf("never started %s", phase)
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation was lost: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("%s outlived request cancellation", phase)
			}
		})
	}
}

func TestRoutedSpeedPrecancelledContextDoesNotStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := measureRoutedProfileSpeedContext(ctx, common.RouterProfile{}, 1<<20); !errors.Is(err, context.Canceled) {
		t.Fatalf("precancelled operation continued: %v", err)
	}
}
