package main

import (
	"context"
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

	"router-vpn/internal/common"
)

func TestMultihopLaneRejectsDecoratedProxyURLs(t *testing.T) {
	for _, raw := range []string{
		"http://user:password@127.0.0.1:1098", "http://127.0.0.1:1098/path",
		"http://127.0.0.1:1099?route=other", "http://127.0.0.1:1099#other", "http://127.0.0.1:1098?",
	} {
		client, cleanup, err := newMultihopLaneHTTPClient(raw, time.Second)
		if cleanup != nil {
			cleanup()
		}
		if err == nil {
			t.Fatalf("non-canonical lane accepted: %s (%v)", raw, client)
		}
	}
}

func TestMultihopLaneRefusesRedirectBeforeSendingAnotherRequest(t *testing.T) {
	client, cleanup, err := newMultihopLaneHTTPClient(multihopEntryProofProxy, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	var requests atomic.Int32
	client.Transport = speedLabTestTransport(func(req *http.Request) (*http.Response, error) {
		requests.Add(1)
		return &http.Response{
			StatusCode: http.StatusFound, Header: http.Header{"Location": {"http://10.77.0.1:9999/other-service"}},
			Body: io.NopCloser(strings.NewReader("redirect")), Request: req,
		}, nil
	})
	req, err := http.NewRequest(http.MethodGet, "http://10.77.0.1:8787/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-token")
	response, err := client.Do(req)
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "redirect refused") || requests.Load() != 1 {
		t.Fatalf("redirect changed the node/service or forwarded credentials: requests=%d err=%v", requests.Load(), err)
	}
}

func TestMultihopLanePrecancelledContextDoesNoWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := common.RouterProfile{}
	if err := proveMultihopLaneNodeContext(ctx, p, multihopEntryProofProxy); !errors.Is(err, context.Canceled) {
		t.Fatalf("proof ignored cancellation: %v", err)
	}
	if _, err := measureRoutedProfileLatencyViaProxyContext(ctx, p, 4, multihopEntryProofProxy); !errors.Is(err, context.Canceled) {
		t.Fatalf("RTT ignored cancellation: %v", err)
	}
	if _, err := measureRoutedProfileSpeedViaProxyContext(ctx, p, 1<<20, multihopEntryProofProxy); !errors.Is(err, context.Canceled) {
		t.Fatalf("throughput ignored cancellation: %v", err)
	}
}

func TestMultihopLaneCancelsInFlightProofLatencyDownloadAndUpload(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	p := common.RouterProfile{ID: "test-hop", NodeKind: "router-vpn", RouterAPI: "http://10.77.0.1:8787", APIToken: "test-token"}
	p.NodeProofID = writeTestWGIdentity(t, root, p.ID)
	for _, phase := range []string{"proof", "latency", "download", "upload"} {
		t.Run(phase, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:1098")
			if err != nil {
				t.Fatal(err)
			}
			started := make(chan struct{}, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-token" {
					http.Error(w, "unauthorized", http.StatusForbidden)
					return
				}
				stall := (r.URL.Path == "/health" && (phase == "proof" || phase == "latency")) ||
					(r.URL.Path == "/api/benchmark/download" && phase == "download") ||
					(r.URL.Path == "/api/benchmark/upload" && phase == "upload")
				if stall {
					if phase == "download" {
						w.Header().Set("Content-Length", "1048576")
						_, _ = w.Write([]byte("partial"))
						w.(http.Flusher).Flush()
					} else if phase == "upload" {
						_, _ = io.Copy(io.Discard, r.Body)
					}
					started <- struct{}{}
					<-r.Context().Done()
					return
				}
				switch r.URL.Path {
				case "/health":
					_, _ = fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":%q}`, p.NodeProofID, desktopNodeProofKind)
				case "/api/benchmark/download":
					_, _ = io.CopyN(w, strings.NewReader(strings.Repeat("x", 1<<20)), 1<<20)
				default:
					http.NotFound(w, r)
				}
			}))
			server.Listener.Close()
			server.Listener = listener
			server.Start()
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var err error
				switch phase {
				case "proof":
					err = proveMultihopLaneNodeContext(ctx, p, multihopEntryProofProxy)
				case "latency":
					_, err = measureRoutedProfileLatencyViaProxyContext(ctx, p, 4, multihopEntryProofProxy)
				default:
					_, err = measureRoutedProfileSpeedViaProxyContext(ctx, p, 1<<20, multihopEntryProofProxy)
				}
				done <- err
			}()
			select {
			case <-started:
			case err := <-done:
				t.Fatalf("measurement never reached %s: %v", phase, err)
			case <-time.After(3 * time.Second):
				t.Fatalf("measurement never started %s", phase)
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation was not preserved in %s: %v", phase, err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("%s kept running after cancellation", phase)
			}
		})
	}
}
