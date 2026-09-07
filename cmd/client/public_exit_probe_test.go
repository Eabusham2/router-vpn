package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type publicExitRoundTripper func(*http.Request) (*http.Response, error)

func (f publicExitRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type publicExitBody struct {
	io.Reader
	closed bool
}

func (b *publicExitBody) Close() error { b.closed = true; return nil }

func TestPublicExitProbeBoundariesAndProviderFallback(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		status          int
	}{
		{"ipv4", "203.0.113.12\n", "203.0.113.12", 200},
		{"ipv6", "2001:4860:4860::8888", "2001:4860:4860::8888", 200},
		{"exact-limit", "203.0.113.12" + strings.Repeat(" ", 244), "203.0.113.12", 200},
		{"oversized-prefix", "203.0.113.12" + strings.Repeat(" ", 300), "", 200},
		{"private", "192.168.50.1", "", 200},
		{"loopback", "127.0.0.1", "", 200},
		{"unspecified", "::", "", 200},
		{"multicast", "ff02::1", "", 200},
		{"bad-status", "203.0.113.12", "", 500},
		{"invalid", "not an address", "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			var bodies []*publicExitBody
			client := &http.Client{Transport: publicExitRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("missing public-exit request protections")
				}
				if r.Header.Get("Authorization") != "" {
					t.Fatal("node credential sent to a public provider")
				}
				body := &publicExitBody{Reader: strings.NewReader(tc.body)}
				bodies = append(bodies, body)
				return &http.Response{StatusCode: tc.status, Body: body, Header: make(http.Header)}, nil
			})}
			got, err := probePublicExitIPContext(context.Background(), client)
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatalf("IP=%q err=%v, want %q", got, err, tc.want)
			}
			wantCalls := 1
			if tc.want == "" {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("provider calls=%d want=%d", calls, wantCalls)
			}
			for _, body := range bodies {
				if !body.closed {
					t.Fatal("provider body left open")
				}
			}
		})
	}
}

func TestPublicExitProbeCancellationCannotFallBackOrAdopt(t *testing.T) {
	for _, stage := range []string{"before", "request", "body"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			client := &http.Client{Transport: publicExitRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Context() != ctx {
					t.Error("request lost its path context")
				}
				cancel()
				if stage == "request" {
					return nil, context.Canceled
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("203.0.113.12")), Header: make(http.Header)}, nil
			})}
			if stage == "before" {
				cancel()
			}
			got, err := probePublicExitIPContext(ctx, client)
			if got != "" || !errors.Is(err, context.Canceled) {
				t.Fatalf("IP=%q err=%v", got, err)
			}
			if calls > 1 || stage == "before" && calls != 0 {
				t.Fatalf("cancelled path made %d requests", calls)
			}
		})
	}
	if _, err := probePublicExitIPContext(context.Background(), nil); err == nil {
		t.Fatal("missing transport did not fail closed")
	}
}

func TestPublicExitProbeFallsBackWithinOwnedTransport(t *testing.T) {
	var hosts []string
	client := &http.Client{Transport: publicExitRoundTripper(func(r *http.Request) (*http.Response, error) {
		hosts = append(hosts, r.URL.Host)
		if len(hosts) == 1 {
			return nil, errors.New("IPv6 provider unavailable")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("203.0.113.12")), Header: make(http.Header)}, nil
	})}
	got, err := probePublicExitIPContext(context.Background(), client)
	if err != nil || got != "203.0.113.12" || strings.Join(hosts, ",") != "api64.ipify.org,api.ipify.org" {
		t.Fatalf("IP=%q err=%v hosts=%v", got, err, hosts)
	}
}
