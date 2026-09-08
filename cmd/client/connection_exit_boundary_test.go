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
)

type cancellingExitProofBody struct {
	io.Reader
	cancel context.CancelFunc
	closed bool
}

func (b *cancellingExitProofBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.cancel()
	return n, err
}

func (b *cancellingExitProofBody) Close() error { b.closed = true; return nil }

func TestExpectedExitProofCannotAdoptAfterCancellationDuringBodyRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := &cancellingExitProofBody{Reader: strings.NewReader("203.0.113.7"), cancel: cancel}
	client := &http.Client{Transport: publicExitRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
	})}
	err := proveExpectedPublicExit(ctx, client, []string{"https://api.ipify.org"}, "203.0.113.7", "test exit", time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled connect adopted a successful exit proof: %v", err)
	}
	if !body.closed {
		t.Fatal("cancelled response was not closed")
	}
}

func TestExpectedExitProofRequiresPublicAddressAndCompleteBoundedResponse(t *testing.T) {
	for _, tc := range []struct {
		name, expected, body string
		valid                bool
	}{
		{"ipv4", "203.0.113.7", "203.0.113.7\n", true},
		{"ipv6", "2001:db8::7", "2001:db8:0:0:0:0:0:7", true},
		{"exact-limit", "203.0.113.7", "203.0.113.7" + strings.Repeat(" ", 256-len("203.0.113.7")), true},
		{"oversized-prefix", "203.0.113.7", "203.0.113.7" + strings.Repeat(" ", 257-len("203.0.113.7")), false},
		{"wrong-exit", "203.0.113.7", "203.0.113.8", false},
		{"private", "192.168.50.1", "192.168.50.1", false},
		{"loopback", "127.0.0.1", "127.0.0.1", false},
		{"carrier-nat", "100.64.0.1", "100.64.0.1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: publicExitRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("connect exit proof omitted cache/compression protections")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
			})}
			err := proveExpectedPublicExit(context.Background(), client, []string{"https://api.ipify.org"}, tc.expected, "test exit", 15*time.Millisecond)
			if (err == nil) != tc.valid {
				t.Fatalf("proof accepted=%t want=%t err=%v", err == nil, tc.valid, err)
			}
			if (tc.name == "private" || tc.name == "loopback" || tc.name == "carrier-nat") && calls != 0 {
				t.Fatal("invalid expected public address reached the network")
			}
		})
	}
}

func TestExpectedExitProofRejectsRedirectWithoutChangingCallerClient(t *testing.T) {
	var redirects, forged atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/forged" {
			forged.Add(1)
			io.WriteString(w, "203.0.113.7")
			return
		}
		http.Redirect(w, r, "/forged", http.StatusFound)
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { redirects.Add(1); return nil }
	err := proveExpectedPublicExit(context.Background(), client, []string{server.URL}, "203.0.113.7", "test exit", 20*time.Millisecond)
	if err == nil || forged.Load() != 0 || redirects.Load() != 0 {
		t.Fatalf("redirect counted as selected-path evidence: err=%v forged=%d callback=%d", err, forged.Load(), redirects.Load())
	}
	// The proof uses a shallow client copy rather than mutating a shared client.
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if redirects.Load() != 1 || forged.Load() != 1 {
		t.Fatal("proof changed its caller's client policy")
	}
}
