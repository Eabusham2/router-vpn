package main

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestMultihopLaneHTTPClientOnlyAllowsReservedLoopbackLanes(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1:1097",
		"http://127.0.0.1:1100",
		"http://localhost:1098",
		"http://10.77.0.1:1098",
		"https://127.0.0.1:1098",
		"socks5://127.0.0.1:1099",
		"not-a-url",
	} {
		client, closeIdle, err := newMultihopLaneHTTPClient(raw, time.Second)
		if err == nil {
			if closeIdle != nil {
				closeIdle()
			}
			t.Fatalf("unsafe/non-reserved hop proxy %q was accepted: %#v", raw, client)
		}
	}

	for _, raw := range []string{multihopEntryProofProxy, multihopProofProxy} {
		client, closeIdle, err := newMultihopLaneHTTPClient(raw, time.Second)
		if err != nil {
			t.Fatalf("reserved hop proxy %q was rejected: %v", raw, err)
		}
		transport, ok := client.Transport.(*http.Transport)
		if !ok || transport.Proxy == nil {
			closeIdle()
			t.Fatalf("reserved hop proxy %q did not install an HTTP proxy transport", raw)
		}
		req := &http.Request{URL: &url.URL{Scheme: "http", Host: "10.77.0.1:8787", Path: "/health"}}
		proxyURL, err := transport.Proxy(req)
		closeIdle()
		if err != nil {
			t.Fatalf("reserved hop proxy %q could not resolve transport proxy: %v", raw, err)
		}
		if proxyURL == nil || proxyURL.String() != raw {
			t.Fatalf("reserved hop proxy changed identity: got %v want %q", proxyURL, raw)
		}
	}
}
