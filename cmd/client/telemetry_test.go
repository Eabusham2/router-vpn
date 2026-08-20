package main

import (
	"bytes"
	"net/http"
	"testing"
)

func TestClampSpeedBytes(t *testing.T) {
	cases := []struct {
		in, want int64
	}{
		{0, 8 << 20},
		{1, 1 << 20},
		{(1 << 20) - 1, 1 << 20},
		{1 << 20, 1 << 20},
		{8 << 20, 8 << 20},
		{16 << 20, 16 << 20},
		{32 << 20, 16 << 20},
	}
	for _, tc := range cases {
		if got := clampSpeedBytes(tc.in); got != tc.want {
			t.Fatalf("clampSpeedBytes(%d)=%d want %d", tc.in, got, tc.want)
		}
	}
}

func TestClampLiveSamples(t *testing.T) {
	cases := []struct{ in, fallback, want int }{
		{0, 3, 3},
		{-1, 5, 5},
		{1, 3, 1},
		{10, 3, 10},
		{11, 3, 10},
	}
	for _, tc := range cases {
		if got := clampLiveSamples(tc.in, tc.fallback); got != tc.want {
			t.Fatalf("clampLiveSamples(%d,%d)=%d want %d", tc.in, tc.fallback, got, tc.want)
		}
	}
}

func TestPrivateBenchmarkRequestHeaders(t *testing.T) {
	payload := bytes.NewReader([]byte("payload"))
	req, err := privateBenchmarkRequest(http.MethodPost, "http://10.77.0.1:8787/api/benchmark/upload", "secret-token", payload)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer secret-token" {
		t.Fatalf("authorization=%q", got)
	}
	if got := req.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control=%q", got)
	}
	if got := req.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("content-type=%q", got)
	}

	getReq, err := privateBenchmarkRequest(http.MethodGet, "http://10.77.0.1:8787/api/benchmark/download", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := getReq.Header.Get("Authorization"); got != "" {
		t.Fatalf("unexpected authorization=%q", got)
	}
	if got := getReq.Header.Get("Content-Type"); got != "" {
		t.Fatalf("unexpected content-type=%q", got)
	}
}
