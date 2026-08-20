package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func benchmarkTestServer(t *testing.T) *server {
	t.Helper()
	_, tunnel, err := net.ParseCIDR("10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	return &server{cfg: cfg{Token: "secret"}, nets: []*net.IPNet{tunnel}}
}

func benchmarkRequest(method, target string, body *bytes.Reader, token string) *http.Request {
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, body)
	}
	req.RemoteAddr = "10.77.0.2:42424"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestBenchmarkRequestedBytesBounds(t *testing.T) {
	cases := []struct {
		query string
		want  int64
		err   bool
	}{
		{"", benchmarkDefaultBytes, false},
		{"?bytes=65536", 65536, false},
		{"?bytes=16777216", benchmarkMaxBytes, false},
		{"?bytes=65535", 0, true},
		{"?bytes=16777217", 0, true},
		{"?bytes=abc", 0, true},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "http://router.local/api/benchmark/download"+tc.query, nil)
		got, err := benchmarkRequestedBytes(req)
		if tc.err {
			if err == nil {
				t.Fatalf("%q: expected error, got %d", tc.query, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("%q: got %d err=%v want %d", tc.query, got, err, tc.want)
		}
	}
}

func TestBenchmarkDownloadRequiresTunnelPeerAndToken(t *testing.T) {
	s := benchmarkTestServer(t)
	unauthorized := benchmarkRequest(http.MethodGet, "http://router.local/api/benchmark/download?bytes=65536", nil, "wrong")
	w := httptest.NewRecorder()
	s.benchmarkDownload(w, unauthorized)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unauthorized code=%d want %d", w.Code, http.StatusForbidden)
	}

	req := benchmarkRequest(http.MethodGet, "http://router.local/api/benchmark/download?bytes=65536", nil, "secret")
	w = httptest.NewRecorder()
	s.benchmarkDownload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("download code=%d body=%q", w.Code, w.Body.String())
	}
	if w.Body.Len() != 65536 {
		t.Fatalf("download bytes=%d want 65536", w.Body.Len())
	}
	if got := w.Header().Get("Content-Length"); got != "65536" {
		t.Fatalf("content-length=%q", got)
	}
	if got := w.Header().Get("X-Routervpn-Benchmark"); got != "download-v1" {
		t.Fatalf("benchmark header=%q", got)
	}
	if got := w.Header().Get("Content-Encoding"); got != "identity" {
		t.Fatalf("content-encoding=%q", got)
	}
	cache := w.Header().Get("Cache-Control")
	if !strings.Contains(cache, "no-store") || !strings.Contains(cache, "no-transform") {
		t.Fatalf("cache-control=%q", cache)
	}
	if got := w.Header().Get("X-Routervpn-Peer"); got != "10.77.0.2" {
		t.Fatalf("peer header=%q", got)
	}
}

func TestBenchmarkUploadBoundsAndProof(t *testing.T) {
	s := benchmarkTestServer(t)
	payload := bytes.Repeat([]byte{0x5a}, 65536)
	req := benchmarkRequest(http.MethodPost, "http://router.local/api/benchmark/upload", bytes.NewReader(payload), "secret")
	w := httptest.NewRecorder()
	s.benchmarkUpload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("upload code=%d body=%q", w.Code, w.Body.String())
	}
	var result struct {
		OK    bool   `json:"ok"`
		Bytes int64  `json:"bytes"`
		Peer  string `json:"peer"`
		Proof string `json:"proof"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Bytes != 65536 || result.Peer != "10.77.0.2" || result.Proof == "" {
		t.Fatalf("unexpected upload result: %+v", result)
	}

	short := benchmarkRequest(http.MethodPost, "http://router.local/api/benchmark/upload", bytes.NewReader(make([]byte, 1024)), "secret")
	shortW := httptest.NewRecorder()
	s.benchmarkUpload(shortW, short)
	if shortW.Code != http.StatusBadRequest {
		t.Fatalf("short upload code=%d want %d", shortW.Code, http.StatusBadRequest)
	}

	tooLarge := benchmarkRequest(http.MethodPost, "http://router.local/api/benchmark/upload", bytes.NewReader([]byte("x")), "secret")
	tooLarge.ContentLength = benchmarkMaxBytes + 1
	largeW := httptest.NewRecorder()
	s.benchmarkUpload(largeW, tooLarge)
	if largeW.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large upload code=%d want %d", largeW.Code, http.StatusRequestEntityTooLarge)
	}

	wrongMethod := benchmarkRequest(http.MethodGet, "http://router.local/api/benchmark/upload", nil, "secret")
	methodW := httptest.NewRecorder()
	s.benchmarkUpload(methodW, wrongMethod)
	if methodW.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET upload code=%d want %d", methodW.Code, http.StatusMethodNotAllowed)
	}
}
